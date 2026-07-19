// Copyright 2026 Pangea. Use of this source code is governed by the BSD-3
// license this repo inherits from klzgrad/naiveproxy.
#include "pangea/capi/pangea_naive_capi.h"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/feature_list.h"
#include "base/functional/callback.h"
#include "base/json/json_reader.h"
#include "base/location.h"
#include "base/json/json_writer.h"
#include "base/run_loop.h"
#include "base/strings/escape.h"
#include "base/strings/string_number_conversions.h"
#include "base/task/single_thread_task_executor.h"
#include "base/task/single_thread_task_runner.h"
#include "base/task/thread_pool/thread_pool_instance.h"
#include "base/time/time.h"
#include "base/values.h"
#include "net/base/ip_endpoint.h"
#include "net/base/net_errors.h"
#include "net/cert/cert_verifier.h"
#include "net/http/http_auth.h"
#include "net/http/http_auth_cache.h"
#include "net/http/http_network_session.h"
#include "net/http/http_transaction_factory.h"
#include "net/log/net_log.h"
#include "net/log/net_log_source.h"
#include "net/proxy_resolution/configured_proxy_resolution_service.h"
#include "net/proxy_resolution/proxy_config.h"
#include "net/proxy_resolution/proxy_config_service_fixed.h"
#include "net/proxy_resolution/proxy_config_with_annotation.h"
#include "net/socket/client_socket_pool.h"
#include "net/socket/client_socket_pool_manager.h"
#include "net/socket/tcp_server_socket.h"
#include "net/tools/naive/naive_config.h"
#include "net/tools/naive/naive_protocol.h"
#include "net/tools/naive/naive_proxy.h"
#include "net/tools/naive/naive_proxy_delegate.h"
#include "net/traffic_annotation/network_traffic_annotation.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_builder.h"
#include "url/url_util.h"

namespace {

constexpr int kListenBackLog = 512;
constexpr int kDefaultMaxSocketsPerPool = 256;
constexpr int kDefaultMaxSocketsPerGroup = 255;
constexpr int kExpectedMaxUsers = 8;
constexpr net::NetworkTrafficAnnotationTag kTrafficAnnotation =
    net::DefineNetworkTrafficAnnotation("pangea_naive", "");

// Bootstraps process-global Chromium singletons exactly once per process.
// Mirrors net/tools/naive/naive_proxy_bin.cc's main(), minus the
// command-line/config-file parsing this shim doesn't use (config arrives as
// a JSON string argument instead).
void EnsureProcessBootstrap() {
  static std::once_flag once;
  std::call_once(once, [] {
    if (!base::CommandLine::InitializedForCurrentProcess()) {
      base::CommandLine::Init(0, nullptr);
    }
    // Deliberately leaked: AtExitManager must live for the rest of the
    // process, same as the stack-local instance in main(), but there is no
    // process-scoped stack frame here to own it.
    new base::AtExitManager();
    base::FeatureList::InitInstance(
        "PartitionConnectionsByNetworkIsolationKey", std::string());
    base::ThreadPoolInstance::CreateAndStartWithDefaultParams("pangea_naive");
    url::AddStandardScheme("quic",
                            url::SCHEME_WITH_HOST_PORT_AND_USER_INFORMATION);
    url::AddStandardScheme("socks",
                            url::SCHEME_WITH_HOST_PORT_AND_USER_INFORMATION);
    net::ClientSocketPoolManager::set_socket_soft_cap_per_pool_for_test(
        net::HttpNetworkSession::SocketPoolType::kNormal,
        kDefaultMaxSocketsPerPool * kExpectedMaxUsers);
    net::ClientSocketPoolManager::set_max_sockets_per_proxy_chain(
        net::HttpNetworkSession::SocketPoolType::kNormal,
        kDefaultMaxSocketsPerPool * kExpectedMaxUsers);
    net::ClientSocketPoolManager::set_max_sockets_per_group_for_test(
        net::HttpNetworkSession::SocketPoolType::kNormal,
        kDefaultMaxSocketsPerGroup * kExpectedMaxUsers);
    net::ClientSocketPool::set_used_idle_socket_timeout(base::Seconds(60));
  });
}

// Builds the URLRequestContext that carries the upstream proxy config
// (target host/port/SNI, HTTP Basic auth, padding/CONNECT-header handling
// via NaiveProxyDelegate). Adapted from the anonymous-namespace
// BuildURLRequestContext() in naive_proxy_bin.cc, trimmed to what this
// shim's config surface needs (no QUIC upstream, no NetLog, no post-quantum
// override — none of those are exercised by the profiles this daemon uses
// today).
//
// cert_net_fetcher is always null here: upstream only builds a real one on
// Fuchsia/Linux/ChromeOS/Android (see the BUILDFLAG guard in
// naive_proxy_bin.cc); on Windows, main() itself passes null too, so this
// matches upstream behavior exactly for this shim's only target platform.
std::unique_ptr<net::URLRequestContext> BuildProxyURLRequestContext(
    const net::NaiveConfig& config,
    net::NetLog* net_log) {
  net::URLRequestContextBuilder builder;
  builder.DisableHttpCache();
  builder.set_net_log(net_log);

  net::ProxyConfig proxy_config;
  proxy_config.proxy_rules().type =
      net::ProxyConfig::ProxyRules::Type::PROXY_LIST;
  if (config.proxy_chains.empty()) {
    proxy_config.proxy_rules().single_proxies.SetSingleProxyChain(
        net::ProxyChain::Direct());
  } else {
    proxy_config.proxy_rules().single_proxies.SetSingleProxyChain(
        config.proxy_chains.at(0));
  }
  auto proxy_service =
      net::ConfiguredProxyResolutionService::CreateWithoutProxyResolver(
          std::make_unique<net::ProxyConfigServiceFixed>(
              net::ProxyConfigWithAnnotation(proxy_config,
                                              kTrafficAnnotation)),
          nullptr, net_log);
  proxy_service->ForceReloadProxyConfig();
  builder.set_proxy_resolution_service(std::move(proxy_service));

  if (!config.host_resolver_rules.empty()) {
    builder.set_host_mapping_rules(config.host_resolver_rules);
  }

  builder.SetCertVerifier(net::CertVerifier::CreateDefault(nullptr));

  builder.set_proxy_delegate(std::make_unique<net::NaiveProxyDelegate>(
      config.extra_headers,
      std::vector<net::PaddingType>{net::PaddingType::kVariant1,
                                     net::PaddingType::kNone}));

  auto context = builder.Build();

  for (const auto& [key, credentials] : config.auth_store) {
    auto* session = context->http_transaction_factory()->GetSession();
    session->http_auth_cache()->Add(key, net::HttpAuth::AUTH_PROXY,
                                     /*realm=*/{},
                                     net::HttpAuth::AUTH_SCHEME_BASIC, {},
                                     /*challenge=*/"Basic", credentials,
                                     /*path=*/"/");
  }
  return context;
}

// Owns everything that must live for the duration of one Start/Stop cycle.
// naive_proxy/context are sequence-affine (Chromium net:: objects) and must
// be destroyed on the IO thread that created them, hence the cleanup runs
// inside the worker thread's lambda, not in PangeaNaiveStop().
struct EngineState {
  std::thread worker;
  scoped_refptr<base::SingleThreadTaskRunner> io_task_runner;
  base::OnceClosure quit_closure;
  std::vector<std::unique_ptr<net::NaiveProxy>> naive_proxies;
  std::vector<std::unique_ptr<net::URLRequestContext>> contexts;
};

std::mutex g_state_mu;
std::shared_ptr<EngineState> g_state;
std::atomic<bool> g_running{false};
std::atomic<int> g_bound_socks_port{0};

std::mutex g_error_mu;
std::string g_last_error;

void SetLastError(const std::string& err) {
  std::lock_guard<std::mutex> lock(g_error_mu);
  g_last_error = err;
}

std::string GetLastNaiveError() {
  std::lock_guard<std::mutex> lock(g_error_mu);
  return g_last_error;
}

// Translates this shim's simplified JSON config (see pangea_naive_capi.h)
// into the native naive config.json shape and parses it with the real
// net::NaiveConfig::Parse, reusing upstream's validation instead of
// hand-rolling a parallel path.
bool BuildNaiveConfig(const base::DictValue& in,
                      net::NaiveConfig* out_config,
                      std::string* out_error) {
  const std::string* remote_host = in.FindString("remoteHost");
  std::optional<int> remote_port = in.FindInt("remotePort");
  const std::string* username = in.FindString("username");
  const std::string* password = in.FindString("password");
  const std::string* server_name = in.FindString("serverName");

  if (!remote_host || remote_host->empty() || !remote_port ||
      !username || !password) {
    *out_error = "config missing required fields (remoteHost/remotePort/"
                 "username/password)";
    return false;
  }
  std::string sni =
      (server_name && !server_name->empty()) ? *server_name : *remote_host;

  base::DictValue native;
  base::ListValue listen_list;
  listen_list.Append("socks://127.0.0.1:0");
  native.Set("listen", std::move(listen_list));

  std::string escaped_user =
      base::EscapeUrlEncodedData(*username, /*use_plus=*/false);
  std::string escaped_pass =
      base::EscapeUrlEncodedData(*password, /*use_plus=*/false);
  native.Set("proxy", "https://" + escaped_user + ":" + escaped_pass + "@" +
                          sni + ":" + base::NumberToString(*remote_port));
  if (sni != *remote_host) {
    native.Set("host-resolver-rules", "MAP " + sni + " " + *remote_host);
  }

  if (!out_config->Parse(native)) {
    *out_error = "naive config parse failed";
    return false;
  }
  return true;
}

}  // namespace

extern "C" int PangeaNaiveStart(const char* configJson) {
  if (g_running.load()) {
    return 0;
  }
  if (configJson == nullptr) {
    SetLastError("configJson is null");
    return 1;
  }

  std::optional<base::DictValue> parsed = base::JSONReader::ReadDict(
      std::string_view(configJson), base::JSON_PARSE_RFC);
  if (!parsed) {
    SetLastError("invalid config JSON");
    return 1;
  }

  net::NaiveConfig config;
  std::string build_error;
  if (!BuildNaiveConfig(*parsed, &config, &build_error)) {
    SetLastError(build_error);
    return 1;
  }

  EnsureProcessBootstrap();

  auto state = std::make_shared<EngineState>();
  auto ready = std::make_shared<std::promise<std::pair<bool, int>>>();
  std::future<std::pair<bool, int>> ready_future = ready->get_future();

  state->worker = std::thread([state, config, ready]() mutable {
    base::SingleThreadTaskExecutor io_task_executor(
        base::MessagePumpType::IO);
    state->io_task_runner = base::SingleThreadTaskRunner::GetCurrentDefault();

    net::NetLog* net_log = net::NetLog::Get();
    auto listen_socket =
        std::make_unique<net::TCPServerSocket>(net_log, net::NetLogSource());
    int result = listen_socket->ListenWithAddressAndPort(
        config.listen[0].addr, config.listen[0].port, kListenBackLog);
    if (result != net::OK) {
      SetLastError("failed to open local socks listener: " +
                   net::ErrorToShortString(result));
      ready->set_value({false, 0});
      return;
    }
    net::IPEndPoint local_addr;
    listen_socket->GetLocalAddress(&local_addr);
    int bound_port = local_addr.port();

    auto context = BuildProxyURLRequestContext(config, net_log);
    auto* session = context->http_transaction_factory()->GetSession();
    auto naive_proxy = std::make_unique<net::NaiveProxy>(
        std::move(listen_socket), config.listen[0].protocol,
        config.listen[0].user, config.listen[0].pass,
        config.insecure_concurrency, config.tunnel_timeout,
        config.idle_timeout, /*resolver=*/nullptr, session,
        kTrafficAnnotation,
        std::vector<net::PaddingType>{net::PaddingType::kVariant1,
                                       net::PaddingType::kNone});

    state->contexts.push_back(std::move(context));
    state->naive_proxies.push_back(std::move(naive_proxy));

    base::RunLoop run_loop;
    state->quit_closure = run_loop.QuitClosure();
    ready->set_value({true, bound_port});

    run_loop.Run();

    // Runs on the IO thread: these are sequence-affine and must not be
    // destroyed from PangeaNaiveStop()'s caller thread.
    state->naive_proxies.clear();
    state->contexts.clear();
  });

  constexpr auto kStartupTimeout = std::chrono::seconds(10);
  if (ready_future.wait_for(kStartupTimeout) != std::future_status::ready) {
    SetLastError("engine startup timed out");
    // state/ready are kept alive by the worker thread's own captured
    // shared_ptr copies, so detaching here does not dangle even though this
    // function's locals go out of scope.
    state->worker.detach();
    return 1;
  }

  auto [success, bound_port] = ready_future.get();
  if (!success) {
    state->worker.join();
    return 1;
  }

  g_bound_socks_port.store(bound_port);
  {
    std::lock_guard<std::mutex> lock(g_state_mu);
    g_state = state;
  }
  g_running.store(true);
  return 0;
}

extern "C" void PangeaNaiveStop(void) {
  if (!g_running.exchange(false)) {
    return;
  }
  std::shared_ptr<EngineState> state;
  {
    std::lock_guard<std::mutex> lock(g_state_mu);
    state = std::move(g_state);
  }
  if (!state) {
    return;
  }
  state->io_task_runner->PostTask(FROM_HERE, std::move(state->quit_closure));
  state->worker.join();
  g_bound_socks_port.store(0);
}

extern "C" char* PangeaNaiveStatus(void) {
  base::DictValue status;
  status.Set("running", g_running.load());
  status.Set("socksPort", g_bound_socks_port.load());
  status.Set("error", GetLastNaiveError());

  std::string json;
  base::JSONWriter::Write(status, &json);

  char* out = static_cast<char*>(std::malloc(json.size() + 1));
  if (out != nullptr) {
    std::memcpy(out, json.c_str(), json.size() + 1);
  }
  return out;
}
