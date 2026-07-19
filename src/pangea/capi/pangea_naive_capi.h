// Copyright 2026 Pangea. Use of this source code is governed by the BSD-3
// license this repo inherits from klzgrad/naiveproxy.
//
// C API for embedding the naive proxy client engine into a host process via
// static linking (e.g. Go's cgo), instead of running the upstream `naive`
// executable as a subprocess. Only one engine instance may be active per
// process.
#ifndef PANGEA_CAPI_PANGEA_NAIVE_CAPI_H_
#define PANGEA_CAPI_PANGEA_NAIVE_CAPI_H_

#ifdef __cplusplus
extern "C" {
#endif

// Starts the engine on a dedicated background thread. configJson is a JSON
// object: {"remoteHost":string,"remotePort":int,"username":string,
// "password":string,"serverName":string (optional, defaults to remoteHost)}.
// The engine binds a local SOCKS5 listener on an OS-assigned loopback port
// (discoverable via PangeaNaiveStatus) and proxies through remoteHost via
// the naive protocol (TLS + HTTP/2 CONNECT), authenticating with
// username/password (HTTP Basic).
//
// Blocks until the local listener is bound or startup fails. Returns 0 on
// success, non-zero on failure (see PangeaNaiveStatus for the error string).
// Returns 0 immediately if already running.
int PangeaNaiveStart(const char* configJson);

// Stops the running engine and joins its background thread. No-op if not
// running. Blocks until fully stopped.
void PangeaNaiveStop(void);

// Returns a JSON status snapshot:
// {"running":bool,"socksPort":int,"error":string}.
// The returned pointer is malloc'd; the caller must free() it.
char* PangeaNaiveStatus(void);

#ifdef __cplusplus
}
#endif

#endif  // PANGEA_CAPI_PANGEA_NAIVE_CAPI_H_
