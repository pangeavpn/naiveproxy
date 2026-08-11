// Copyright 2013 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SOCKET_SOCKET_DESCRIPTOR_H_
#define NET_SOCKET_SOCKET_DESCRIPTOR_H_

#include "build/build_config.h"
#include "net/base/net_export.h"

#if BUILDFLAG(IS_WIN)
#include "base/win/windows_types.h"
#endif

namespace net {

#if BUILDFLAG(IS_WIN)
typedef UINT_PTR SocketDescriptor;
const SocketDescriptor kInvalidSocket = (SocketDescriptor)(~0);
#elif BUILDFLAG(IS_POSIX) || BUILDFLAG(IS_FUCHSIA)
typedef int SocketDescriptor;
const SocketDescriptor kInvalidSocket = -1;
#endif

// Creates  socket. See WSASocket/socket documentation of parameters.
SocketDescriptor NET_EXPORT CreatePlatformSocket(int family,
                                                 int type,
                                                 int protocol);

#if BUILDFLAG(IS_ANDROID)
// Called with every socket this stack opens, before it is bound or connected,
// so an embedder inside a VpnService can VpnService.protect() it.
using SocketProtector = bool (*)(int);
void NET_EXPORT SetSocketProtector(SocketProtector protector);
#endif

}  // namespace net

#endif  // NET_SOCKET_SOCKET_DESCRIPTOR_H_
