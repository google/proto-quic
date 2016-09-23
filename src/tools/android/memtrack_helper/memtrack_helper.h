/*
 * Copyright 2015 The Chromium Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef TOOLS_ANDROID_MEMTRACK_HELPER_H_
#define TOOLS_ANDROID_MEMTRACK_HELPER_H_

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>

static inline void exit_with_failure(const char* reason) {
  perror(reason);
  exit(EXIT_FAILURE);
}

static inline void init_memtrack_server_addr(struct sockaddr_un* addr) {
  const char* const kAbstractSocketName = "chrome_tracing_memtrack_helper";
  memset(addr, 0, sizeof(*addr));
  addr->sun_family = AF_UNIX;
  strncpy(&addr->sun_path[1], kAbstractSocketName, sizeof(addr->sun_path) - 2);
}

#endif  // TOOLS_ANDROID_MEMTRACK_HELPER_H_
