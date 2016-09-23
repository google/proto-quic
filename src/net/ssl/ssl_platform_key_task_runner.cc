// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/ssl/ssl_platform_key_task_runner.h"

#include "base/lazy_instance.h"

namespace net {

SSLPlatformKeyTaskRunner::SSLPlatformKeyTaskRunner()
    : worker_thread_("Platform Key Thread") {
  base::Thread::Options options;
  options.joinable = false;
  worker_thread_.StartWithOptions(options);
}

SSLPlatformKeyTaskRunner::~SSLPlatformKeyTaskRunner() = default;

scoped_refptr<base::SingleThreadTaskRunner>
SSLPlatformKeyTaskRunner::task_runner() {
  return worker_thread_.task_runner();
}

base::LazyInstance<SSLPlatformKeyTaskRunner>::Leaky g_platform_key_task_runner =
    LAZY_INSTANCE_INITIALIZER;

scoped_refptr<base::SingleThreadTaskRunner> GetSSLPlatformKeyTaskRunner() {
  return g_platform_key_task_runner.Get().task_runner();
}

}  // namespace net
