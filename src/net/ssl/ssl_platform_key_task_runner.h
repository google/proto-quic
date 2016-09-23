// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SSL_SSL_PLATFORM_KEY_TASK_RUNNER_H_
#define NET_SSL_SSL_PLATFORM_KEY_TASK_RUNNER_H_

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/threading/thread.h"

namespace base {
class SingleThreadTaskRunner;
}

namespace net {

// Serialize all the private key operations on a single background thread to
// avoid problems with buggy smartcards. Its underlying Thread is non-joinable
// and as such provides TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN semantics.
class SSLPlatformKeyTaskRunner {
 public:
  SSLPlatformKeyTaskRunner();
  ~SSLPlatformKeyTaskRunner();

  scoped_refptr<base::SingleThreadTaskRunner> task_runner();

 private:
  base::Thread worker_thread_;

  DISALLOW_COPY_AND_ASSIGN(SSLPlatformKeyTaskRunner);
};

scoped_refptr<base::SingleThreadTaskRunner> GetSSLPlatformKeyTaskRunner();

}  // namespace net

#endif  // NET_SSL_SSL_PLATFORM_KEY_TASK_RUNNER_H_
