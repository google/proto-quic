// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/rand_util.h"
#include "tools/ipc_fuzzer/fuzzer/rand_util.h"

namespace ipc_fuzzer {

MersenneTwister* g_mersenne_twister = NULL;

void InitRand() {
  // TODO(aedla): convert to C++11 std::mt19937 in the future
  g_mersenne_twister = new MersenneTwister();
  g_mersenne_twister->init_genrand(static_cast<uint32_t>(base::RandUint64()));
}

}  // namespace ipc_fuzzer
