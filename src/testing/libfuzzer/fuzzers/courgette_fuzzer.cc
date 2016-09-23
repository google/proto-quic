// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include <memory>

#include "courgette/assembly_program.h"
#include "courgette/courgette.h"
#include "courgette/encoded_program.h"
#include "courgette/program_detector.h"

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::unique_ptr<courgette::AssemblyProgram> prog;
  courgette::Status status =
      courgette::ParseDetectedExecutable(data, size, &prog);
  if (status != courgette::C_OK) {
    return 0;
  }
  std::unique_ptr<courgette::EncodedProgram> enc_prog(prog->Encode());
  return 0;
}
