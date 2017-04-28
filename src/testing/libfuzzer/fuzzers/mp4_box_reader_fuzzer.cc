// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include <memory>

#include "base/logging.h"
#include "media/formats/mp4/box_reader.h"

class NullMediaLog : public media::MediaLog {
 public:
  NullMediaLog() {}
  ~NullMediaLog() override {}

  void AddEvent(std::unique_ptr<media::MediaLogEvent> event) override {}

 private:
  DISALLOW_COPY_AND_ASSIGN(NullMediaLog);
};

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  bool err;
  NullMediaLog media_log;
  std::unique_ptr<media::mp4::BoxReader> reader(
      media::mp4::BoxReader::ReadTopLevelBox(data, static_cast<int>(size),
                                             &media_log, &err));
  return !err && reader && reader->ScanChildren() ? 0 : 0;
}
