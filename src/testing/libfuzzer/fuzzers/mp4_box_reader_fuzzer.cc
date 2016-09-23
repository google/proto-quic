// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include <memory>

#include "media/formats/mp4/box_reader.h"
#include "base/logging.h"

class NullMediaLog : public media::MediaLog {
 public:
  NullMediaLog() {}

  void DoAddEventLogString(const std::string& event) {}

  void AddEvent(std::unique_ptr<media::MediaLogEvent> event) override {}

 protected:
  virtual ~NullMediaLog() {}

 private:
  DISALLOW_COPY_AND_ASSIGN(NullMediaLog);
};

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  bool err;
  scoped_refptr<NullMediaLog> media_log(new NullMediaLog());
  std::unique_ptr<media::mp4::BoxReader> reader(
      media::mp4::BoxReader::ReadTopLevelBox(data, static_cast<const int>(size),
                                             media_log, &err));
  if (err) {
    return 0;
  }
  if (reader == NULL) {
    return 0;
  }
  if (!reader->ScanChildren()) {
    return 0;
  }
  return 0;
}
