// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory.h>
#include <stddef.h>
#include <stdint.h>

#include "third_party/minizip/src/ioapi.h"
#include "third_party/minizip/src/unzip.h"

zlib_filefunc_def test_filefunc;

uint32_t current_offset = 0;
size_t test_data_size;
const uint8_t* test_data;

void* Open(void* /* opaque */, const char* /* filename */, int /* mode */) {
  return nullptr;
}

uint32_t Read(void* /* opaque */,
              void* /* stream */,
              void* buffer,
              uint32_t size) {
  memcpy(buffer, test_data, size);
  return size;
}

long Seek(void* /* opaque */, void* /* stream */, uint32_t offset, int origin) {
  switch (origin) {
    case ZLIB_FILEFUNC_SEEK_SET:
      current_offset = offset;
      break;
    case ZLIB_FILEFUNC_SEEK_CUR:
      current_offset += offset;
    case ZLIB_FILEFUNC_SEEK_END:
      current_offset = test_data_size + offset;
  }
  return current_offset;
}

long Tell(void* /* opaque */, void* /* stream */) {
  return current_offset;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  test_data = data;
  test_data_size = size;

  test_filefunc.zopen_file = Open;
  test_filefunc.zread_file = Read;
  test_filefunc.zseek_file = Seek;
  test_filefunc.ztell_file = Tell;

  unzOpen2(nullptr /* filename */, &test_filefunc);

  return 0;
}
