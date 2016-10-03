// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>

#include "crypto/openssl_bio_string.h"
#include "crypto/scoped_openssl_types.h"


extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  if (size == 0) { return 0; }

  std::string buffer;
  std::string input(reinterpret_cast<const char*>(data), size);

  std::size_t data_hash = std::hash<std::string>()(input);
  uint8_t choice = data_hash % 3;

  crypto::ScopedBIO bio(crypto::BIO_new_string(&buffer));
  if (choice == 0) {
    BIO_printf(bio.get(), "%s", input.c_str());
  } else if (choice == 1) {
    BIO_write(bio.get(), input.c_str(), size);
  } else {
    BIO_puts(bio.get(), input.c_str());
  }
  BIO_flush(bio.get());

  return 0;
}

