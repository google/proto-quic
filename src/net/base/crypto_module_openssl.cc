// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/logging.h"
#include "net/base/crypto_module.h"

namespace net {

std::string CryptoModule::GetTokenName() const {
  NOTIMPLEMENTED();
  return "";
}

// static
CryptoModule* CryptoModule::CreateFromHandle(OSModuleHandle handle) {
  NOTIMPLEMENTED();
  return NULL;
}

CryptoModule::CryptoModule(OSModuleHandle handle) : module_handle_(handle) {
}

CryptoModule::~CryptoModule() {
}

}  // namespace net
