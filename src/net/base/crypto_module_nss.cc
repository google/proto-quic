// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/base/crypto_module.h"

#include <pk11pub.h>

namespace net {

std::string CryptoModule::GetTokenName() const {
  return PK11_GetTokenName(module_handle_);
}

// static
CryptoModule* CryptoModule::CreateFromHandle(OSModuleHandle handle) {
  return new CryptoModule(handle);
}

CryptoModule::CryptoModule(OSModuleHandle handle) : module_handle_(handle) {
  PK11_ReferenceSlot(module_handle_);
}

CryptoModule::~CryptoModule() {
  PK11_FreeSlot(module_handle_);
}

}  // namespace net
