// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/win/com_init_util.h"

#include <windows.h>
#include <winternl.h>

namespace base {
namespace win {

#if DCHECK_IS_ON()

namespace {

// Derived from combase.dll.
struct OleTlsData {
  enum ApartmentFlags {
    STA = 0x80,
    MTA = 0x140,
  };

  void* thread_base;
  void* sm_allocator;
  DWORD apartment_id;
  DWORD apartment_flags;
  // There are many more fields than this, but for our purposes, we only care
  // about |apartment_flags|. Correctly declaring the previous types allows this
  // to work between x86 and x64 builds.
};

ComApartmentType GetComApartmentTypeForThread() {
  TEB* teb = NtCurrentTeb();
  OleTlsData* ole_tls_data = reinterpret_cast<OleTlsData*>(teb->ReservedForOle);
  if (!ole_tls_data)
    return ComApartmentType::NONE;

  if (ole_tls_data->apartment_flags & OleTlsData::ApartmentFlags::STA)
    return ComApartmentType::STA;

  if ((ole_tls_data->apartment_flags & OleTlsData::ApartmentFlags::MTA) ==
      OleTlsData::ApartmentFlags::MTA) {
    return ComApartmentType::MTA;
  }

  return ComApartmentType::NONE;
}

}  // namespace

void AssertComInitialized() {
  DCHECK_NE(ComApartmentType::NONE, GetComApartmentTypeForThread());
}

void AssertComApartmentType(ComApartmentType apartment_type) {
  DCHECK_EQ(apartment_type, GetComApartmentTypeForThread());
}

#endif  // DCHECK_IS_ON()

}  // namespace win
}  // namespace base
