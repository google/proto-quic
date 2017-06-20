// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/win/com_init_check_hook.h"

#include <windows.h>
#include <objbase.h>
#include <stdint.h>
#include <string.h>

#include "base/synchronization/lock.h"
#include "base/win/com_init_util.h"
#include "base/win/patch_util.h"

namespace base {
namespace win {

#if COM_INIT_CHECK_HOOK_ENABLED()

namespace {

// Hotpatchable Microsoft x86 32-bit functions take one of two forms:
// Newer format:
// RelAddr  Binary     Instruction                 Remarks
//      -5  cc         int 3
//      -4  cc         int 3
//      -3  cc         int 3
//      -2  cc         int 3
//      -1  cc         int 3
//       0  8bff       mov edi,edi                 Actual entry point and no-op.
//       2  ...                                    Actual body.
//
// Older format:
// RelAddr  Binary     Instruction                 Remarks
//      -5  90         nop
//      -4  90         nop
//      -3  90         nop
//      -2  90         nop
//      -1  90         nop
//       0  8bff       mov edi,edi                 Actual entry point and no-op.
//       2  ...                                    Actual body.
//
// The "int 3" or nop sled as well as entry point no-op are critical, as they
// are just enough to patch in a short backwards jump to -5 (2 bytes) then that
// can do a relative 32-bit jump about 2GB before or after the current address.
//
// To perform a hotpatch, we need to figure out where we want to go and where
// we are now as the final jump is relative. Let's say we want to jump to
// 0x12345678. Relative jumps are calculated from eip, which for our jump is the
// next instruction address. For the example above, that means we start at a 0
// base address.
//
// Our patch will then look as follows:
// RelAddr  Binary     Instruction                 Remarks
//      -5  e978563412 jmp 0x12345678-(-0x5+0x5)   Note little-endian format.
//       0  ebf9       jmp -0x5-(0x0+0x2)          Goes to RelAddr -0x5.
//       2  ...                                    Actual body.
// Note: The jmp instructions above are structured as
//       Address(Destination)-(Address(jmp Instruction)+sizeof(jmp Instruction))

// The struct below is provided for convenience and must be packed together byte
// by byte with no word alignment padding. This comes at a very small
// performance cost because now there are shifts handling the fields, but
// it improves readability.
#pragma pack(push, 1)
struct StructuredHotpatch {
  unsigned char jmp_32_relative = 0xe9;  // jmp relative 32-bit.
  int32_t relative_address = 0;          // 32-bit signed operand.
  unsigned char jmp_8_relative = 0xeb;   // jmp relative 8-bit.
  unsigned char back_address = 0xf9;     // Operand of -7.
};
#pragma pack(pop)

static_assert(sizeof(StructuredHotpatch) == 7,
              "Needs to be exactly 7 bytes for the hotpatch to work.");

// nop Function Padding with "mov edi,edi"
const unsigned char g_hotpatch_placeholder_nop[] = {0x90, 0x90, 0x90, 0x90,
                                                    0x90, 0x8b, 0xff};

// int 3 Function Padding with "mov edi,edi"
const unsigned char g_hotpatch_placeholder_int3[] = {0xcc, 0xcc, 0xcc, 0xcc,
                                                     0xcc, 0x8b, 0xff};

class HookManager {
 public:
  static HookManager* GetInstance() {
    static auto* hook_manager = new HookManager();
    return hook_manager;
  }

  void RegisterHook() {
    AutoLock auto_lock(lock_);
    if (init_count_ == 0)
      WriteHook();

    ++init_count_;
  }

  void UnregisterHook() {
    AutoLock auto_lock(lock_);
    DCHECK_NE(0U, init_count_);
    if (init_count_ == 1)
      RevertHook();

    --init_count_;
  }

 private:
  enum class HotpatchPlaceholderFormat {
    // The hotpatch placeholder is currently unknown
    UNKNOWN,
    // The hotpatch placeholder used int 3's in the sled.
    INT3,
    // The hotpatch placeholder used nop's in the sled.
    NOP,
  };

  HookManager() = default;
  ~HookManager() = default;

  void WriteHook() {
    lock_.AssertAcquired();
    DCHECK(!ole32_library_);
    ole32_library_ = ::LoadLibrary(L"ole32.dll");

    if (!ole32_library_)
      return;

    // See banner comment above why this subtracts 5 bytes.
    co_create_instance_padded_address_ =
        reinterpret_cast<uint32_t>(
            GetProcAddress(ole32_library_, "CoCreateInstance")) - 5;

    // See banner comment above why this adds 7 bytes.
    original_co_create_instance_body_function_ =
        reinterpret_cast<decltype(original_co_create_instance_body_function_)>(
            co_create_instance_padded_address_ + 7);

    HotpatchPlaceholderFormat format = GetHotpatchPlaceholderFormat(
        reinterpret_cast<const void*>(co_create_instance_padded_address_));
    if (format == HotpatchPlaceholderFormat::UNKNOWN) {
      NOTREACHED() << "Unrecognized hotpatch function format.";
      return;
    }

    uint32_t dchecked_co_create_instance_address = reinterpret_cast<uint32_t>(
        static_cast<void*>(&HookManager::DCheckedCoCreateInstance));
    uint32_t jmp_offset_base_address = co_create_instance_padded_address_ + 5;
    StructuredHotpatch structured_hotpatch;
    structured_hotpatch.relative_address =
        dchecked_co_create_instance_address - jmp_offset_base_address;

    DCHECK_EQ(hotpatch_placeholder_format_, HotpatchPlaceholderFormat::UNKNOWN);
    DWORD patch_result = internal::ModifyCode(
        reinterpret_cast<void*>(co_create_instance_padded_address_),
        reinterpret_cast<void*>(&structured_hotpatch),
        sizeof(structured_hotpatch));
    if (patch_result == NO_ERROR)
      hotpatch_placeholder_format_ = format;
  }

  void RevertHook() {
    lock_.AssertAcquired();
    switch (hotpatch_placeholder_format_) {
      case HotpatchPlaceholderFormat::INT3:
        internal::ModifyCode(
            reinterpret_cast<void*>(co_create_instance_padded_address_),
            reinterpret_cast<const void*>(&g_hotpatch_placeholder_int3),
            sizeof(g_hotpatch_placeholder_int3));
        break;
      case HotpatchPlaceholderFormat::NOP:
        internal::ModifyCode(
            reinterpret_cast<void*>(co_create_instance_padded_address_),
            reinterpret_cast<const void*>(&g_hotpatch_placeholder_nop),
            sizeof(g_hotpatch_placeholder_nop));
        break;
      case HotpatchPlaceholderFormat::UNKNOWN:
        break;
    }

    hotpatch_placeholder_format_ = HotpatchPlaceholderFormat::UNKNOWN;

    if (ole32_library_) {
      ::FreeLibrary(ole32_library_);
      ole32_library_ = nullptr;
    }

    co_create_instance_padded_address_ = 0;
    original_co_create_instance_body_function_ = nullptr;
  }

  HotpatchPlaceholderFormat GetHotpatchPlaceholderFormat(const void* address) {
    if (::memcmp(reinterpret_cast<void*>(co_create_instance_padded_address_),
                 reinterpret_cast<const void*>(&g_hotpatch_placeholder_int3),
                 sizeof(g_hotpatch_placeholder_int3)) == 0) {
      return HotpatchPlaceholderFormat::INT3;
    }

    if (::memcmp(reinterpret_cast<void*>(co_create_instance_padded_address_),
                 reinterpret_cast<const void*>(&g_hotpatch_placeholder_nop),
                 sizeof(g_hotpatch_placeholder_nop)) == 0) {
      return HotpatchPlaceholderFormat::NOP;
    }

    return HotpatchPlaceholderFormat::UNKNOWN;
  }

  static HRESULT __stdcall DCheckedCoCreateInstance(const CLSID& rclsid,
                                                    IUnknown* pUnkOuter,
                                                    DWORD dwClsContext,
                                                    REFIID riid,
                                                    void** ppv) {
    // Chrome COM callers need to make sure that their thread is configured to
    // process COM objects to avoid creating an implicit MTA or silently failing
    // STA object creation call due to the SUCCEEDED() pattern for COM calls.
    //
    // If you hit this assert as part of migrating to the Task Scheduler,
    // evaluate your threading guarantees and dispatch your work with
    // base::CreateCOMSTATaskRunnerWithTraits().
    //
    // If you need MTA support, ping //base/task_scheduler/OWNERS.
    AssertComInitialized();
    return original_co_create_instance_body_function_(rclsid, pUnkOuter,
                                                      dwClsContext, riid, ppv);
  }

  // Synchronizes everything in this class.
  base::Lock lock_;
  size_t init_count_ = 0;
  HMODULE ole32_library_ = nullptr;
  uint32_t co_create_instance_padded_address_ = 0;
  HotpatchPlaceholderFormat hotpatch_placeholder_format_ =
      HotpatchPlaceholderFormat::UNKNOWN;
  static decltype(
      ::CoCreateInstance)* original_co_create_instance_body_function_;

  DISALLOW_COPY_AND_ASSIGN(HookManager);
};

decltype(::CoCreateInstance)*
    HookManager::original_co_create_instance_body_function_ = nullptr;

}  // namespace

#endif  // COM_INIT_CHECK_HOOK_ENABLED()

ComInitCheckHook::ComInitCheckHook() {
#if COM_INIT_CHECK_HOOK_ENABLED()
  HookManager::GetInstance()->RegisterHook();
#endif  // COM_INIT_CHECK_HOOK_ENABLED()
}

ComInitCheckHook::~ComInitCheckHook() {
#if COM_INIT_CHECK_HOOK_ENABLED()
  HookManager::GetInstance()->UnregisterHook();
#endif  // COM_INIT_CHECK_HOOK_ENABLED()
}

}  // namespace win
}  // namespace base
