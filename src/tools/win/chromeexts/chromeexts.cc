// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <windows.h>
#include <dbgeng.h>
#include <wrl/client.h>

namespace {
using Microsoft::WRL::ComPtr;
constexpr size_t kMaxWindowStringLength = 256;
}  // namespace

HRESULT CALLBACK DebugExtensionInitialize(ULONG* version, ULONG* flags) {
  *version = DEBUG_EXTENSION_VERSION(0, 1);
  *flags = 0;
  return S_OK;
}

void CALLBACK DebugExtensionUninitialize() {}

HRESULT CALLBACK help(IDebugClient* client, PCSTR args) {
  ComPtr<IDebugControl> debug_control;
  HRESULT hr = client->QueryInterface(IID_PPV_ARGS(&debug_control));
  if (FAILED(hr)) {
    return hr;
  }

  debug_control->Output(DEBUG_OUTPUT_NORMAL,
                        "Chrome Windows Debugger Extension\n");
  debug_control->Output(DEBUG_OUTPUT_NORMAL,
                        "hwnd - Displays basic hwnd info.\n");
  return S_OK;
}

HRESULT CALLBACK hwnd(IDebugClient* client, PCSTR args) {
  ComPtr<IDebugControl> debug_control;
  HRESULT hr = client->QueryInterface(IID_PPV_ARGS(&debug_control));
  if (FAILED(hr)) {
    return hr;
  }

  // While sizeof(HWND) can change between 32-bit and 64-bit platforms, Windows
  // only cares about the lower 32-bits. We evaluate as 64-bit as a convenience
  // and truncate the displayed hwnds to 32-bit below.
  // See https://msdn.microsoft.com/en-us/library/aa384203.aspx
  DEBUG_VALUE value;
  hr = debug_control->Evaluate(args, DEBUG_VALUE_INT64, &value, nullptr);
  if (FAILED(hr)) {
    debug_control->Output(DEBUG_OUTPUT_ERROR, "Unable to evaluate %s\n", args);
    return hr;
  }

  HWND hwnd = reinterpret_cast<HWND>(value.I64);
  if (!IsWindow(hwnd)) {
    debug_control->Output(DEBUG_OUTPUT_NORMAL, "Not a window: %s\n", args);
    return E_FAIL;
  }

  wchar_t title[kMaxWindowStringLength];
  GetWindowText(hwnd, title, ARRAYSIZE(title));
  debug_control->Output(DEBUG_OUTPUT_NORMAL, "Title: %ws\n", title);
  wchar_t window_class[kMaxWindowStringLength];
  GetClassName(hwnd, window_class, ARRAYSIZE(window_class));
  debug_control->Output(DEBUG_OUTPUT_NORMAL, "Class: %ws\n", window_class);
  debug_control->Output(DEBUG_OUTPUT_NORMAL, "Hierarchy: \n");
  debug_control->Output(DEBUG_OUTPUT_NORMAL, "   Owner: %08x Parent: %08x\n",
                        GetWindow(hwnd, GW_OWNER), GetParent(hwnd));
  debug_control->Output(DEBUG_OUTPUT_NORMAL, "   Prev:  %08x Next:   %08x\n",
                        GetNextWindow(hwnd, GW_HWNDPREV),
                        GetNextWindow(hwnd, GW_HWNDNEXT));
  debug_control->Output(DEBUG_OUTPUT_NORMAL, "Styles: %08x (Ex: %08x)\n",
                        GetWindowLong(hwnd, GWL_STYLE),
                        GetWindowLong(hwnd, GWL_EXSTYLE));
  RECT window_rect;
  if (GetWindowRect(hwnd, &window_rect)) {
    debug_control->Output(DEBUG_OUTPUT_NORMAL, "Bounds: (%d, %d) %dx%d\n",
                          window_rect.left, window_rect.top,
                          window_rect.right - window_rect.left,
                          window_rect.bottom - window_rect.top);
  } else {
    DWORD last_error = GetLastError();
    debug_control->Output(DEBUG_OUTPUT_NORMAL,
                          "Bounds: Unavailable (Last Error = %d)\n",
                          last_error);
  }
  return S_OK;
}
