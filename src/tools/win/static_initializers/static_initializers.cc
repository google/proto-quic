// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <dia2.h>
#include <stdio.h>

#include <string>

// Create an IDiaData source and open a PDB file.
static bool LoadDataFromPdb(const wchar_t* filename,
                            IDiaDataSource** source,
                            IDiaSession** session,
                            IDiaSymbol** global,
                            DWORD* machine_type) {
  // Alternate path to search for debug data.
  const wchar_t search_path[] = L"SRV**\\\\symbols\\symbols";
  DWORD mach_type = 0;
  HRESULT hr = CoInitialize(NULL);

  // Obtain access to the provider.
  hr = CoCreateInstance(__uuidof(DiaSource),
                        NULL,
                        CLSCTX_INPROC_SERVER,
                        __uuidof(IDiaDataSource),
                        (void**)source);

  if (FAILED(hr)) {
    printf("CoCreateInstance failed - HRESULT = %08lX\n", hr);
    return false;
  }

  wchar_t ext[MAX_PATH];
  _wsplitpath_s(filename, NULL, 0, NULL, 0, NULL, 0, ext, MAX_PATH);

  // Open and prepare the debug data associated with the executable.
  hr = (*source)->loadDataForExe(filename, search_path, NULL);
  if (FAILED(hr)) {
    printf("loadDataForExe failed - HRESULT = %08lX\n", hr);
    return false;
  }

  // Open a session for querying symbols.
  hr = (*source)->openSession(session);

  if (FAILED(hr)) {
    printf("openSession failed - HRESULT = %08lX\n", hr);
    return false;
  }

  // Retrieve a reference to the global scope.
  hr = (*session)->get_globalScope(global);

  if (FAILED(hr)) {
    printf("get_globalScope failed\n");
    return false;
  }

  // Set machine type for getting correct register names.
  if (SUCCEEDED((*global)->get_machineType(&mach_type))) {
    switch (mach_type) {
      case IMAGE_FILE_MACHINE_I386:
        *machine_type = CV_CFL_80386;
        break;
      case IMAGE_FILE_MACHINE_IA64:
        *machine_type = CV_CFL_IA64;
        break;
      case IMAGE_FILE_MACHINE_AMD64:
        *machine_type = CV_CFL_AMD64;
        break;
      default:
        printf("unexpected machine type\n");
        return false;
    }
  }

  return true;
}

// Release DIA objects and CoUninitialize.
static void Cleanup(IDiaSymbol* global_symbol, IDiaSession* dia_session) {
  if (global_symbol)
    global_symbol->Release();
  if (dia_session)
    dia_session->Release();
  CoUninitialize();
}

static void PrintIfDynamicInitializer(const std::wstring& module,
                                      IDiaSymbol* symbol) {
  DWORD symtag;

  if (FAILED(symbol->get_symTag(&symtag)))
    return;

  if (symtag != SymTagFunction && symtag != SymTagBlock)
    return;

  BSTR bstr_name;
  if (SUCCEEDED(symbol->get_name(&bstr_name))) {
    if (wcsstr(bstr_name, L"`dynamic initializer for '")) {
      wprintf(L"%s: %s\n", module.c_str(), bstr_name);
      SysFreeString(bstr_name);
    }
  }
}

static bool DumpStaticInitializers(IDiaSymbol* global_symbol) {
  // Retrieve the compilands first.
  IDiaEnumSymbols* enum_symbols;
  if (FAILED(global_symbol->findChildren(
          SymTagCompiland, NULL, nsNone, &enum_symbols))) {
    return false;
  }

  IDiaSymbol* compiland;
  ULONG element_count = 0;

  std::wstring current_module;
  while (SUCCEEDED(enum_symbols->Next(1, &compiland, &element_count)) &&
         (element_count == 1)) {
    BSTR bstr_name;
    if (FAILED(compiland->get_name(&bstr_name))) {
      current_module = L"<unknown>";
    } else {
      current_module = bstr_name;
      SysFreeString(bstr_name);
    }

    // Find all the symbols defined in this compiland, and print them if they
    // have the name corresponding to an initializer.
    IDiaEnumSymbols* enum_children;
    if (SUCCEEDED(compiland->findChildren(
            SymTagNull, NULL, nsNone, &enum_children))) {
      IDiaSymbol* symbol;
      ULONG children = 0;
      while (SUCCEEDED(enum_children->Next(1, &symbol, &children)) &&
             children == 1) {  // Enumerate until we don't get any more symbols.
        PrintIfDynamicInitializer(current_module, symbol);
        symbol->Release();
      }
      enum_children->Release();
    }
    compiland->Release();
  }

  enum_symbols->Release();
  return true;
}

int wmain(int argc, wchar_t* argv[]) {
  if (argc != 2) {
    wprintf(L"usage: %ls binary_name\n", argv[0]);
    return 1;
  }

  IDiaDataSource* dia_data_source;
  IDiaSession* dia_session;
  IDiaSymbol* global_symbol;
  DWORD machine_type = CV_CFL_80386;
  if (!LoadDataFromPdb(argv[1],
                       &dia_data_source,
                       &dia_session,
                       &global_symbol,
                       &machine_type)) {
    wprintf(L"Couldn't load data from pdb.\n");
    return 1;
  }

  wprintf(L"Static initializers in %s:\n", argv[1]);

  if (!DumpStaticInitializers(global_symbol))
    return 1;

  Cleanup(global_symbol, dia_session);

  return 0;
}
