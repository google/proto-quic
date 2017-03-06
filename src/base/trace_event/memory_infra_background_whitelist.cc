// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/trace_event/memory_infra_background_whitelist.h"

#include <ctype.h>
#include <string.h>

#include <string>

namespace base {
namespace trace_event {
namespace {

// The names of dump providers whitelisted for background tracing. Dump
// providers can be added here only if the background mode dump has very
// less performance and memory overhead.
const char* const kDumpProviderWhitelist[] = {
    "android::ResourceManagerImpl",
    "BlinkGC",
    "ClientDiscardableSharedMemoryManager",
    "DOMStorage",
    "DiscardableSharedMemoryManager",
    "IndexedDBBackingStore",
    "JavaHeap",
    "LevelDB",
    "LeveldbValueStore",
    "Malloc",
    "MemoryCache",
    "PartitionAlloc",
    "ProcessMemoryMetrics",
    "Skia",
    "Sql",
    "URLRequestContext",
    "V8Isolate",
    "WinHeap",
    "SyncDirectory",
    "TabRestoreServiceHelper",
    nullptr  // End of list marker.
};

// A list of string names that are allowed for the memory allocator dumps in
// background mode.
const char* const kAllocatorDumpNameWhitelist[] = {
    "blink_gc",
    "blink_gc/allocated_objects",
    "discardable",
    "discardable/child_0x?",
    "dom_storage/0x?/cache_size",
    "dom_storage/session_storage_0x?",
    "java_heap",
    "java_heap/allocated_objects",
    "leveldb/index_db/0x?",
    "leveldb/leveldb_proto/0x?",
    "leveldb/value_store/Extensions.Database.Open.Settings/0x?",
    "leveldb/value_store/Extensions.Database.Open.Rules/0x?",
    "leveldb/value_store/Extensions.Database.Open.State/0x?",
    "leveldb/value_store/Extensions.Database.Open/0x?",
    "leveldb/value_store/Extensions.Database.Restore/0x?",
    "leveldb/value_store/Extensions.Database.Value.Restore/0x?",
    "malloc",
    "malloc/allocated_objects",
    "malloc/metadata_fragmentation_caches",
    "net/http_network_session_0x?",
    "net/http_network_session_0x?/quic_stream_factory",
    "net/http_network_session_0x?/socket_pool",
    "net/http_network_session_0x?/spdy_session_pool",
    "net/http_network_session_0x?/stream_factory",
    "net/sdch_manager_0x?",
    "net/ssl_session_cache",
    "net/url_request_context_0x?",
    "net/url_request_context_0x?/http_cache",
    "net/url_request_context_0x?/http_network_session",
    "net/url_request_context_0x?/sdch_manager",
    "web_cache/Image_resources",
    "web_cache/CSS stylesheet_resources",
    "web_cache/Script_resources",
    "web_cache/XSL stylesheet_resources",
    "web_cache/Font_resources",
    "web_cache/Other_resources",
    "partition_alloc/allocated_objects",
    "partition_alloc/partitions",
    "partition_alloc/partitions/array_buffer",
    "partition_alloc/partitions/buffer",
    "partition_alloc/partitions/fast_malloc",
    "partition_alloc/partitions/layout",
    "skia/sk_glyph_cache",
    "skia/sk_resource_cache",
    "sqlite",
    "ui/resource_manager_0x?",
    "v8/isolate_0x?/heap_spaces",
    "v8/isolate_0x?/heap_spaces/code_space",
    "v8/isolate_0x?/heap_spaces/large_object_space",
    "v8/isolate_0x?/heap_spaces/map_space",
    "v8/isolate_0x?/heap_spaces/new_space",
    "v8/isolate_0x?/heap_spaces/old_space",
    "v8/isolate_0x?/heap_spaces/other_spaces",
    "v8/isolate_0x?/malloc",
    "v8/isolate_0x?/zapped_for_debug",
    "winheap",
    "winheap/allocated_objects",
    "sync/0x?/kernel",
    "sync/0x?/store",
    "sync/0x?/model_type/APP",
    "sync/0x?/model_type/APP_LIST",
    "sync/0x?/model_type/APP_NOTIFICATION",
    "sync/0x?/model_type/APP_SETTING",
    "sync/0x?/model_type/ARC_PACKAGE",
    "sync/0x?/model_type/ARTICLE",
    "sync/0x?/model_type/AUTOFILL",
    "sync/0x?/model_type/AUTOFILL_PROFILE",
    "sync/0x?/model_type/AUTOFILL_WALLET",
    "sync/0x?/model_type/BOOKMARK",
    "sync/0x?/model_type/DEVICE_INFO",
    "sync/0x?/model_type/DICTIONARY",
    "sync/0x?/model_type/EXPERIMENTS",
    "sync/0x?/model_type/EXTENSION",
    "sync/0x?/model_type/EXTENSION_SETTING",
    "sync/0x?/model_type/FAVICON_IMAGE",
    "sync/0x?/model_type/FAVICON_TRACKING",
    "sync/0x?/model_type/HISTORY_DELETE_DIRECTIVE",
    "sync/0x?/model_type/MANAGED_USER",
    "sync/0x?/model_type/MANAGED_USER_SETTING",
    "sync/0x?/model_type/MANAGED_USER_SHARED_SETTING",
    "sync/0x?/model_type/MANAGED_USER_WHITELIST",
    "sync/0x?/model_type/NIGORI",
    "sync/0x?/model_type/PASSWORD",
    "sync/0x?/model_type/PREFERENCE",
    "sync/0x?/model_type/PRINTER",
    "sync/0x?/model_type/PRIORITY_PREFERENCE",
    "sync/0x?/model_type/READING_LIST",
    "sync/0x?/model_type/SEARCH_ENGINE",
    "sync/0x?/model_type/SESSION",
    "sync/0x?/model_type/SYNCED_NOTIFICATION",
    "sync/0x?/model_type/SYNCED_NOTIFICATION_APP_INFO",
    "sync/0x?/model_type/THEME",
    "sync/0x?/model_type/TYPED_URL",
    "sync/0x?/model_type/WALLET_METADATA",
    "sync/0x?/model_type/WIFI_CREDENTIAL",
    "tab_restore/service_helper_0x?/entries",
    "tab_restore/service_helper_0x?/entries/tab_0x?",
    "tab_restore/service_helper_0x?/entries/window_0x?",
    nullptr  // End of list marker.
};

const char* const* g_dump_provider_whitelist = kDumpProviderWhitelist;
const char* const* g_allocator_dump_name_whitelist =
    kAllocatorDumpNameWhitelist;

}  // namespace

bool IsMemoryDumpProviderWhitelisted(const char* mdp_name) {
  for (size_t i = 0; g_dump_provider_whitelist[i] != nullptr; ++i) {
    if (strcmp(mdp_name, g_dump_provider_whitelist[i]) == 0)
      return true;
  }
  return false;
}

bool IsMemoryAllocatorDumpNameWhitelisted(const std::string& name) {
  // Remove special characters, numbers (including hexadecimal which are marked
  // by '0x') from the given string.
  const size_t length = name.size();
  std::string stripped_str;
  stripped_str.reserve(length);
  bool parsing_hex = false;
  for (size_t i = 0; i < length; ++i) {
    if (parsing_hex && isxdigit(name[i]))
      continue;
    parsing_hex = false;
    if (i + 1 < length && name[i] == '0' && name[i + 1] == 'x') {
      parsing_hex = true;
      stripped_str.append("0x?");
      ++i;
    } else {
      stripped_str.push_back(name[i]);
    }
  }

  for (size_t i = 0; g_allocator_dump_name_whitelist[i] != nullptr; ++i) {
    if (stripped_str == g_allocator_dump_name_whitelist[i]) {
      return true;
    }
  }
  return false;
}

void SetDumpProviderWhitelistForTesting(const char* const* list) {
  g_dump_provider_whitelist = list;
}

void SetAllocatorDumpNameWhitelistForTesting(const char* const* list) {
  g_allocator_dump_name_whitelist = list;
}

}  // namespace trace_event
}  // namespace base
