// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SPDY_SPDY_FLAGS_H_
#define NET_SPDY_SPDY_FLAGS_H_

#include "net/base/net_export.h"

namespace net {

NET_EXPORT_PRIVATE extern bool FLAGS_chromium_http2_flag_log_compressed_size;
NET_EXPORT_PRIVATE extern bool
    FLAGS_chromium_reloadable_flag_increase_hpack_table_size;
NET_EXPORT_PRIVATE extern bool FLAGS_use_nested_spdy_framer_decoder;

}  // namespace net

#endif  // NET_SPDY_SPDY_FLAGS_H_
