// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/spdy_flags.h"

// Use NestedSpdyFramerDecoder.
bool FLAGS_use_nested_spdy_framer_decoder = false;

// Enforce the limit we advertise on frame payload size with
// GOAWAY_FRAME_SIZE_ERROR.
bool FLAGS_chromium_http2_flag_enforce_max_frame_size = true;

// Use SpdyHeaderBlock::AppendValueOrAddHeader when adding to headers.
bool FLAGS_chromium_http2_flag_use_new_spdy_header_block_header_joining = true;
