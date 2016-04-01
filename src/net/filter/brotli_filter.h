// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_FILTER_BROTLI_FILTER_H_
#define NET_FILTER_BROTLI_FILTER_H_

#include "net/filter/filter.h"

namespace net {

// Creates instance of filter or returns nullptr if brotli is not supported.
Filter* CreateBrotliFilter(Filter::FilterType type_id);

}  // namespace net

#endif  // NET_FILTER_BROTLI_FILTER_H__
