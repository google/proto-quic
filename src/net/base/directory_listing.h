// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_BASE_DIRECTORY_LISTING_H_
#define NET_BASE_DIRECTORY_LISTING_H_

#include <stdint.h>
#include <string>

#include "base/strings/string16.h"
#include "net/base/net_export.h"

namespace base {
class Time;
}

namespace net {

// Call these functions to get the html snippet for a directory listing.
// The return values of both functions are in UTF-8.
NET_EXPORT std::string GetDirectoryListingHeader(const base::string16& title);

// Given the name of a file in a directory (ftp or local) and
// other information (is_dir, size, modification time), it returns
// the html snippet to add the entry for the file to the directory listing.
// Currently, it's a script tag containing a call to a Javascript function
// |addRow|.
//
// |name| is the file name to be displayed. |raw_bytes| will be used
// as the actual target of the link (so for example, ftp links should use
// server's encoding). If |raw_bytes| is an empty string, UTF-8 encoded |name|
// will be used.
//
// Both |name| and |raw_bytes| are escaped internally.
NET_EXPORT std::string GetDirectoryListingEntry(const base::string16& name,
                                                const std::string& raw_bytes,
                                                bool is_dir,
                                                int64_t size,
                                                base::Time modified);

}  // namespace net

#endif  // NET_BASE_DIRECTORY_LISTING_H_
