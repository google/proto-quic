// Copyright 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#import "net/base/mac/url_conversions.h"

#import <Foundation/Foundation.h>

#include "base/mac/scoped_nsobject.h"
#include "net/base/escape.h"
#include "url/gurl.h"
#include "url/url_canon.h"

namespace net {

NSURL* NSURLWithGURL(const GURL& url) {
  if (!url.is_valid())
    return nil;

  // NSURL strictly enforces RFC 1738 which requires that certain characters
  // are always encoded. These characters are: "<", ">", """, "#", "%", "{",
  // "}", "|", "\", "^", "~", "[", "]", and "`".
  //
  // GURL leaves some of these characters unencoded in the path, query, and
  // ref. This function manually encodes those components, and then passes the
  // result to NSURL.
  GURL::Replacements replacements;
  std::string escaped_path = EscapeNSURLPrecursor(url.path());
  std::string escaped_query = EscapeNSURLPrecursor(url.query());
  std::string escaped_ref = EscapeNSURLPrecursor(url.ref());
  if (!escaped_path.empty()) {
    replacements.SetPath(escaped_path.c_str(),
                         url::Component(0, escaped_path.size()));
  }
  if (!escaped_query.empty()) {
    replacements.SetQuery(escaped_query.c_str(),
                          url::Component(0, escaped_query.size()));
  }
  if (!escaped_ref.empty()) {
    replacements.SetRef(escaped_ref.c_str(),
                        url::Component(0, escaped_ref.size()));
  }
  GURL escaped_url = url.ReplaceComponents(replacements);

  base::scoped_nsobject<NSString> escaped_url_string(
      [[NSString alloc] initWithUTF8String:escaped_url.spec().c_str()]);
  return [NSURL URLWithString:escaped_url_string];
}

GURL GURLWithNSURL(NSURL* url) {
  if (url)
    return GURL([[url absoluteString] UTF8String]);
  return GURL();
}

}  // namespace net
