// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_BASE_SDCH_DICTIONARY_H_
#define NET_BASE_SDCH_DICTIONARY_H_

#include <stddef.h>

#include <memory>
#include <set>
#include <string>

#include "base/memory/ref_counted.h"
#include "base/time/time.h"
#include "net/base/net_export.h"
#include "net/base/sdch_problem_codes.h"
#include "url/gurl.h"

namespace net {

// Contains all information for an SDCH dictionary.  This class is intended
// to be used with a RefCountedData<> wrappers.  These dictionaries
// are vended by SdchManager; see sdch_manager.h for details.
class NET_EXPORT_PRIVATE SdchDictionary {
 public:
  // Construct a vc-diff usable dictionary from the dictionary_text starting
  // at the given offset. The supplied client_hash should be used to
  // advertise the dictionary's availability relative to the suppplied URL.
  SdchDictionary(const std::string& dictionary_text,
                 size_t offset,
                 const std::string& client_hash,
                 const std::string& server_hash,
                 const GURL& url,
                 const std::string& domain,
                 const std::string& path,
                 const base::Time& expiration,
                 const std::set<int>& ports);

  ~SdchDictionary();

  // Sdch filters can get our text to use in decoding compressed data.
  const std::string& text() const { return text_; }

  const GURL& url() const { return url_; }
  const std::string& client_hash() const { return client_hash_; }
  const std::string& server_hash() const { return server_hash_; }
  const std::string& domain() const { return domain_; }
  const std::string& path() const { return path_; }
  const base::Time& expiration() const { return expiration_; }
  const std::set<int>& ports() const { return ports_; }

  // Security methods to check if we can establish a new dictionary with the
  // given data, that arrived in response to get of dictionary_url.
  static SdchProblemCode CanSet(const std::string& domain,
                                const std::string& path,
                                const std::set<int>& ports,
                                const GURL& dictionary_url);

  // Security method to check if we can use a dictionary to decompress a
  // target that arrived with a reference to this dictionary.
  SdchProblemCode CanUse(const GURL& referring_url) const;

  // Compare paths to see if they "match" for dictionary use.
  static bool PathMatch(const std::string& path,
                        const std::string& restriction);

  // Is this dictionary expired?
  bool Expired() const;

 private:
  friend class base::RefCountedData<SdchDictionary>;

  // Private copy-constructor to support RefCountedData<>, which requires
  // that an object stored in it be either DefaultConstructible or
  // CopyConstructible
  SdchDictionary(const SdchDictionary& rhs);

  // The actual text of the dictionary.
  std::string text_;

  // Part of the hash of text_ that the client uses to advertise the fact that
  // it has a specific dictionary pre-cached.
  std::string client_hash_;

  // Part of the hash of text_ that the server uses to identify the
  // dictionary it wants used for decoding.
  std::string server_hash_;

  // The GURL that arrived with the text_ in a URL request to specify where
  // this dictionary may be used.
  const GURL url_;

  // Metadate "headers" in before dictionary text contained the following:
  // Each dictionary payload consists of several headers, followed by the text
  // of the dictionary. The following are the known headers.
  const std::string domain_;
  const std::string path_;
  const base::Time expiration_;  // Implied by max-age.
  const std::set<int> ports_;

  void operator=(const SdchDictionary&) = delete;
};

}  // namespace net

#endif  // NET_BASE_SDCH_DICTIONARY_H_
