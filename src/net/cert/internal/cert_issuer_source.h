// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_CERT_INTERNAL_CERT_ISSUER_SOURCE_H_
#define NET_CERT_INTERNAL_CERT_ISSUER_SOURCE_H_

#include <memory>
#include <vector>

#include "base/callback.h"
#include "net/base/net_export.h"
#include "net/cert/internal/completion_status.h"
#include "net/cert/internal/parsed_certificate.h"

namespace net {

// Interface for looking up issuers of a certificate during path building.
// Provides a synchronous and asynchronous method for retrieving issuers, so the
// path builder can try to complete synchronously first. The caller is expected
// to call SyncGetIssuersOf first, see if it can make progress with those
// results, and if not, then fall back to calling AsyncGetIssuersOf.
// An implementations may choose to return results from either one of the Get
// methods, or from both.
class NET_EXPORT CertIssuerSource {
 public:
  class NET_EXPORT Request {
   public:
    Request() = default;
    // Destruction of the Request cancels it.
    virtual ~Request() = default;

    // Retrieves the next issuer.
    //
    // If one is available it will be stored in |out_cert| and SYNC will be
    // returned. GetNext should be called again to retrieve any remaining
    // issuers.
    //
    // If no issuers are currently available, |out_cert| will be cleared and the
    // return value will indicate if the Request is exhausted. If the return
    // value is ASYNC, the |issuers_callback| that was passed to
    // AsyncGetIssuersOf will be called again (unless the Request is destroyed
    // first). If the return value is SYNC, the Request is complete and the
    // |issuers_callback| will not be called again.
    virtual CompletionStatus GetNext(
        scoped_refptr<ParsedCertificate>* out_cert) = 0;

   private:
    DISALLOW_COPY_AND_ASSIGN(Request);
  };

  using IssuerCallback = base::Callback<void(Request*)>;

  virtual ~CertIssuerSource() = default;

  // Finds certificates whose Subject matches |cert|'s Issuer.
  // Matches are appended to |issuers|. Any existing contents of |issuers| will
  // not be modified. If the implementation does not support synchronous
  // lookups, or if there are no matches, |issuers| is not modified.
  virtual void SyncGetIssuersOf(const ParsedCertificate* cert,
                                ParsedCertificateList* issuers) = 0;

  // Finds certificates whose Subject matches |cert|'s Issuer.
  // If an async callback will be made |*out_req| is filled with a Request
  // object which may be destroyed to cancel the callback. If the implementation
  // does not support asynchronous lookups or can determine synchronously that
  // it would return no results, |*out_req| will be set to nullptr.
  //
  // When matches are available or the request is complete, |issuers_callback|
  // will be called with a pointer to the same Request. The Request::GetNext
  // method may then be used to iterate through the retrieved issuers. Note that
  // |issuers_callback| may be called multiple times. See the documentation for
  // Request::GetNext for more details.
  virtual void AsyncGetIssuersOf(const ParsedCertificate* cert,
                                 const IssuerCallback& issuers_callback,
                                 std::unique_ptr<Request>* out_req) = 0;
};

}  // namespace net

#endif  // NET_CERT_INTERNAL_CERT_ISSUER_SOURCE_H_
