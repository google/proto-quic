// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/ftp_protocol_handler.h"

#include "base/logging.h"
#include "net/base/net_errors.h"
#include "net/base/port_util.h"
#include "net/ftp/ftp_auth_cache.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_error_job.h"
#include "net/url_request/url_request_ftp_job.h"
#include "url/gurl.h"

namespace net {

FtpProtocolHandler::FtpProtocolHandler(
    FtpTransactionFactory* ftp_transaction_factory)
    : ftp_transaction_factory_(ftp_transaction_factory),
      ftp_auth_cache_(new FtpAuthCache) {
  DCHECK(ftp_transaction_factory_);
}

FtpProtocolHandler::~FtpProtocolHandler() {
}

URLRequestJob* FtpProtocolHandler::MaybeCreateJob(
    URLRequest* request, NetworkDelegate* network_delegate) const {
  DCHECK_EQ("ftp", request->url().scheme());

  if (!IsPortAllowedForScheme(request->url().EffectiveIntPort(),
                              request->url().scheme())) {
    return new URLRequestErrorJob(request, network_delegate, ERR_UNSAFE_PORT);
  }

  return new URLRequestFtpJob(request,
                              network_delegate,
                              ftp_transaction_factory_,
                              ftp_auth_cache_.get());
}

}  // namespace net
