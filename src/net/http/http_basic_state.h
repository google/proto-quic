// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// A class that stores the common state between HttpBasicStream and
// WebSocketBasicHandshakeStream.

#ifndef NET_HTTP_HTTP_BASIC_STATE_H_
#define NET_HTTP_HTTP_BASIC_STATE_H_

#include <memory>
#include <string>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "net/base/completion_callback.h"
#include "net/base/net_export.h"
#include "net/base/request_priority.h"

namespace net {

class BoundNetLog;
class ClientSocketHandle;
class GrowableIOBuffer;
class HttpStreamParser;
struct HttpRequestInfo;

class NET_EXPORT_PRIVATE HttpBasicState {
 public:
  HttpBasicState(ClientSocketHandle* connection, bool using_proxy);
  ~HttpBasicState();

  // Initialize() must be called before using any of the other methods.
  int Initialize(const HttpRequestInfo* request_info,
                 RequestPriority priority,
                 const BoundNetLog& net_log,
                 const CompletionCallback& callback);

  HttpStreamParser* parser() const { return parser_.get(); }

  bool using_proxy() const { return using_proxy_; }

  // Deletes |parser_| and sets it to NULL.
  void DeleteParser();

  ClientSocketHandle* connection() const { return connection_.get(); }

  std::unique_ptr<ClientSocketHandle> ReleaseConnection();

  scoped_refptr<GrowableIOBuffer> read_buf() const;

  // Generates a string of the form "METHOD PATH HTTP/1.1\r\n", based on the
  // values of request_info_ and using_proxy_.
  std::string GenerateRequestLine() const;

 private:
  scoped_refptr<GrowableIOBuffer> read_buf_;

  std::unique_ptr<HttpStreamParser> parser_;

  std::unique_ptr<ClientSocketHandle> connection_;

  const bool using_proxy_;

  const HttpRequestInfo* request_info_;

  DISALLOW_COPY_AND_ASSIGN(HttpBasicState);
};

}  // namespace net

#endif  // NET_HTTP_HTTP_BASIC_STATE_H_
