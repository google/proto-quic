// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/http_basic_state.h"

#include "base/memory/ptr_util.h"
#include "net/base/completion_callback.h"
#include "net/base/request_priority.h"
#include "net/http/http_request_info.h"
#include "net/socket/client_socket_handle.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {
namespace {

TEST(HttpBasicStateTest, ConstructsProperly) {
  ClientSocketHandle* const handle = new ClientSocketHandle;
  // Ownership of |handle| is passed to |state|.
  const HttpBasicState state(base::WrapUnique(handle), true /* using_proxy */,
                             false /* http_09_on_non_default_ports_enabled */);
  EXPECT_EQ(handle, state.connection());
  EXPECT_TRUE(state.using_proxy());
  EXPECT_FALSE(state.http_09_on_non_default_ports_enabled());
}

TEST(HttpBasicStateTest, ConstructsProperlyWithDifferentOptions) {
  const HttpBasicState state(base::MakeUnique<ClientSocketHandle>(),
                             false /* using_proxy */,
                             true /* http_09_on_non_default_ports_enabled */);
  EXPECT_FALSE(state.using_proxy());
  EXPECT_TRUE(state.http_09_on_non_default_ports_enabled());
}

TEST(HttpBasicStateTest, ReleaseConnectionWorks) {
  ClientSocketHandle* const handle = new ClientSocketHandle;
  // Ownership of |handle| is passed to |state|.
  HttpBasicState state(base::WrapUnique(handle), false, false);
  const std::unique_ptr<ClientSocketHandle> released_connection(
      state.ReleaseConnection());
  EXPECT_EQ(NULL, state.connection());
  EXPECT_EQ(handle, released_connection.get());
}

TEST(HttpBasicStateTest, InitializeWorks) {
  HttpBasicState state(base::MakeUnique<ClientSocketHandle>(), false, false);
  const HttpRequestInfo request_info;
  EXPECT_EQ(OK, state.Initialize(&request_info, LOW, NetLogWithSource(),
                                 CompletionCallback()));
  EXPECT_TRUE(state.parser());
}

TEST(HttpBasicStateTest, DeleteParser) {
  HttpBasicState state(base::MakeUnique<ClientSocketHandle>(), false, false);
  const HttpRequestInfo request_info;
  state.Initialize(&request_info, LOW, NetLogWithSource(),
                   CompletionCallback());
  EXPECT_TRUE(state.parser());
  state.DeleteParser();
  EXPECT_EQ(NULL, state.parser());
}

TEST(HttpBasicStateTest, GenerateRequestLineNoProxy) {
  const bool use_proxy = false;
  HttpBasicState state(base::MakeUnique<ClientSocketHandle>(), use_proxy,
                       false);
  HttpRequestInfo request_info;
  request_info.url = GURL("http://www.example.com/path?foo=bar#hoge");
  request_info.method = "PUT";
  state.Initialize(&request_info, LOW, NetLogWithSource(),
                   CompletionCallback());
  EXPECT_EQ("PUT /path?foo=bar HTTP/1.1\r\n", state.GenerateRequestLine());
}

TEST(HttpBasicStateTest, GenerateRequestLineWithProxy) {
  const bool use_proxy = true;
  HttpBasicState state(base::MakeUnique<ClientSocketHandle>(), use_proxy,
                       false);
  HttpRequestInfo request_info;
  request_info.url = GURL("http://www.example.com/path?foo=bar#hoge");
  request_info.method = "PUT";
  state.Initialize(&request_info, LOW, NetLogWithSource(),
                   CompletionCallback());
  EXPECT_EQ("PUT http://www.example.com/path?foo=bar HTTP/1.1\r\n",
            state.GenerateRequestLine());
}

}  // namespace
}  // namespace net
