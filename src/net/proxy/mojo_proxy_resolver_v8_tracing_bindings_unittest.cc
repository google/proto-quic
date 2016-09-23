// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/proxy/mojo_proxy_resolver_v8_tracing_bindings.h"

#include <string>
#include <utility>
#include <vector>

#include "base/macros.h"
#include "base/strings/utf_string_conversions.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace net {

class MojoProxyResolverV8TracingBindingsTest : public testing::Test {
 public:
  MojoProxyResolverV8TracingBindingsTest() = default;

  void SetUp() override {
    bindings_.reset(new MojoProxyResolverV8TracingBindings<
                    MojoProxyResolverV8TracingBindingsTest>(this));
  }

  void Alert(const mojo::String& message) {
    alerts_.push_back(message.To<std::string>());
  }

  void OnError(int32_t line_number, const mojo::String& message) {
    errors_.push_back(std::make_pair(line_number, message.To<std::string>()));
  }

  void ResolveDns(interfaces::HostResolverRequestInfoPtr request_info,
                  interfaces::HostResolverRequestClientPtr client) {}

 protected:
  std::unique_ptr<MojoProxyResolverV8TracingBindings<
      MojoProxyResolverV8TracingBindingsTest>>
      bindings_;

  std::vector<std::string> alerts_;
  std::vector<std::pair<int, std::string>> errors_;

 private:
  DISALLOW_COPY_AND_ASSIGN(MojoProxyResolverV8TracingBindingsTest);
};

TEST_F(MojoProxyResolverV8TracingBindingsTest, Basic) {
  bindings_->Alert(base::ASCIIToUTF16("alert"));
  bindings_->OnError(-1, base::ASCIIToUTF16("error"));

  EXPECT_TRUE(bindings_->GetHostResolver());
  EXPECT_FALSE(bindings_->GetNetLogWithSource().net_log());

  ASSERT_EQ(1u, alerts_.size());
  EXPECT_EQ("alert", alerts_[0]);
  ASSERT_EQ(1u, errors_.size());
  EXPECT_EQ(-1, errors_[0].first);
  EXPECT_EQ("error", errors_[0].second);
}

}  // namespace net
