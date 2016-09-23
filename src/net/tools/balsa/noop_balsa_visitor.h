// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Provides empty BalsaVisitorInterface overrides for convenience.
// Intended to be used as a base class for BalsaVisitorInterface subclasses that
// only need to override a small number of methods.

#ifndef NET_TOOLS_BALSA_NOOP_BALSA_VISITOR_H_
#define NET_TOOLS_BALSA_NOOP_BALSA_VISITOR_H_

#include <stddef.h>

#include "base/macros.h"
#include "net/tools/balsa/balsa_visitor_interface.h"

namespace net {

// See file comment above.
class NoOpBalsaVisitor : public BalsaVisitorInterface {
 public:
  NoOpBalsaVisitor() { }
  ~NoOpBalsaVisitor() override {}

  void ProcessBodyInput(const char* input, size_t size) override {}
  void ProcessBodyData(const char* input, size_t size) override {}
  void ProcessHeaderInput(const char* input, size_t size) override {}
  void ProcessTrailerInput(const char* input, size_t size) override {}
  void ProcessHeaders(const BalsaHeaders& headers) override {}

  void ProcessRequestFirstLine(const char* line_input,
                               size_t line_length,
                               const char* method_input,
                               size_t method_length,
                               const char* request_uri_input,
                               size_t request_uri_length,
                               const char* version_input,
                               size_t version_length) override {}
  void ProcessResponseFirstLine(const char* line_input,
                                size_t line_length,
                                const char* version_input,
                                size_t version_length,
                                const char* status_input,
                                size_t status_length,
                                const char* reason_input,
                                size_t reason_length) override {}
  void ProcessChunkLength(size_t chunk_length) override {}
  void ProcessChunkExtensions(const char* input, size_t size) override {}
  void HeaderDone() override {}
  void MessageDone() override {}
  void HandleHeaderError(BalsaFrame* framer) override {}
  void HandleHeaderWarning(BalsaFrame* framer) override {}
  void HandleChunkingError(BalsaFrame* framer) override {}
  void HandleBodyError(BalsaFrame* framer) override {}

 private:
  DISALLOW_COPY_AND_ASSIGN(NoOpBalsaVisitor);
};

}  // namespace net

#endif  // NET_TOOLS_BALSA_NOOP_BALSA_VISITOR_H_
