// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/websockets/websocket_extension_parser.h"

#include "base/logging.h"
#include "net/http/http_util.h"

namespace net {

WebSocketExtensionParser::WebSocketExtensionParser() {}

WebSocketExtensionParser::~WebSocketExtensionParser() {}

bool WebSocketExtensionParser::Parse(const char* data, size_t size) {
  current_ = data;
  end_ = data + size;
  extensions_.clear();

  bool failed = false;

  do {
    WebSocketExtension extension;
    if (!ConsumeExtension(&extension)) {
      failed = true;
      break;
    }
    extensions_.push_back(extension);

    ConsumeSpaces();
  } while (ConsumeIfMatch(','));

  if (!failed && current_ == end_)
    return true;

  extensions_.clear();
  return false;
}

bool WebSocketExtensionParser::Consume(char c) {
  ConsumeSpaces();
  if (current_ == end_ || c != *current_)
    return false;
  ++current_;
  return true;
}

bool WebSocketExtensionParser::ConsumeExtension(WebSocketExtension* extension) {
  base::StringPiece name;
  if (!ConsumeToken(&name))
    return false;
  *extension = WebSocketExtension(name.as_string());

  while (ConsumeIfMatch(';')) {
    WebSocketExtension::Parameter parameter((std::string()));
    if (!ConsumeExtensionParameter(&parameter))
      return false;
    extension->Add(parameter);
  }

  return true;
}

bool WebSocketExtensionParser::ConsumeExtensionParameter(
    WebSocketExtension::Parameter* parameter) {
  base::StringPiece name, value;
  std::string value_string;

  if (!ConsumeToken(&name))
    return false;

  if (!ConsumeIfMatch('=')) {
    *parameter = WebSocketExtension::Parameter(name.as_string());
    return true;
  }

  if (Lookahead('\"')) {
    if (!ConsumeQuotedToken(&value_string))
      return false;
  } else {
    if (!ConsumeToken(&value))
      return false;
    value_string = value.as_string();
  }
  *parameter = WebSocketExtension::Parameter(name.as_string(), value_string);
  return true;
}

bool WebSocketExtensionParser::ConsumeToken(base::StringPiece* token) {
  ConsumeSpaces();
  const char* head = current_;
  while (current_ < end_ && HttpUtil::IsTokenChar(*current_))
    ++current_;
  if (current_ == head)
    return false;
  *token = base::StringPiece(head, current_ - head);
  return true;
}

bool WebSocketExtensionParser::ConsumeQuotedToken(std::string* token) {
  if (!Consume('"'))
    return false;

  *token = "";
  while (current_ < end_ && *current_ != '"') {
    if (*current_ == '\\') {
      ++current_;
      if (current_ == end_)
        return false;
    }
    if (!HttpUtil::IsTokenChar(*current_))
      return false;
    *token += *current_;
    ++current_;
  }
  if (current_ == end_)
    return false;
  DCHECK_EQ(*current_, '"');

  ++current_;

  return !token->empty();
}

void WebSocketExtensionParser::ConsumeSpaces() {
  while (current_ < end_ && (*current_ == ' ' || *current_ == '\t'))
    ++current_;
  return;
}

bool WebSocketExtensionParser::Lookahead(char c) {
  const char* head = current_;
  bool result = Consume(c);
  current_ = head;
  return result;
}

bool WebSocketExtensionParser::ConsumeIfMatch(char c) {
  const char* head = current_;
  if (!Consume(c)) {
    current_ = head;
    return false;
  }

  return true;
}

}  // namespace net
