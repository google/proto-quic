// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/websockets/websocket_extension_parser.h"

#include "base/strings/string_util.h"

namespace net {

WebSocketExtensionParser::WebSocketExtensionParser() {}

WebSocketExtensionParser::~WebSocketExtensionParser() {}

bool WebSocketExtensionParser::Parse(const char* data, size_t size) {
  current_ = data;
  end_ = data + size;
  extensions_.clear();

  bool failed = false;

  while (true) {
    WebSocketExtension extension;
    if (!ConsumeExtension(&extension)) {
      failed = true;
      break;
    }
    extensions_.push_back(extension);

    ConsumeSpaces();

    if (!ConsumeIfMatch(',')) {
      break;
    }
  }

  if (!failed && current_ == end_)
    return true;

  extensions_.clear();
  return false;
}

bool WebSocketExtensionParser::Consume(char c) {
  ConsumeSpaces();
  if (current_ == end_ || c != current_[0]) {
    return false;
  }
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
  while (current_ < end_ &&
         !IsControl(current_[0]) && !IsSeparator(current_[0]))
    ++current_;
  if (current_ == head) {
    return false;
  }
  *token = base::StringPiece(head, current_ - head);
  return true;
}

bool WebSocketExtensionParser::ConsumeQuotedToken(std::string* token) {
  if (!Consume('"'))
    return false;

  *token = "";
  while (current_ < end_ && !IsControl(current_[0])) {
    if (UnconsumedBytes() >= 2 && current_[0] == '\\') {
      char next = current_[1];
      if (IsControl(next) || IsSeparator(next)) break;
      *token += next;
      current_ += 2;
    } else if (IsSeparator(current_[0])) {
      break;
    } else {
      *token += current_[0];
      ++current_;
    }
  }
  // We can't use Consume here because we don't want to consume spaces.
  if (current_ >= end_ || current_[0] != '"')
    return false;

  ++current_;

  return !token->empty();
}

void WebSocketExtensionParser::ConsumeSpaces() {
  while (current_ < end_ && (current_[0] == ' ' || current_[0] == '\t'))
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

// static
bool WebSocketExtensionParser::IsControl(char c) {
  return (0 <= c && c <= 31) || c == 127;
}

// static
bool WebSocketExtensionParser::IsSeparator(char c) {
  const char separators[] = "()<>@,;:\\\"/[]?={} \t";
  return strchr(separators, c) != NULL;
}

}  // namespace net
