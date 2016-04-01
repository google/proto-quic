// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/properties_based_quic_server_info.h"

#include "base/base64.h"
#include "net/base/net_errors.h"
#include "net/http/http_server_properties.h"

using std::string;

namespace net {

PropertiesBasedQuicServerInfo::PropertiesBasedQuicServerInfo(
    const QuicServerId& server_id,
    base::WeakPtr<HttpServerProperties> http_server_properties)
    : QuicServerInfo(server_id),
      http_server_properties_(http_server_properties) {
  DCHECK(http_server_properties_);
}

PropertiesBasedQuicServerInfo::~PropertiesBasedQuicServerInfo() {}

void PropertiesBasedQuicServerInfo::Start() {}

int PropertiesBasedQuicServerInfo::WaitForDataReady(
    const CompletionCallback& callback) {
  const string* data = http_server_properties_->GetQuicServerInfo(server_id_);
  string decoded;
  if (!data || !base::Base64Decode(*data, &decoded) || !Parse(decoded)) {
    return ERR_FAILED;
  }
  return OK;
}

void PropertiesBasedQuicServerInfo::ResetWaitForDataReadyCallback() {}

void PropertiesBasedQuicServerInfo::CancelWaitForDataReadyCallback() {}

bool PropertiesBasedQuicServerInfo::IsDataReady() {
  return true;
}

bool PropertiesBasedQuicServerInfo::IsReadyToPersist() {
  return true;
}

void PropertiesBasedQuicServerInfo::Persist() {
  string encoded;
  base::Base64Encode(Serialize(), &encoded);
  http_server_properties_->SetQuicServerInfo(server_id_, encoded);
}

void PropertiesBasedQuicServerInfo::OnExternalCacheHit() {}

PropertiesBasedQuicServerInfoFactory::PropertiesBasedQuicServerInfoFactory(
    base::WeakPtr<HttpServerProperties> http_server_properties)
    : http_server_properties_(http_server_properties) {}

PropertiesBasedQuicServerInfoFactory::~PropertiesBasedQuicServerInfoFactory() {}

QuicServerInfo* PropertiesBasedQuicServerInfoFactory::GetForServer(
    const QuicServerId& server_id) {
  return new PropertiesBasedQuicServerInfo(server_id, http_server_properties_);
}

}  // namespace net
