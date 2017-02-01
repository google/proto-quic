// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/chromium/properties_based_quic_server_info.h"

#include "base/base64.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/histogram_macros.h"
#include "net/base/net_errors.h"
#include "net/http/http_server_properties.h"

using std::string;

namespace {

void RecordQuicServerInfoStatus(
    net::QuicServerInfo::QuicServerInfoAPICall call) {
  UMA_HISTOGRAM_ENUMERATION(
      "Net.QuicDiskCache.APICall.PropertiesBasedCache", call,
      net::QuicServerInfo::QUIC_SERVER_INFO_NUM_OF_API_CALLS);
}

void RecordQuicServerInfoFailure(net::QuicServerInfo::FailureReason failure) {
  UMA_HISTOGRAM_ENUMERATION(
      "Net.QuicDiskCache.FailureReason.PropertiesBasedCache", failure,
      net::QuicServerInfo::NUM_OF_FAILURES);
}

}  // namespace

namespace net {

PropertiesBasedQuicServerInfo::PropertiesBasedQuicServerInfo(
    const QuicServerId& server_id,
    HttpServerProperties* http_server_properties)
    : QuicServerInfo(server_id),
      http_server_properties_(http_server_properties) {
  DCHECK(http_server_properties_);
}

PropertiesBasedQuicServerInfo::~PropertiesBasedQuicServerInfo() {}

void PropertiesBasedQuicServerInfo::Start() {
  RecordQuicServerInfoStatus(QUIC_SERVER_INFO_START);
}

int PropertiesBasedQuicServerInfo::WaitForDataReady(
    const CompletionCallback& callback) {
  RecordQuicServerInfoStatus(QUIC_SERVER_INFO_WAIT_FOR_DATA_READY);
  const string* data = http_server_properties_->GetQuicServerInfo(server_id_);
  string decoded;
  if (!data) {
    RecordQuicServerInfoFailure(PARSE_NO_DATA_FAILURE);
    return ERR_FAILED;
  }
  if (!base::Base64Decode(*data, &decoded)) {
    RecordQuicServerInfoFailure(PARSE_DATA_DECODE_FAILURE);
    return ERR_FAILED;
  }
  RecordQuicServerInfoStatus(QUIC_SERVER_INFO_PARSE);
  if (!Parse(decoded)) {
    RecordQuicServerInfoFailure(PARSE_FAILURE);
    return ERR_FAILED;
  }
  return OK;
}

void PropertiesBasedQuicServerInfo::ResetWaitForDataReadyCallback() {
  RecordQuicServerInfoStatus(QUIC_SERVER_INFO_RESET_WAIT_FOR_DATA_READY);
}

void PropertiesBasedQuicServerInfo::CancelWaitForDataReadyCallback() {
  RecordQuicServerInfoStatus(QUIC_SERVER_INFO_WAIT_FOR_DATA_READY_CANCEL);
}

bool PropertiesBasedQuicServerInfo::IsDataReady() {
  return true;
}

bool PropertiesBasedQuicServerInfo::IsReadyToPersist() {
  RecordQuicServerInfoStatus(QUIC_SERVER_INFO_READY_TO_PERSIST);
  return true;
}

void PropertiesBasedQuicServerInfo::Persist() {
  RecordQuicServerInfoStatus(QUIC_SERVER_INFO_PERSIST);
  string encoded;
  base::Base64Encode(Serialize(), &encoded);
  http_server_properties_->SetQuicServerInfo(server_id_, encoded);
}

void PropertiesBasedQuicServerInfo::OnExternalCacheHit() {
  RecordQuicServerInfoStatus(QUIC_SERVER_INFO_EXTERNAL_CACHE_HIT);
}

PropertiesBasedQuicServerInfoFactory::PropertiesBasedQuicServerInfoFactory(
    HttpServerProperties* http_server_properties)
    : http_server_properties_(http_server_properties) {}

PropertiesBasedQuicServerInfoFactory::~PropertiesBasedQuicServerInfoFactory() {}

std::unique_ptr<QuicServerInfo>
PropertiesBasedQuicServerInfoFactory::GetForServer(
    const QuicServerId& server_id) {
  return base::MakeUnique<PropertiesBasedQuicServerInfo>(
      server_id, http_server_properties_);
}

}  // namespace net
