// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/http/bidirectional_stream.h"

#include <memory>
#include <string>

#include "base/bind.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/histogram_macros.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/timer/timer.h"
#include "base/values.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/http/bidirectional_stream_request_info.h"
#include "net/http/http_log_util.h"
#include "net/http/http_network_session.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_stream.h"
#include "net/log/net_log_capture_mode.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source_type.h"
#include "net/spdy/spdy_header_block.h"
#include "net/spdy/spdy_http_utils.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/ssl/ssl_config.h"
#include "url/gurl.h"

namespace net {

namespace {

std::unique_ptr<base::Value> NetLogHeadersCallback(
    const SpdyHeaderBlock* headers,
    NetLogCaptureMode capture_mode) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->Set("headers", ElideSpdyHeaderBlockForNetLog(*headers, capture_mode));
  return std::move(dict);
}

std::unique_ptr<base::Value> NetLogCallback(const GURL* url,
                                            const std::string* method,
                                            const HttpRequestHeaders* headers,
                                            NetLogCaptureMode capture_mode) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetString("url", url->possibly_invalid_spec());
  dict->SetString("method", *method);
  std::string empty;
  std::unique_ptr<base::Value> headers_param(
      headers->NetLogCallback(&empty, capture_mode));
  dict->Set("headers", std::move(headers_param));
  return std::move(dict);
}

}  // namespace

BidirectionalStream::Delegate::Delegate() {}

BidirectionalStream::Delegate::~Delegate() {}

BidirectionalStream::BidirectionalStream(
    std::unique_ptr<BidirectionalStreamRequestInfo> request_info,
    HttpNetworkSession* session,
    bool send_request_headers_automatically,
    Delegate* delegate)
    : BidirectionalStream(std::move(request_info),
                          session,
                          send_request_headers_automatically,
                          delegate,
                          base::MakeUnique<base::Timer>(false, false)) {}

BidirectionalStream::BidirectionalStream(
    std::unique_ptr<BidirectionalStreamRequestInfo> request_info,
    HttpNetworkSession* session,
    bool send_request_headers_automatically,
    Delegate* delegate,
    std::unique_ptr<base::Timer> timer)
    : request_info_(std::move(request_info)),
      net_log_(NetLogWithSource::Make(session->net_log(),
                                      NetLogSourceType::BIDIRECTIONAL_STREAM)),
      session_(session),
      send_request_headers_automatically_(send_request_headers_automatically),
      request_headers_sent_(false),
      delegate_(delegate),
      timer_(std::move(timer)),
      weak_factory_(this) {
  DCHECK(delegate_);
  DCHECK(request_info_);

  if (net_log_.IsCapturing()) {
    net_log_.BeginEvent(
        NetLogEventType::BIDIRECTIONAL_STREAM_ALIVE,
        base::Bind(&NetLogCallback, &request_info_->url, &request_info_->method,
                   base::Unretained(&request_info_->extra_headers)));
  }

  SSLConfig server_ssl_config;
  session->ssl_config_service()->GetSSLConfig(&server_ssl_config);
  session->GetAlpnProtos(&server_ssl_config.alpn_protos);

  if (!request_info_->url.SchemeIs(url::kHttpsScheme)) {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::Bind(&BidirectionalStream::NotifyFailed,
                   weak_factory_.GetWeakPtr(), ERR_DISALLOWED_URL_SCHEME));
    return;
  }

  HttpRequestInfo http_request_info;
  http_request_info.url = request_info_->url;
  http_request_info.method = request_info_->method;
  http_request_info.extra_headers = request_info_->extra_headers;
  stream_request_.reset(
      session->http_stream_factory()->RequestBidirectionalStreamImpl(
          http_request_info, request_info_->priority, server_ssl_config,
          server_ssl_config, this, net_log_));
  // Check that this call cannot fail to set a non-NULL |stream_request_|.
  DCHECK(stream_request_);
  // Check that HttpStreamFactory does not invoke OnBidirectionalStreamImplReady
  // synchronously.
  DCHECK(!stream_impl_);
}

BidirectionalStream::~BidirectionalStream() {
  UpdateHistograms();
  if (net_log_.IsCapturing()) {
    net_log_.EndEvent(NetLogEventType::BIDIRECTIONAL_STREAM_ALIVE);
  }
}

void BidirectionalStream::SendRequestHeaders() {
  DCHECK(stream_impl_);
  DCHECK(!request_headers_sent_);
  DCHECK(!send_request_headers_automatically_);

  stream_impl_->SendRequestHeaders();
}

int BidirectionalStream::ReadData(IOBuffer* buf, int buf_len) {
  DCHECK(stream_impl_);

  int rv = stream_impl_->ReadData(buf, buf_len);
  if (rv > 0) {
    read_end_time_ = base::TimeTicks::Now();
    net_log_.AddByteTransferEvent(
        NetLogEventType::BIDIRECTIONAL_STREAM_BYTES_RECEIVED, rv, buf->data());
  } else if (rv == ERR_IO_PENDING) {
    read_buffer_ = buf;
    // Bytes will be logged in OnDataRead().
  }
  if (net_log_.IsCapturing()) {
    net_log_.AddEvent(NetLogEventType::BIDIRECTIONAL_STREAM_READ_DATA,
                      NetLog::IntCallback("rv", rv));
  }
  return rv;
}

void BidirectionalStream::SendData(const scoped_refptr<IOBuffer>& data,
                                   int length,
                                   bool end_stream) {
  DCHECK(stream_impl_);
  DCHECK(write_buffer_list_.empty());
  DCHECK(write_buffer_len_list_.empty());

  if (net_log_.IsCapturing()) {
    net_log_.AddEvent(NetLogEventType::BIDIRECTIONAL_STREAM_SEND_DATA);
  }
  stream_impl_->SendData(data, length, end_stream);
  write_buffer_list_.push_back(data);
  write_buffer_len_list_.push_back(length);
}

void BidirectionalStream::SendvData(
    const std::vector<scoped_refptr<IOBuffer>>& buffers,
    const std::vector<int>& lengths,
    bool end_stream) {
  DCHECK(stream_impl_);
  DCHECK_EQ(buffers.size(), lengths.size());
  DCHECK(write_buffer_list_.empty());
  DCHECK(write_buffer_len_list_.empty());

  if (net_log_.IsCapturing()) {
    net_log_.AddEvent(NetLogEventType::BIDIRECTIONAL_STREAM_SENDV_DATA,
                      NetLog::IntCallback("num_buffers", buffers.size()));
  }
  stream_impl_->SendvData(buffers, lengths, end_stream);
  for (size_t i = 0; i < buffers.size(); ++i) {
    write_buffer_list_.push_back(buffers[i]);
    write_buffer_len_list_.push_back(lengths[i]);
  }
}

NextProto BidirectionalStream::GetProtocol() const {
  if (!stream_impl_)
    return kProtoUnknown;

  return stream_impl_->GetProtocol();
}

int64_t BidirectionalStream::GetTotalReceivedBytes() const {
  if (!stream_impl_)
    return 0;

  return stream_impl_->GetTotalReceivedBytes();
}

int64_t BidirectionalStream::GetTotalSentBytes() const {
  if (!stream_impl_)
    return 0;

  return stream_impl_->GetTotalSentBytes();
}

void BidirectionalStream::OnStreamReady(bool request_headers_sent) {
  request_headers_sent_ = request_headers_sent;
  if (net_log_.IsCapturing()) {
    net_log_.AddEvent(
        NetLogEventType::BIDIRECTIONAL_STREAM_READY,
        NetLog::BoolCallback("request_headers_sent", request_headers_sent));
  }
  send_start_time_ = base::TimeTicks::Now();
  send_end_time_ = send_start_time_;
  delegate_->OnStreamReady(request_headers_sent);
}

void BidirectionalStream::OnHeadersReceived(
    const SpdyHeaderBlock& response_headers) {
  HttpResponseInfo response_info;
  if (!SpdyHeadersToHttpResponse(response_headers, &response_info)) {
    DLOG(WARNING) << "Invalid headers";
    NotifyFailed(ERR_FAILED);
    return;
  }
  if (net_log_.IsCapturing()) {
    net_log_.AddEvent(NetLogEventType::BIDIRECTIONAL_STREAM_RECV_HEADERS,
                      base::Bind(&NetLogHeadersCallback, &response_headers));
  }
  read_start_time_ = base::TimeTicks::Now();
  read_end_time_ = read_start_time_;
  session_->http_stream_factory()->ProcessAlternativeServices(
      session_, response_info.headers.get(),
      url::SchemeHostPort(request_info_->url));
  delegate_->OnHeadersReceived(response_headers);
}

void BidirectionalStream::OnDataRead(int bytes_read) {
  DCHECK(read_buffer_);

  if (net_log_.IsCapturing()) {
    net_log_.AddByteTransferEvent(
        NetLogEventType::BIDIRECTIONAL_STREAM_BYTES_RECEIVED, bytes_read,
        read_buffer_->data());
  }
  read_end_time_ = base::TimeTicks::Now();
  read_buffer_ = nullptr;
  delegate_->OnDataRead(bytes_read);
}

void BidirectionalStream::OnDataSent() {
  DCHECK(!write_buffer_list_.empty());
  DCHECK_EQ(write_buffer_list_.size(), write_buffer_len_list_.size());

  if (net_log_.IsCapturing()) {
    if (write_buffer_list_.size() > 1) {
      net_log_.BeginEvent(
          NetLogEventType::BIDIRECTIONAL_STREAM_BYTES_SENT_COALESCED,
          NetLog::IntCallback("num_buffers_coalesced",
                              write_buffer_list_.size()));
    }
    for (size_t i = 0; i < write_buffer_list_.size(); ++i) {
      net_log_.AddByteTransferEvent(
          NetLogEventType::BIDIRECTIONAL_STREAM_BYTES_SENT,
          write_buffer_len_list_[i], write_buffer_list_[i]->data());
    }
    if (write_buffer_list_.size() > 1) {
      net_log_.EndEvent(
          NetLogEventType::BIDIRECTIONAL_STREAM_BYTES_SENT_COALESCED);
    }
  }
  send_end_time_ = base::TimeTicks::Now();
  write_buffer_list_.clear();
  write_buffer_len_list_.clear();
  delegate_->OnDataSent();
}

void BidirectionalStream::OnTrailersReceived(const SpdyHeaderBlock& trailers) {
  if (net_log_.IsCapturing()) {
    net_log_.AddEvent(NetLogEventType::BIDIRECTIONAL_STREAM_RECV_TRAILERS,
                      base::Bind(&NetLogHeadersCallback, &trailers));
  }
  read_end_time_ = base::TimeTicks::Now();
  delegate_->OnTrailersReceived(trailers);
}

void BidirectionalStream::OnFailed(int status) {
  if (net_log_.IsCapturing()) {
    net_log_.AddEvent(NetLogEventType::BIDIRECTIONAL_STREAM_FAILED,
                      NetLog::IntCallback("net_error", status));
  }
  NotifyFailed(status);
}

void BidirectionalStream::OnStreamReady(const SSLConfig& used_ssl_config,
                                        const ProxyInfo& used_proxy_info,
                                        HttpStream* stream) {
  NOTREACHED();
}

void BidirectionalStream::OnBidirectionalStreamImplReady(
    const SSLConfig& used_ssl_config,
    const ProxyInfo& used_proxy_info,
    BidirectionalStreamImpl* stream) {
  DCHECK(!stream_impl_);

  start_time_ = base::TimeTicks::Now();
  stream_request_.reset();
  stream_impl_.reset(stream);
  stream_impl_->Start(request_info_.get(), net_log_,
                      send_request_headers_automatically_, this,
                      std::move(timer_));
}

void BidirectionalStream::OnWebSocketHandshakeStreamReady(
    const SSLConfig& used_ssl_config,
    const ProxyInfo& used_proxy_info,
    WebSocketHandshakeStreamBase* stream) {
  NOTREACHED();
}

void BidirectionalStream::OnStreamFailed(int result,
                                         const SSLConfig& used_ssl_config) {
  DCHECK_LT(result, 0);
  DCHECK_NE(result, ERR_IO_PENDING);
  DCHECK(stream_request_);

  NotifyFailed(result);
}

void BidirectionalStream::OnCertificateError(int result,
                                             const SSLConfig& used_ssl_config,
                                             const SSLInfo& ssl_info) {
  DCHECK_LT(result, 0);
  DCHECK_NE(result, ERR_IO_PENDING);
  DCHECK(stream_request_);

  NotifyFailed(result);
}

void BidirectionalStream::OnNeedsProxyAuth(
    const HttpResponseInfo& proxy_response,
    const SSLConfig& used_ssl_config,
    const ProxyInfo& used_proxy_info,
    HttpAuthController* auth_controller) {
  DCHECK(stream_request_);

  NotifyFailed(ERR_PROXY_AUTH_REQUESTED);
}

void BidirectionalStream::OnNeedsClientAuth(const SSLConfig& used_ssl_config,
                                            SSLCertRequestInfo* cert_info) {
  DCHECK(stream_request_);

  NotifyFailed(ERR_SSL_CLIENT_AUTH_CERT_NEEDED);
}

void BidirectionalStream::OnHttpsProxyTunnelResponse(
    const HttpResponseInfo& response_info,
    const SSLConfig& used_ssl_config,
    const ProxyInfo& used_proxy_info,
    HttpStream* stream) {
  DCHECK(stream_request_);

  NotifyFailed(ERR_HTTPS_PROXY_TUNNEL_RESPONSE);
}

void BidirectionalStream::OnQuicBroken() {}

void BidirectionalStream::NotifyFailed(int error) {
  delegate_->OnFailed(error);
}

void BidirectionalStream::UpdateHistograms() {
  // If the request failed before response is started, treat the metrics as
  // bogus and skip logging.
  if (start_time_.is_null() || read_start_time_.is_null() ||
      read_end_time_.is_null() || send_start_time_.is_null() ||
      send_end_time_.is_null()) {
    return;
  }
  if (GetProtocol() == kProtoHTTP2) {
    UMA_HISTOGRAM_TIMES("Net.BidirectionalStream.TimeToReadStart.HTTP2",
                        read_start_time_ - start_time_);
    UMA_HISTOGRAM_TIMES("Net.BidirectionalStream.TimeToReadEnd.HTTP2",
                        read_end_time_ - start_time_);
    UMA_HISTOGRAM_TIMES("Net.BidirectionalStream.TimeToSendStart.HTTP2",
                        send_start_time_ - start_time_);
    UMA_HISTOGRAM_TIMES("Net.BidirectionalStream.TimeToSendEnd.HTTP2",
                        send_end_time_ - start_time_);
    UMA_HISTOGRAM_COUNTS("Net.BidirectionalStream.ReceivedBytes.HTTP2",
                         stream_impl_->GetTotalReceivedBytes());
    UMA_HISTOGRAM_COUNTS("Net.BidirectionalStream.SentBytes.HTTP2",
                         stream_impl_->GetTotalSentBytes());
  } else if (GetProtocol() == kProtoQUIC1SPDY3) {
    UMA_HISTOGRAM_TIMES("Net.BidirectionalStream.TimeToReadStart.QUIC",
                        read_start_time_ - start_time_);
    UMA_HISTOGRAM_TIMES("Net.BidirectionalStream.TimeToReadEnd.QUIC",
                        read_end_time_ - start_time_);
    UMA_HISTOGRAM_TIMES("Net.BidirectionalStream.TimeToSendStart.QUIC",
                        send_start_time_ - start_time_);
    UMA_HISTOGRAM_TIMES("Net.BidirectionalStream.TimeToSendEnd.QUIC",
                        send_end_time_ - start_time_);
    UMA_HISTOGRAM_COUNTS("Net.BidirectionalStream.ReceivedBytes.QUIC",
                         stream_impl_->GetTotalReceivedBytes());
    UMA_HISTOGRAM_COUNTS("Net.BidirectionalStream.SentBytes.QUIC",
                         stream_impl_->GetTotalSentBytes());
  }
}

}  // namespace net
