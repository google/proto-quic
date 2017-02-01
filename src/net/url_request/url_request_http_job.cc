// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/url_request_http_job.h"

#include <vector>

#include "base/base_switches.h"
#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/command_line.h"
#include "base/compiler_specific.h"
#include "base/file_version_info.h"
#include "base/location.h"
#include "base/macros.h"
#include "base/metrics/field_trial.h"
#include "base/metrics/histogram_macros.h"
#include "base/profiler/scoped_tracker.h"
#include "base/rand_util.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_util.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/time.h"
#include "base/trace_event/trace_event.h"
#include "base/values.h"
#include "net/base/host_port_pair.h"
#include "net/base/load_flags.h"
#include "net/base/net_errors.h"
#include "net/base/network_delegate.h"
#include "net/base/registry_controlled_domains/registry_controlled_domain.h"
#include "net/base/sdch_manager.h"
#include "net/base/sdch_problem_codes.h"
#include "net/base/trace_constants.h"
#include "net/base/url_util.h"
#include "net/cert/cert_status_flags.h"
#include "net/cookies/cookie_store.h"
#include "net/filter/brotli_source_stream.h"
#include "net/filter/filter_source_stream.h"
#include "net/filter/gzip_source_stream.h"
#include "net/filter/sdch_source_stream.h"
#include "net/filter/source_stream.h"
#include "net/http/http_content_disposition.h"
#include "net/http/http_network_session.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_response_headers.h"
#include "net/http/http_response_info.h"
#include "net/http/http_status_code.h"
#include "net/http/http_transaction.h"
#include "net/http/http_transaction_factory.h"
#include "net/http/http_util.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_with_source.h"
#include "net/nqe/network_quality_estimator.h"
#include "net/proxy/proxy_info.h"
#include "net/proxy/proxy_retry_info.h"
#include "net/proxy/proxy_service.h"
#include "net/ssl/channel_id_service.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/ssl/ssl_config_service.h"
#include "net/url_request/http_user_agent_settings.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_error_job.h"
#include "net/url_request/url_request_job_factory.h"
#include "net/url_request/url_request_redirect_job.h"
#include "net/url_request/url_request_throttler_manager.h"
#include "net/websockets/websocket_handshake_stream_base.h"
#include "url/origin.h"

#if defined(OS_ANDROID)
#include "net/android/network_library.h"
#endif

static const char kAvailDictionaryHeader[] = "Avail-Dictionary";

namespace {

const char kDeflate[] = "deflate";
const char kGZip[] = "gzip";
const char kSdch[] = "sdch";
const char kXGZip[] = "x-gzip";
const char kBrotli[] = "br";

// True if the request method is "safe" (per section 4.2.1 of RFC 7231).
bool IsMethodSafe(const std::string& method) {
  return method == "GET" || method == "HEAD" || method == "OPTIONS" ||
         method == "TRACE";
}

// Logs whether the CookieStore used for this request matches the
// ChannelIDService used when establishing the connection that this request is
// sent over. This logging is only done for requests to accounts.google.com, and
// only for requests where Channel ID was sent when establishing the connection.
void LogChannelIDAndCookieStores(const GURL& url,
                                 const net::URLRequestContext* context,
                                 const net::SSLInfo& ssl_info) {
  if (url.host() != "accounts.google.com" || !ssl_info.channel_id_sent)
    return;
  // This enum is used for an UMA histogram - don't reuse or renumber entries.
  enum {
    // Value 0 was removed (CID_EPHEMERAL_COOKIE_EPHEMERAL)
    // ChannelIDStore is ephemeral, but CookieStore is persistent.
    CID_EPHEMERAL_COOKIE_PERSISTENT = 1,
    // ChannelIDStore is persistent, but CookieStore is ephemeral.
    CID_PERSISTENT_COOKIE_EPHEMERAL = 2,
    // Value 3 was removed (CID_PERSISTENT_COOKIE_PERSISTENT)
    // There is no CookieStore for this request.
    NO_COOKIE_STORE = 4,
    // There is no ChannelIDStore for this request. This should never happen,
    // because we only log if Channel ID was sent.
    NO_CHANNEL_ID_STORE = 5,
    // Value 6 was removed (KNOWN_MISMATCH).
    // Both stores are ephemeral, and the ChannelIDService used when
    // establishing the connection is the same one that the CookieStore was
    // created to be used with.
    EPHEMERAL_MATCH = 7,
    // Both stores are ephemeral, but a different CookieStore should have been
    // used on this request.
    EPHEMERAL_MISMATCH = 8,
    // Both stores are persistent, and the ChannelIDService used when
    // establishing the connection is the same one that the CookieStore was
    // created to be used with.
    PERSISTENT_MATCH = 9,
    // Both stores are persistent, but a different CookieStore should have been
    // used on this request.
    PERSISTENT_MISMATCH = 10,
    // Both stores are ephemeral, but it was never recorded in the CookieStore
    // which ChannelIDService it was created for, so it is unknown whether the
    // stores match.
    EPHEMERAL_UNKNOWN = 11,
    // Both stores are persistent, but it was never recorded in the CookieStore
    // which ChannelIDService it was created for, so it is unknown whether the
    // stores match.
    PERSISTENT_UNKNOWN = 12,
    EPHEMERALITY_MAX
  } ephemerality;
  const net::HttpNetworkSession::Params* params =
      context->GetNetworkSessionParams();
  net::CookieStore* cookie_store = context->cookie_store();
  if (params == nullptr || params->channel_id_service == nullptr) {
    ephemerality = NO_CHANNEL_ID_STORE;
  } else if (cookie_store == nullptr) {
    ephemerality = NO_COOKIE_STORE;
  } else if (params->channel_id_service->GetChannelIDStore()->IsEphemeral()) {
    if (cookie_store->IsEphemeral()) {
      if (cookie_store->GetChannelIDServiceID() == -1) {
        ephemerality = EPHEMERAL_UNKNOWN;
      } else if (cookie_store->GetChannelIDServiceID() ==
                 params->channel_id_service->GetUniqueID()) {
        ephemerality = EPHEMERAL_MATCH;
      } else {
        NOTREACHED();
        ephemerality = EPHEMERAL_MISMATCH;
      }
    } else {
      NOTREACHED();
      ephemerality = CID_EPHEMERAL_COOKIE_PERSISTENT;
    }
  } else if (cookie_store->IsEphemeral()) {
    NOTREACHED();
    ephemerality = CID_PERSISTENT_COOKIE_EPHEMERAL;
  } else if (cookie_store->GetChannelIDServiceID() == -1) {
    ephemerality = PERSISTENT_UNKNOWN;
  } else if (cookie_store->GetChannelIDServiceID() ==
             params->channel_id_service->GetUniqueID()) {
    ephemerality = PERSISTENT_MATCH;
  } else {
    NOTREACHED();
    ephemerality = PERSISTENT_MISMATCH;
  }
  UMA_HISTOGRAM_ENUMERATION("Net.TokenBinding.StoreEphemerality", ephemerality,
                            EPHEMERALITY_MAX);
}

}  // namespace

namespace net {

// TODO(darin): make sure the port blocking code is not lost
// static
URLRequestJob* URLRequestHttpJob::Factory(URLRequest* request,
                                          NetworkDelegate* network_delegate,
                                          const std::string& scheme) {
  DCHECK(scheme == "http" || scheme == "https" || scheme == "ws" ||
         scheme == "wss");

  if (!request->context()->http_transaction_factory()) {
    NOTREACHED() << "requires a valid context";
    return new URLRequestErrorJob(
        request, network_delegate, ERR_INVALID_ARGUMENT);
  }

  const GURL& url = request->url();

  // Check for reasons not to return a URLRequestHttpJob. These don't apply to
  // https and wss requests.
  if (!url.SchemeIsCryptographic()) {
    // Check for HSTS upgrade.
    TransportSecurityState* hsts =
        request->context()->transport_security_state();
    if (hsts && hsts->ShouldUpgradeToSSL(url.host())) {
      GURL::Replacements replacements;
      replacements.SetSchemeStr(
          url.SchemeIs(url::kHttpScheme) ? url::kHttpsScheme : url::kWssScheme);
      return new URLRequestRedirectJob(
          request, network_delegate, url.ReplaceComponents(replacements),
          // Use status code 307 to preserve the method, so POST requests work.
          URLRequestRedirectJob::REDIRECT_307_TEMPORARY_REDIRECT, "HSTS");
    }

#if defined(OS_ANDROID)
    // Check whether the app allows cleartext traffic to this host, and return
    // ERR_CLEARTEXT_NOT_PERMITTED if not.
    if (request->context()->check_cleartext_permitted() &&
        !android::IsCleartextPermitted(url.host())) {
      return new URLRequestErrorJob(request, network_delegate,
                                    ERR_CLEARTEXT_NOT_PERMITTED);
    }
#endif
  }

  return new URLRequestHttpJob(request,
                               network_delegate,
                               request->context()->http_user_agent_settings());
}

URLRequestHttpJob::URLRequestHttpJob(
    URLRequest* request,
    NetworkDelegate* network_delegate,
    const HttpUserAgentSettings* http_user_agent_settings)
    : URLRequestJob(request, network_delegate),
      priority_(DEFAULT_PRIORITY),
      response_info_(nullptr),
      proxy_auth_state_(AUTH_STATE_DONT_NEED_AUTH),
      server_auth_state_(AUTH_STATE_DONT_NEED_AUTH),
      read_in_progress_(false),
      throttling_entry_(nullptr),
      sdch_test_activated_(false),
      sdch_test_control_(false),
      is_cached_content_(false),
      packet_timing_enabled_(false),
      done_(false),
      bytes_observed_in_packets_(0),
      awaiting_callback_(false),
      http_user_agent_settings_(http_user_agent_settings),
      total_received_bytes_from_previous_transactions_(0),
      total_sent_bytes_from_previous_transactions_(0),
      weak_factory_(this) {
  URLRequestThrottlerManager* manager = request->context()->throttler_manager();
  if (manager)
    throttling_entry_ = manager->RegisterRequestUrl(request->url());

  ResetTimer();
}

URLRequestHttpJob::~URLRequestHttpJob() {
  CHECK(!awaiting_callback_);

  DCHECK(!sdch_test_control_ || !sdch_test_activated_);
  if (!is_cached_content_) {
    if (sdch_test_control_)
      RecordPacketStats(SdchPolicyDelegate::SDCH_EXPERIMENT_HOLDBACK);
    if (sdch_test_activated_)
      RecordPacketStats(SdchPolicyDelegate::SDCH_EXPERIMENT_DECODE);
  }
  // Make sure SdchSourceStream are told to emit histogram data while |this|
  // is still alive.
  DestroySourceStream();

  DoneWithRequest(ABORTED);
}

void URLRequestHttpJob::SetPriority(RequestPriority priority) {
  priority_ = priority;
  if (transaction_)
    transaction_->SetPriority(priority_);
}

void URLRequestHttpJob::Start() {
  // TODO(mmenke): Remove ScopedTracker below once crbug.com/456327 is fixed.
  tracked_objects::ScopedTracker tracking_profile(
      FROM_HERE_WITH_EXPLICIT_FUNCTION("456327 URLRequestHttpJob::Start"));

  DCHECK(!transaction_.get());

  // URLRequest::SetReferrer ensures that we do not send username and password
  // fields in the referrer.
  GURL referrer(request_->referrer());

  request_info_.url = request_->url();
  request_info_.method = request_->method();
  request_info_.load_flags = request_->load_flags();
  // Enable privacy mode if cookie settings or flags tell us not send or
  // save cookies.
  bool enable_privacy_mode =
      (request_info_.load_flags & LOAD_DO_NOT_SEND_COOKIES) ||
      (request_info_.load_flags & LOAD_DO_NOT_SAVE_COOKIES) ||
      CanEnablePrivacyMode();
  // Privacy mode could still be disabled in SetCookieHeaderAndStart if we are
  // going to send previously saved cookies.
  request_info_.privacy_mode = enable_privacy_mode ?
      PRIVACY_MODE_ENABLED : PRIVACY_MODE_DISABLED;

  // Strip Referer from request_info_.extra_headers to prevent, e.g., plugins
  // from overriding headers that are controlled using other means. Otherwise a
  // plugin could set a referrer although sending the referrer is inhibited.
  request_info_.extra_headers.RemoveHeader(HttpRequestHeaders::kReferer);

  // Our consumer should have made sure that this is a safe referrer. See for
  // instance WebCore::FrameLoader::HideReferrer.
  if (referrer.is_valid()) {
    request_info_.extra_headers.SetHeader(HttpRequestHeaders::kReferer,
                                          referrer.spec());
  }

  request_info_.token_binding_referrer = request_->token_binding_referrer();

  request_info_.extra_headers.SetHeaderIfMissing(
      HttpRequestHeaders::kUserAgent,
      http_user_agent_settings_ ?
          http_user_agent_settings_->GetUserAgent() : std::string());

  AddExtraHeaders();
  AddCookieHeaderAndStart();
}

void URLRequestHttpJob::Kill() {
  weak_factory_.InvalidateWeakPtrs();
  if (transaction_)
    DestroyTransaction();
  URLRequestJob::Kill();
}

void URLRequestHttpJob::GetConnectionAttempts(ConnectionAttempts* out) const {
  if (transaction_)
    transaction_->GetConnectionAttempts(out);
  else
    out->clear();
}

void URLRequestHttpJob::NotifyBeforeSendHeadersCallback(
    const ProxyInfo& proxy_info,
    HttpRequestHeaders* request_headers) {
  DCHECK(request_headers);
  DCHECK_NE(URLRequestStatus::CANCELED, GetStatus().status());
  if (network_delegate()) {
    network_delegate()->NotifyBeforeSendHeaders(
        request_, proxy_info,
        request_->context()->proxy_service()->proxy_retry_info(),
        request_headers);
  }
}

void URLRequestHttpJob::NotifyHeadersComplete() {
  DCHECK(!response_info_);

  response_info_ = transaction_->GetResponseInfo();

  // Save boolean, as we'll need this info at destruction time, and filters may
  // also need this info.
  is_cached_content_ = response_info_->was_cached;

  if (!is_cached_content_ && throttling_entry_.get())
    throttling_entry_->UpdateWithResponse(GetResponseCode());

  // The ordering of these calls is not important.
  ProcessStrictTransportSecurityHeader();
  ProcessPublicKeyPinsHeader();
  ProcessExpectCTHeader();

  // Handle the server notification of a new SDCH dictionary.
  SdchManager* sdch_manager(request()->context()->sdch_manager());
  if (sdch_manager) {
    SdchProblemCode rv = sdch_manager->IsInSupportedDomain(request()->url());
    if (rv != SDCH_OK) {
      SdchManager::LogSdchProblem(request()->net_log(), rv);
    } else {
      const std::string name = "Get-Dictionary";
      std::string url_text;
      size_t iter = 0;
      // TODO(jar): We need to not fetch dictionaries the first time they are
      // seen, but rather wait until we can justify their usefulness.
      // For now, we will only fetch the first dictionary, which will at least
      // require multiple suggestions before we get additional ones for this
      // site. Eventually we should wait until a dictionary is requested
      // several times
      // before we even download it (so that we don't waste memory or
      // bandwidth).
      if (GetResponseHeaders()->EnumerateHeader(&iter, name, &url_text)) {
        // Resolve suggested URL relative to request url.
        GURL sdch_dictionary_url = request_->url().Resolve(url_text);
        // Don't try to download Dictionary for cached responses. It's either
        // useless or too late.
        if (sdch_dictionary_url.is_valid() && !is_cached_content_) {
          rv = sdch_manager->OnGetDictionary(request_->url(),
                                             sdch_dictionary_url);
          if (rv != SDCH_OK)
            SdchManager::LogSdchProblem(request()->net_log(), rv);
        }
      }
    }
  }

  // Handle the server signalling no SDCH encoding.
  if (dictionaries_advertised_) {
    // We are wary of proxies that discard or damage SDCH encoding. If a server
    // explicitly states that this is not SDCH content, then we can correct our
    // assumption that this is an SDCH response, and avoid the need to recover
    // as though the content is corrupted (when we discover it is not SDCH
    // encoded).
    std::string sdch_response_status;
    size_t iter = 0;
    while (GetResponseHeaders()->EnumerateHeader(&iter, "X-Sdch-Encode",
                                                 &sdch_response_status)) {
      if (sdch_response_status == "0") {
        dictionaries_advertised_.reset();
        break;
      }
    }
  }

  // The HTTP transaction may be restarted several times for the purposes
  // of sending authorization information. Each time it restarts, we get
  // notified of the headers completion so that we can update the cookie store.
  if (transaction_->IsReadyToRestartForAuth()) {
    DCHECK(!response_info_->auth_challenge.get());
    // TODO(battre): This breaks the webrequest API for
    // URLRequestTestHTTP.BasicAuthWithCookies
    // where OnBeforeStartTransaction -> OnStartTransaction ->
    // OnBeforeStartTransaction occurs.
    RestartTransactionWithAuth(AuthCredentials());
    return;
  }

  URLRequestJob::NotifyHeadersComplete();
}

void URLRequestHttpJob::DestroyTransaction() {
  DCHECK(transaction_.get());

  DoneWithRequest(ABORTED);

  total_received_bytes_from_previous_transactions_ +=
      transaction_->GetTotalReceivedBytes();
  total_sent_bytes_from_previous_transactions_ +=
      transaction_->GetTotalSentBytes();
  transaction_.reset();
  response_info_ = NULL;
  receive_headers_end_ = base::TimeTicks();
}

void URLRequestHttpJob::StartTransaction() {
  // TODO(mmenke): Remove ScopedTracker below once crbug.com/456327 is fixed.
  tracked_objects::ScopedTracker tracking_profile(
      FROM_HERE_WITH_EXPLICIT_FUNCTION(
          "456327 URLRequestHttpJob::StartTransaction"));

  if (network_delegate()) {
    OnCallToDelegate();
    // The NetworkDelegate must watch for OnRequestDestroyed and not modify
    // |extra_headers| or invoke the callback after it's called. Not using a
    // WeakPtr here because it's not enough, the consumer has to watch for
    // destruction regardless, due to the headers parameter.
    int rv = network_delegate()->NotifyBeforeStartTransaction(
        request_,
        base::Bind(&URLRequestHttpJob::NotifyBeforeStartTransactionCallback,
                   base::Unretained(this)),
        &request_info_.extra_headers);
    // If an extension blocks the request, we rely on the callback to
    // MaybeStartTransactionInternal().
    if (rv == ERR_IO_PENDING)
      return;
    MaybeStartTransactionInternal(rv);
    return;
  }
  StartTransactionInternal();
}

void URLRequestHttpJob::NotifyBeforeStartTransactionCallback(int result) {
  // Check that there are no callbacks to already canceled requests.
  DCHECK_NE(URLRequestStatus::CANCELED, GetStatus().status());

  MaybeStartTransactionInternal(result);
}

void URLRequestHttpJob::MaybeStartTransactionInternal(int result) {
  // TODO(mmenke): Remove ScopedTracker below once crbug.com/456327 is fixed.
  tracked_objects::ScopedTracker tracking_profile(
      FROM_HERE_WITH_EXPLICIT_FUNCTION(
          "456327 URLRequestHttpJob::MaybeStartTransactionInternal"));

  OnCallToDelegateComplete();
  if (result == OK) {
    StartTransactionInternal();
  } else {
    std::string source("delegate");
    request_->net_log().AddEvent(NetLogEventType::CANCELLED,
                                 NetLog::StringCallback("source", &source));
    // Don't call back synchronously to the delegate.
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::Bind(&URLRequestHttpJob::NotifyStartError,
                   weak_factory_.GetWeakPtr(),
                   URLRequestStatus(URLRequestStatus::FAILED, result)));
  }
}

void URLRequestHttpJob::StartTransactionInternal() {
  // This should only be called while the request's status is IO_PENDING.
  DCHECK_EQ(URLRequestStatus::IO_PENDING, request_->status().status());

  // NOTE: This method assumes that request_info_ is already setup properly.

  // If we already have a transaction, then we should restart the transaction
  // with auth provided by auth_credentials_.

  int rv;

  // Notify NetworkQualityEstimator.
  NetworkQualityEstimator* network_quality_estimator =
      request()->context()->network_quality_estimator();
  if (network_quality_estimator)
    network_quality_estimator->NotifyStartTransaction(*request_);

  if (network_delegate()) {
    network_delegate()->NotifyStartTransaction(request_,
                                               request_info_.extra_headers);
  }

  if (transaction_.get()) {
    rv = transaction_->RestartWithAuth(
        auth_credentials_, base::Bind(&URLRequestHttpJob::OnStartCompleted,
                                      base::Unretained(this)));
    auth_credentials_ = AuthCredentials();
  } else {
    DCHECK(request_->context()->http_transaction_factory());

    rv = request_->context()->http_transaction_factory()->CreateTransaction(
        priority_, &transaction_);

    if (rv == OK && request_info_.url.SchemeIsWSOrWSS()) {
      base::SupportsUserData::Data* data = request_->GetUserData(
          WebSocketHandshakeStreamBase::CreateHelper::DataKey());
      if (data) {
        transaction_->SetWebSocketHandshakeStreamCreateHelper(
            static_cast<WebSocketHandshakeStreamBase::CreateHelper*>(data));
      } else {
        rv = ERR_DISALLOWED_URL_SCHEME;
      }
    }

    if (rv == OK) {
      transaction_->SetBeforeHeadersSentCallback(
          base::Bind(&URLRequestHttpJob::NotifyBeforeSendHeadersCallback,
                     base::Unretained(this)));

      if (!throttling_entry_.get() ||
          !throttling_entry_->ShouldRejectRequest(*request_)) {
        rv = transaction_->Start(
            &request_info_, base::Bind(&URLRequestHttpJob::OnStartCompleted,
                                       base::Unretained(this)),
            request_->net_log());
        start_time_ = base::TimeTicks::Now();
      } else {
        // Special error code for the exponential back-off module.
        rv = ERR_TEMPORARILY_THROTTLED;
      }
    }
  }

  if (rv == ERR_IO_PENDING)
    return;

  // The transaction started synchronously, but we need to notify the
  // URLRequest delegate via the message loop.
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::Bind(&URLRequestHttpJob::OnStartCompleted,
                            weak_factory_.GetWeakPtr(), rv));
}

void URLRequestHttpJob::AddExtraHeaders() {
  SdchManager* sdch_manager = request()->context()->sdch_manager();

  // Supply Accept-Encoding field only if it is not already provided.
  // It should be provided IF the content is known to have restrictions on
  // potential encoding, such as streaming multi-media.
  // For details see bug 47381.
  // TODO(jar, enal): jpeg files etc. should set up a request header if
  // possible. Right now it is done only by buffered_resource_loader and
  // simple_data_source.
  if (!request_info_.extra_headers.HasHeader(
      HttpRequestHeaders::kAcceptEncoding)) {
    // We don't support SDCH responses to POST as there is a possibility
    // of having SDCH encoded responses returned (e.g. by the cache)
    // which we cannot decode, and in those situations, we will need
    // to retransmit the request without SDCH, which is illegal for a POST.
    bool advertise_sdch = sdch_manager != NULL && request()->method() != "POST";
    if (advertise_sdch) {
      SdchProblemCode rv = sdch_manager->IsInSupportedDomain(request()->url());
      if (rv != SDCH_OK) {
        advertise_sdch = false;
        SdchManager::LogSdchProblem(request()->net_log(), rv);
      }
    }
    if (advertise_sdch) {
      dictionaries_advertised_ =
          sdch_manager->GetDictionarySet(request_->url());
    }

    // The AllowLatencyExperiment() is only true if we've successfully done a
    // full SDCH compression recently in this browser session for this host.
    // Note that for this path, there might be no applicable dictionaries,
    // and hence we can't participate in the experiment.
    if (dictionaries_advertised_ &&
        sdch_manager->AllowLatencyExperiment(request_->url())) {
      // We are participating in the test (or control), and hence we'll
      // eventually record statistics via either SDCH_EXPERIMENT_DECODE or
      // SDCH_EXPERIMENT_HOLDBACK, and we'll need some packet timing data.
      packet_timing_enabled_ = true;
      if (base::RandDouble() < .01) {
        sdch_test_control_ = true;  // 1% probability.
        dictionaries_advertised_.reset();
        advertise_sdch = false;
      } else {
        sdch_test_activated_ = true;
      }
    }

    // Advertise "br" encoding only if transferred data is opaque to proxy.
    bool advertise_brotli = false;
    if (request()->context()->enable_brotli()) {
      if (request()->url().SchemeIsCryptographic() ||
          IsLocalhost(request()->url().HostNoBrackets())) {
        advertise_brotli = true;
      }
    }

    // Supply Accept-Encoding headers first so that it is more likely that they
    // will be in the first transmitted packet. This can sometimes make it
    // easier to filter and analyze the streams to assure that a proxy has not
    // damaged these headers. Some proxies deliberately corrupt Accept-Encoding
    // headers.
    std::string advertised_encodings = "gzip, deflate";
    if (advertise_sdch)
      advertised_encodings += ", sdch";
    if (advertise_brotli)
      advertised_encodings += ", br";
    // Tell the server what compression formats are supported.
    request_info_.extra_headers.SetHeader(HttpRequestHeaders::kAcceptEncoding,
                                          advertised_encodings);

    if (dictionaries_advertised_) {
      request_info_.extra_headers.SetHeader(
          kAvailDictionaryHeader,
          dictionaries_advertised_->GetDictionaryClientHashList());
      // Since we're tagging this transaction as advertising a dictionary,
      // we'll definitely employ an SDCH filter (or tentative sdch filter)
      // when we get a response. When done, we'll record histograms via
      // SDCH_DECODE or SDCH_PASSTHROUGH. Hence we need to record packet
      // arrival times.
      packet_timing_enabled_ = true;
    }
  }

  if (http_user_agent_settings_) {
    // Only add default Accept-Language if the request didn't have it
    // specified.
    std::string accept_language =
        http_user_agent_settings_->GetAcceptLanguage();
    if (!accept_language.empty()) {
      request_info_.extra_headers.SetHeaderIfMissing(
          HttpRequestHeaders::kAcceptLanguage,
          accept_language);
    }
  }
}

void URLRequestHttpJob::AddCookieHeaderAndStart() {
  CookieStore* cookie_store = request_->context()->cookie_store();
  if (cookie_store && !(request_info_.load_flags & LOAD_DO_NOT_SEND_COOKIES)) {
    CookieOptions options;
    options.set_include_httponly();

    // Set SameSiteCookieMode according to the rules laid out in
    // https://tools.ietf.org/html/draft-west-first-party-cookies:
    //
    // * Include both "strict" and "lax" same-site cookies if the request's
    //   |url|, |initiator|, and |first_party_for_cookies| all have the same
    //   registrable domain. Note: this also covers the case of a request
    //   without an initiator (only happens for browser-initiated main frame
    //   navigations).
    //
    // * Include only "lax" same-site cookies if the request's |URL| and
    //   |first_party_for_cookies| have the same registrable domain, _and_ the
    //   request's |method| is "safe" ("GET" or "HEAD").
    //
    //   Note that this will generally be the case only for cross-site requests
    //   which target a top-level browsing context.
    //
    // * Otherwise, do not include same-site cookies.
    if (registry_controlled_domains::SameDomainOrHost(
            request_->url(), request_->first_party_for_cookies(),
            registry_controlled_domains::INCLUDE_PRIVATE_REGISTRIES)) {
      if (!request_->initiator() ||
          registry_controlled_domains::SameDomainOrHost(
              request_->url(), request_->initiator().value().GetURL(),
              registry_controlled_domains::INCLUDE_PRIVATE_REGISTRIES)) {
        options.set_same_site_cookie_mode(
            CookieOptions::SameSiteCookieMode::INCLUDE_STRICT_AND_LAX);
      } else if (IsMethodSafe(request_->method())) {
        options.set_same_site_cookie_mode(
            CookieOptions::SameSiteCookieMode::INCLUDE_LAX);
      }
    }

    cookie_store->GetCookieListWithOptionsAsync(
        request_->url(), options,
        base::Bind(&URLRequestHttpJob::SetCookieHeaderAndStart,
                   weak_factory_.GetWeakPtr()));
  } else {
    StartTransaction();
  }
}

void URLRequestHttpJob::SetCookieHeaderAndStart(const CookieList& cookie_list) {
  if (!cookie_list.empty() && CanGetCookies(cookie_list)) {
    request_info_.extra_headers.SetHeader(
        HttpRequestHeaders::kCookie, CookieStore::BuildCookieLine(cookie_list));
    // Disable privacy mode as we are sending cookies anyway.
    request_info_.privacy_mode = PRIVACY_MODE_DISABLED;
  }
  StartTransaction();
}

void URLRequestHttpJob::SaveCookiesAndNotifyHeadersComplete(int result) {
  // End of the call started in OnStartCompleted.
  OnCallToDelegateComplete();

  if (result != OK) {
    std::string source("delegate");
    request_->net_log().AddEvent(NetLogEventType::CANCELLED,
                                 NetLog::StringCallback("source", &source));
    NotifyStartError(URLRequestStatus(URLRequestStatus::FAILED, result));
    return;
  }

  base::Time response_date;
  if (!GetResponseHeaders()->GetDateValue(&response_date))
    response_date = base::Time();

  if (!(request_info_.load_flags & LOAD_DO_NOT_SAVE_COOKIES) &&
      request_->context()->cookie_store()) {
    CookieOptions options;
    options.set_include_httponly();
    options.set_server_time(response_date);

    // Set all cookies, without waiting for them to be set. Any subsequent read
    // will see the combined result of all cookie operation.
    const base::StringPiece name("Set-Cookie");
    std::string cookie;
    size_t iter = 0;
    HttpResponseHeaders* headers = GetResponseHeaders();
    while (headers->EnumerateHeader(&iter, name, &cookie)) {
      if (cookie.empty() || !CanSetCookie(cookie, &options))
        continue;
      request_->context()->cookie_store()->SetCookieWithOptionsAsync(
          request_->url(), cookie, options, CookieStore::SetCookiesCallback());
    }
  }

  NotifyHeadersComplete();
}

// NOTE: |ProcessStrictTransportSecurityHeader| and
// |ProcessPublicKeyPinsHeader| have very similar structures, by design.
void URLRequestHttpJob::ProcessStrictTransportSecurityHeader() {
  DCHECK(response_info_);
  TransportSecurityState* security_state =
      request_->context()->transport_security_state();
  const SSLInfo& ssl_info = response_info_->ssl_info;

  // Only accept HSTS headers on HTTPS connections that have no
  // certificate errors.
  if (!ssl_info.is_valid() || IsCertStatusError(ssl_info.cert_status) ||
      !security_state) {
    return;
  }

  // Don't accept HSTS headers when the hostname is an IP address.
  if (request_info_.url.HostIsIPAddress())
    return;

  // http://tools.ietf.org/html/draft-ietf-websec-strict-transport-sec:
  //
  //   If a UA receives more than one STS header field in a HTTP response
  //   message over secure transport, then the UA MUST process only the
  //   first such header field.
  HttpResponseHeaders* headers = GetResponseHeaders();
  std::string value;
  if (headers->EnumerateHeader(nullptr, "Strict-Transport-Security", &value))
    security_state->AddHSTSHeader(request_info_.url.host(), value);
}

void URLRequestHttpJob::ProcessPublicKeyPinsHeader() {
  DCHECK(response_info_);
  TransportSecurityState* security_state =
      request_->context()->transport_security_state();
  const SSLInfo& ssl_info = response_info_->ssl_info;

  // Only accept HPKP headers on HTTPS connections that have no
  // certificate errors.
  if (!ssl_info.is_valid() || IsCertStatusError(ssl_info.cert_status) ||
      !security_state) {
    return;
  }

  // Don't accept HSTS headers when the hostname is an IP address.
  if (request_info_.url.HostIsIPAddress())
    return;

  // http://tools.ietf.org/html/rfc7469:
  //
  //   If a UA receives more than one PKP header field in an HTTP
  //   response message over secure transport, then the UA MUST process
  //   only the first such header field.
  HttpResponseHeaders* headers = GetResponseHeaders();
  std::string value;
  if (headers->EnumerateHeader(nullptr, "Public-Key-Pins", &value))
    security_state->AddHPKPHeader(request_info_.url.host(), value, ssl_info);
  if (headers->EnumerateHeader(nullptr, "Public-Key-Pins-Report-Only",
                               &value)) {
    security_state->ProcessHPKPReportOnlyHeader(
        value, HostPortPair::FromURL(request_info_.url), ssl_info);
  }
}

void URLRequestHttpJob::ProcessExpectCTHeader() {
  DCHECK(response_info_);
  TransportSecurityState* security_state =
      request_->context()->transport_security_state();
  const SSLInfo& ssl_info = response_info_->ssl_info;

  // Only accept Expect CT headers on HTTPS connections that have no
  // certificate errors.
  if (!ssl_info.is_valid() || IsCertStatusError(ssl_info.cert_status) ||
      !security_state) {
    return;
  }

  // Only process the first Expect-CT header value.
  HttpResponseHeaders* headers = GetResponseHeaders();
  std::string value;
  if (headers->EnumerateHeader(nullptr, "Expect-CT", &value)) {
    security_state->ProcessExpectCTHeader(
        value, HostPortPair::FromURL(request_info_.url), ssl_info);
  }
}

void URLRequestHttpJob::OnStartCompleted(int result) {
  TRACE_EVENT0(kNetTracingCategory, "URLRequestHttpJob::OnStartCompleted");
  RecordTimer();

  // If the job is done (due to cancellation), can just ignore this
  // notification.
  if (done_)
    return;

  receive_headers_end_ = base::TimeTicks::Now();

  const URLRequestContext* context = request_->context();

  if (result == OK) {
    if (transaction_ && transaction_->GetResponseInfo()) {
      SetProxyServer(transaction_->GetResponseInfo()->proxy_server);
    }
    scoped_refptr<HttpResponseHeaders> headers = GetResponseHeaders();

    if (network_delegate()) {
      // Note that |this| may not be deleted until
      // |URLRequestHttpJob::OnHeadersReceivedCallback()| or
      // |NetworkDelegate::URLRequestDestroyed()| has been called.
      OnCallToDelegate();
      allowed_unsafe_redirect_url_ = GURL();
      // The NetworkDelegate must watch for OnRequestDestroyed and not modify
      // any of the arguments or invoke the callback after it's called. Not
      // using a WeakPtr here because it's not enough, the consumer has to watch
      // for destruction regardless, due to the pointer parameters.
      int error = network_delegate()->NotifyHeadersReceived(
          request_, base::Bind(&URLRequestHttpJob::OnHeadersReceivedCallback,
                               base::Unretained(this)),
          headers.get(), &override_response_headers_,
          &allowed_unsafe_redirect_url_);
      if (error != OK) {
        if (error == ERR_IO_PENDING) {
          awaiting_callback_ = true;
        } else {
          std::string source("delegate");
          request_->net_log().AddEvent(
              NetLogEventType::CANCELLED,
              NetLog::StringCallback("source", &source));
          OnCallToDelegateComplete();
          NotifyStartError(URLRequestStatus(URLRequestStatus::FAILED, error));
        }
        return;
      }
    }
    if (transaction_ && transaction_->GetResponseInfo()) {
      LogChannelIDAndCookieStores(request_->url(), request_->context(),
                                  transaction_->GetResponseInfo()->ssl_info);
    }

    SaveCookiesAndNotifyHeadersComplete(OK);
  } else if (IsCertificateError(result)) {
    // We encountered an SSL certificate error.
    // Maybe overridable, maybe not. Ask the delegate to decide.
    TransportSecurityState* state = context->transport_security_state();
    NotifySSLCertificateError(
        transaction_->GetResponseInfo()->ssl_info,
        state->ShouldSSLErrorsBeFatal(request_info_.url.host()));
  } else if (result == ERR_SSL_CLIENT_AUTH_CERT_NEEDED) {
    NotifyCertificateRequested(
        transaction_->GetResponseInfo()->cert_request_info.get());
  } else {
    // Even on an error, there may be useful information in the response
    // info (e.g. whether there's a cached copy).
    if (transaction_.get())
      response_info_ = transaction_->GetResponseInfo();
    NotifyStartError(URLRequestStatus(URLRequestStatus::FAILED, result));
  }
}

void URLRequestHttpJob::OnHeadersReceivedCallback(int result) {
  awaiting_callback_ = false;

  // Check that there are no callbacks to already canceled requests.
  DCHECK_NE(URLRequestStatus::CANCELED, GetStatus().status());

  SaveCookiesAndNotifyHeadersComplete(result);
}

void URLRequestHttpJob::OnReadCompleted(int result) {
  TRACE_EVENT0(kNetTracingCategory, "URLRequestHttpJob::OnReadCompleted");
  read_in_progress_ = false;

  DCHECK_NE(ERR_IO_PENDING, result);

  if (ShouldFixMismatchedContentLength(result))
    result = OK;

  // EOF or error, done with this job.
  if (result <= 0)
    DoneWithRequest(FINISHED);

  ReadRawDataComplete(result);
}

void URLRequestHttpJob::RestartTransactionWithAuth(
    const AuthCredentials& credentials) {
  auth_credentials_ = credentials;

  // These will be reset in OnStartCompleted.
  response_info_ = NULL;
  receive_headers_end_ = base::TimeTicks();

  ResetTimer();

  // Update the cookies, since the cookie store may have been updated from the
  // headers in the 401/407. Since cookies were already appended to
  // extra_headers, we need to strip them out before adding them again.
  request_info_.extra_headers.RemoveHeader(HttpRequestHeaders::kCookie);

  AddCookieHeaderAndStart();
}

void URLRequestHttpJob::SetUpload(UploadDataStream* upload) {
  DCHECK(!transaction_.get()) << "cannot change once started";
  request_info_.upload_data_stream = upload;
}

void URLRequestHttpJob::SetExtraRequestHeaders(
    const HttpRequestHeaders& headers) {
  DCHECK(!transaction_.get()) << "cannot change once started";
  request_info_.extra_headers.CopyFrom(headers);
}

LoadState URLRequestHttpJob::GetLoadState() const {
  return transaction_.get() ?
      transaction_->GetLoadState() : LOAD_STATE_IDLE;
}

bool URLRequestHttpJob::GetMimeType(std::string* mime_type) const {
  DCHECK(transaction_.get());

  if (!response_info_)
    return false;

  HttpResponseHeaders* headers = GetResponseHeaders();
  if (!headers)
    return false;
  return headers->GetMimeType(mime_type);
}

bool URLRequestHttpJob::GetCharset(std::string* charset) {
  DCHECK(transaction_.get());

  if (!response_info_)
    return false;

  return GetResponseHeaders()->GetCharset(charset);
}

void URLRequestHttpJob::GetResponseInfo(HttpResponseInfo* info) {
  if (response_info_) {
    DCHECK(transaction_.get());

    *info = *response_info_;
    if (override_response_headers_.get())
      info->headers = override_response_headers_;
  }
}

void URLRequestHttpJob::GetLoadTimingInfo(
    LoadTimingInfo* load_timing_info) const {
  // If haven't made it far enough to receive any headers, don't return
  // anything. This makes for more consistent behavior in the case of errors.
  if (!transaction_ || receive_headers_end_.is_null())
    return;
  if (transaction_->GetLoadTimingInfo(load_timing_info))
    load_timing_info->receive_headers_end = receive_headers_end_;
}

bool URLRequestHttpJob::GetRemoteEndpoint(IPEndPoint* endpoint) const {
  if (!transaction_)
    return false;

  return transaction_->GetRemoteEndpoint(endpoint);
}

int URLRequestHttpJob::GetResponseCode() const {
  DCHECK(transaction_.get());

  if (!response_info_)
    return -1;

  return GetResponseHeaders()->response_code();
}

void URLRequestHttpJob::PopulateNetErrorDetails(
    NetErrorDetails* details) const {
  if (!transaction_)
    return;
  return transaction_->PopulateNetErrorDetails(details);
}

std::unique_ptr<SourceStream> URLRequestHttpJob::SetUpSourceStream() {
  DCHECK(transaction_.get());
  if (!response_info_)
    return nullptr;

  std::unique_ptr<SourceStream> upstream = URLRequestJob::SetUpSourceStream();
  HttpResponseHeaders* headers = GetResponseHeaders();
  std::string type;
  std::vector<SourceStream::SourceType> types;
  size_t iter = 0;
  while (headers->EnumerateHeader(&iter, "Content-Encoding", &type)) {
    if (base::LowerCaseEqualsASCII(type, kBrotli)) {
      types.push_back(SourceStream::TYPE_BROTLI);
    } else if (base::LowerCaseEqualsASCII(type, kDeflate)) {
      types.push_back(SourceStream::TYPE_DEFLATE);
    } else if (base::LowerCaseEqualsASCII(type, kGZip) ||
               base::LowerCaseEqualsASCII(type, kXGZip)) {
      types.push_back(SourceStream::TYPE_GZIP);
    } else if (base::LowerCaseEqualsASCII(type, kSdch)) {
      // If SDCH support is not configured, pass through raw response.
      if (!request()->context()->sdch_manager())
        return upstream;
      types.push_back(SourceStream::TYPE_SDCH);
    } else {
      // Unknown encoding type. Pass through raw response body.
      return upstream;
    }
  }

  // Sdch specific hacks:
  std::string mime_type;
  bool success = GetMimeType(&mime_type);
  DCHECK(success || mime_type.empty());
  SdchPolicyDelegate::FixUpSdchContentEncodings(
      request()->net_log(), mime_type, dictionaries_advertised_.get(), &types);

  for (std::vector<SourceStream::SourceType>::reverse_iterator r_iter =
           types.rbegin();
       r_iter != types.rend(); ++r_iter) {
    std::unique_ptr<FilterSourceStream> downstream;
    SourceStream::SourceType type = *r_iter;
    switch (type) {
      case SourceStream::TYPE_BROTLI:
        downstream = CreateBrotliSourceStream(std::move(upstream));
        break;
      case SourceStream::TYPE_SDCH:
      case SourceStream::TYPE_SDCH_POSSIBLE: {
        if (request()->context()->sdch_manager()) {
          GURL url = request()->url();
          std::unique_ptr<SdchPolicyDelegate> delegate(new SdchPolicyDelegate(
              type == SourceStream::TYPE_SDCH_POSSIBLE, this, mime_type, url,
              is_cached_content_, request()->context()->sdch_manager(),
              std::move(dictionaries_advertised_), GetResponseCode(),
              request()->net_log()));
          downstream.reset(new SdchSourceStream(std::move(upstream),
                                                std::move(delegate), type));
        }
        break;
      }
      case SourceStream::TYPE_GZIP:
      case SourceStream::TYPE_DEFLATE:
      case SourceStream::TYPE_GZIP_FALLBACK:
        downstream = GzipSourceStream::Create(std::move(upstream), type);
        break;
      case SourceStream::TYPE_NONE:
      case SourceStream::TYPE_INVALID:
      case SourceStream::TYPE_MAX:
        NOTREACHED();
        return nullptr;
    }
    if (downstream == nullptr)
      return nullptr;
    upstream = std::move(downstream);
  }

  return upstream;
}

bool URLRequestHttpJob::CopyFragmentOnRedirect(const GURL& location) const {
  // Allow modification of reference fragments by default, unless
  // |allowed_unsafe_redirect_url_| is set and equal to the redirect URL.
  // When this is the case, we assume that the network delegate has set the
  // desired redirect URL (with or without fragment), so it must not be changed
  // any more.
  return !allowed_unsafe_redirect_url_.is_valid() ||
       allowed_unsafe_redirect_url_ != location;
}

bool URLRequestHttpJob::IsSafeRedirect(const GURL& location) {
  // HTTP is always safe.
  // TODO(pauljensen): Remove once crbug.com/146591 is fixed.
  if (location.is_valid() &&
      (location.scheme() == "http" || location.scheme() == "https")) {
    return true;
  }
  // Delegates may mark a URL as safe for redirection.
  if (allowed_unsafe_redirect_url_.is_valid() &&
      allowed_unsafe_redirect_url_ == location) {
    return true;
  }
  // Query URLRequestJobFactory as to whether |location| would be safe to
  // redirect to.
  return request_->context()->job_factory() &&
      request_->context()->job_factory()->IsSafeRedirectTarget(location);
}

bool URLRequestHttpJob::NeedsAuth() {
  int code = GetResponseCode();
  if (code == -1)
    return false;

  // Check if we need either Proxy or WWW Authentication. This could happen
  // because we either provided no auth info, or provided incorrect info.
  switch (code) {
    case 407:
      if (proxy_auth_state_ == AUTH_STATE_CANCELED)
        return false;
      proxy_auth_state_ = AUTH_STATE_NEED_AUTH;
      return true;
    case 401:
      if (server_auth_state_ == AUTH_STATE_CANCELED)
        return false;
      server_auth_state_ = AUTH_STATE_NEED_AUTH;
      return true;
  }
  return false;
}

void URLRequestHttpJob::GetAuthChallengeInfo(
    scoped_refptr<AuthChallengeInfo>* result) {
  DCHECK(transaction_.get());
  DCHECK(response_info_);

  // sanity checks:
  DCHECK(proxy_auth_state_ == AUTH_STATE_NEED_AUTH ||
         server_auth_state_ == AUTH_STATE_NEED_AUTH);
  DCHECK((GetResponseHeaders()->response_code() == HTTP_UNAUTHORIZED) ||
         (GetResponseHeaders()->response_code() ==
          HTTP_PROXY_AUTHENTICATION_REQUIRED));

  *result = response_info_->auth_challenge;
}

void URLRequestHttpJob::SetAuth(const AuthCredentials& credentials) {
  DCHECK(transaction_.get());

  // Proxy gets set first, then WWW.
  if (proxy_auth_state_ == AUTH_STATE_NEED_AUTH) {
    proxy_auth_state_ = AUTH_STATE_HAVE_AUTH;
  } else {
    DCHECK_EQ(server_auth_state_, AUTH_STATE_NEED_AUTH);
    server_auth_state_ = AUTH_STATE_HAVE_AUTH;
  }

  RestartTransactionWithAuth(credentials);
}

void URLRequestHttpJob::CancelAuth() {
  // Proxy gets set first, then WWW.
  if (proxy_auth_state_ == AUTH_STATE_NEED_AUTH) {
    proxy_auth_state_ = AUTH_STATE_CANCELED;
  } else {
    DCHECK_EQ(server_auth_state_, AUTH_STATE_NEED_AUTH);
    server_auth_state_ = AUTH_STATE_CANCELED;
  }

  // These will be reset in OnStartCompleted.
  response_info_ = NULL;
  receive_headers_end_ = base::TimeTicks::Now();

  ResetTimer();

  // OK, let the consumer read the error page...
  //
  // Because we set the AUTH_STATE_CANCELED flag, NeedsAuth will return false,
  // which will cause the consumer to receive OnResponseStarted instead of
  // OnAuthRequired.
  //
  // We have to do this via InvokeLater to avoid "recursing" the consumer.
  //
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::Bind(&URLRequestHttpJob::OnStartCompleted,
                            weak_factory_.GetWeakPtr(), OK));
}

void URLRequestHttpJob::ContinueWithCertificate(
    X509Certificate* client_cert,
    SSLPrivateKey* client_private_key) {
  DCHECK(transaction_.get());

  DCHECK(!response_info_) << "should not have a response yet";
  receive_headers_end_ = base::TimeTicks();

  ResetTimer();

  int rv = transaction_->RestartWithCertificate(
      client_cert, client_private_key,
      base::Bind(&URLRequestHttpJob::OnStartCompleted, base::Unretained(this)));
  if (rv == ERR_IO_PENDING)
    return;

  // The transaction started synchronously, but we need to notify the
  // URLRequest delegate via the message loop.
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::Bind(&URLRequestHttpJob::OnStartCompleted,
                            weak_factory_.GetWeakPtr(), rv));
}

void URLRequestHttpJob::ContinueDespiteLastError() {
  // If the transaction was destroyed, then the job was cancelled.
  if (!transaction_.get())
    return;

  DCHECK(!response_info_) << "should not have a response yet";
  receive_headers_end_ = base::TimeTicks();

  ResetTimer();

  int rv = transaction_->RestartIgnoringLastError(
      base::Bind(&URLRequestHttpJob::OnStartCompleted, base::Unretained(this)));
  if (rv == ERR_IO_PENDING)
    return;

  // The transaction started synchronously, but we need to notify the
  // URLRequest delegate via the message loop.
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::Bind(&URLRequestHttpJob::OnStartCompleted,
                            weak_factory_.GetWeakPtr(), rv));
}

bool URLRequestHttpJob::ShouldFixMismatchedContentLength(int rv) const {
  // Some servers send the body compressed, but specify the content length as
  // the uncompressed size. Although this violates the HTTP spec we want to
  // support it (as IE and FireFox do), but *only* for an exact match.
  // See http://crbug.com/79694.
  if (rv == ERR_CONTENT_LENGTH_MISMATCH ||
      rv == ERR_INCOMPLETE_CHUNKED_ENCODING) {
    if (request_->response_headers()) {
      int64_t expected_length =
          request_->response_headers()->GetContentLength();
      VLOG(1) << __func__ << "() \"" << request_->url().spec() << "\""
              << " content-length = " << expected_length
              << " pre total = " << prefilter_bytes_read()
              << " post total = " << postfilter_bytes_read();
      if (postfilter_bytes_read() == expected_length) {
        // Clear the error.
        return true;
      }
    }
  }
  return false;
}

int URLRequestHttpJob::ReadRawData(IOBuffer* buf, int buf_size) {
  DCHECK_NE(buf_size, 0);
  DCHECK(!read_in_progress_);

  int rv = transaction_->Read(
      buf, buf_size,
      base::Bind(&URLRequestHttpJob::OnReadCompleted, base::Unretained(this)));

  if (ShouldFixMismatchedContentLength(rv))
    rv = OK;

  if (rv == 0 || (rv < 0 && rv != ERR_IO_PENDING))
    DoneWithRequest(FINISHED);

  if (rv == ERR_IO_PENDING)
    read_in_progress_ = true;

  return rv;
}

void URLRequestHttpJob::StopCaching() {
  if (transaction_.get())
    transaction_->StopCaching();
}

bool URLRequestHttpJob::GetFullRequestHeaders(
    HttpRequestHeaders* headers) const {
  if (!transaction_)
    return false;

  return transaction_->GetFullRequestHeaders(headers);
}

int64_t URLRequestHttpJob::GetTotalReceivedBytes() const {
  int64_t total_received_bytes =
      total_received_bytes_from_previous_transactions_;
  if (transaction_)
    total_received_bytes += transaction_->GetTotalReceivedBytes();
  return total_received_bytes;
}

int64_t URLRequestHttpJob::GetTotalSentBytes() const {
  int64_t total_sent_bytes = total_sent_bytes_from_previous_transactions_;
  if (transaction_)
    total_sent_bytes += transaction_->GetTotalSentBytes();
  return total_sent_bytes;
}

void URLRequestHttpJob::DoneReading() {
  if (transaction_) {
    transaction_->DoneReading();
  }
  DoneWithRequest(FINISHED);
}

void URLRequestHttpJob::DoneReadingRedirectResponse() {
  if (transaction_) {
    if (transaction_->GetResponseInfo()->headers->IsRedirect(NULL)) {
      // If the original headers indicate a redirect, go ahead and cache the
      // response, even if the |override_response_headers_| are a redirect to
      // another location.
      transaction_->DoneReading();
    } else {
      // Otherwise, |override_response_headers_| must be non-NULL and contain
      // bogus headers indicating a redirect.
      DCHECK(override_response_headers_.get());
      DCHECK(override_response_headers_->IsRedirect(NULL));
      transaction_->StopCaching();
    }
  }
  DoneWithRequest(FINISHED);
}

HostPortPair URLRequestHttpJob::GetSocketAddress() const {
  return response_info_ ? response_info_->socket_address : HostPortPair();
}

void URLRequestHttpJob::RecordTimer() {
  if (request_creation_time_.is_null()) {
    NOTREACHED()
        << "The same transaction shouldn't start twice without new timing.";
    return;
  }

  base::TimeDelta to_start = base::Time::Now() - request_creation_time_;
  request_creation_time_ = base::Time();

  UMA_HISTOGRAM_MEDIUM_TIMES("Net.HttpTimeToFirstByte", to_start);
  if (request_info_.upload_data_stream &&
      request_info_.upload_data_stream->size() > 1024 * 1024) {
    UMA_HISTOGRAM_MEDIUM_TIMES("Net.HttpTimeToFirstByte.LargeUpload", to_start);
  }
}

void URLRequestHttpJob::ResetTimer() {
  if (!request_creation_time_.is_null()) {
    NOTREACHED()
        << "The timer was reset before it was recorded.";
    return;
  }
  request_creation_time_ = base::Time::Now();
}

void URLRequestHttpJob::UpdatePacketReadTimes() {
  if (!packet_timing_enabled_)
    return;

  DCHECK_GT(prefilter_bytes_read(), bytes_observed_in_packets_);

  base::Time now(base::Time::Now());
  if (!bytes_observed_in_packets_)
    request_time_snapshot_ = now;
  final_packet_time_ = now;

  bytes_observed_in_packets_ = prefilter_bytes_read();
}

void URLRequestHttpJob::RecordPacketStats(
    SdchPolicyDelegate::StatisticSelector statistic) const {
  if (!packet_timing_enabled_ || (final_packet_time_ == base::Time()))
    return;

  base::TimeDelta duration = final_packet_time_ - request_time_snapshot_;
  switch (statistic) {
    case SdchPolicyDelegate::StatisticSelector::SDCH_DECODE: {
      UMA_HISTOGRAM_CUSTOM_COUNTS("Sdch3.Network_Decode_Bytes_Processed_b",
                                  static_cast<int>(bytes_observed_in_packets_),
                                  500, 100000, 100);
      return;
    }
    case SdchPolicyDelegate::StatisticSelector::SDCH_PASSTHROUGH: {
      // Despite advertising a dictionary, we handled non-sdch compressed
      // content.
      return;
    }

    case SdchPolicyDelegate::SDCH_EXPERIMENT_DECODE: {
      UMA_HISTOGRAM_CUSTOM_TIMES("Sdch3.Experiment3_Decode", duration,
                                 base::TimeDelta::FromMilliseconds(20),
                                 base::TimeDelta::FromMinutes(10), 100);
      return;
    }
    case SdchPolicyDelegate::SDCH_EXPERIMENT_HOLDBACK: {
      UMA_HISTOGRAM_CUSTOM_TIMES("Sdch3.Experiment3_Holdback", duration,
                                 base::TimeDelta::FromMilliseconds(20),
                                 base::TimeDelta::FromMinutes(10), 100);
      return;
    }
    default:
      NOTREACHED();
      return;
  }
}

void URLRequestHttpJob::RecordPerfHistograms(CompletionCause reason) {
  if (start_time_.is_null())
    return;

  base::TimeDelta total_time = base::TimeTicks::Now() - start_time_;
  UMA_HISTOGRAM_TIMES("Net.HttpJob.TotalTime", total_time);

  if (reason == FINISHED) {
    UMA_HISTOGRAM_TIMES("Net.HttpJob.TotalTimeSuccess", total_time);
  } else {
    UMA_HISTOGRAM_TIMES("Net.HttpJob.TotalTimeCancel", total_time);
  }

  if (response_info_) {
    // QUIC (by default) supports https scheme only, thus track https URLs only
    // for QUIC.
    bool is_https_google = request() && request()->url().SchemeIs("https") &&
                           HasGoogleHost(request()->url());
    bool used_quic = response_info_->DidUseQuic();
    if (is_https_google) {
      if (used_quic) {
        UMA_HISTOGRAM_MEDIUM_TIMES("Net.HttpJob.TotalTime.Secure.Quic",
                                   total_time);
      } else {
        UMA_HISTOGRAM_MEDIUM_TIMES("Net.HttpJob.TotalTime.Secure.NotQuic",
                                   total_time);
      }
    }

    UMA_HISTOGRAM_CUSTOM_COUNTS("Net.HttpJob.PrefilterBytesRead",
                                prefilter_bytes_read(), 1, 50000000, 50);
    if (response_info_->was_cached) {
      UMA_HISTOGRAM_TIMES("Net.HttpJob.TotalTimeCached", total_time);
      UMA_HISTOGRAM_CUSTOM_COUNTS("Net.HttpJob.PrefilterBytesRead.Cache",
                                  prefilter_bytes_read(), 1, 50000000, 50);

      if (response_info_->unused_since_prefetch)
        UMA_HISTOGRAM_COUNTS("Net.Prefetch.HitBytes", prefilter_bytes_read());
    } else {
      UMA_HISTOGRAM_TIMES("Net.HttpJob.TotalTimeNotCached", total_time);
      UMA_HISTOGRAM_CUSTOM_COUNTS("Net.HttpJob.PrefilterBytesRead.Net",
                                  prefilter_bytes_read(), 1, 50000000, 50);

      if (request_info_.load_flags & LOAD_PREFETCH) {
        UMA_HISTOGRAM_COUNTS("Net.Prefetch.PrefilterBytesReadFromNetwork",
                             prefilter_bytes_read());
      }
      if (is_https_google) {
        if (used_quic) {
          UMA_HISTOGRAM_MEDIUM_TIMES(
              "Net.HttpJob.TotalTimeNotCached.Secure.Quic", total_time);
        } else {
          UMA_HISTOGRAM_MEDIUM_TIMES(
              "Net.HttpJob.TotalTimeNotCached.Secure.NotQuic", total_time);
        }
      }
    }
  }

  start_time_ = base::TimeTicks();
}

void URLRequestHttpJob::DoneWithRequest(CompletionCause reason) {
  if (done_)
    return;
  done_ = true;

  // Notify NetworkQualityEstimator.
  NetworkQualityEstimator* network_quality_estimator =
      request()->context()->network_quality_estimator();
  if (network_quality_estimator) {
    network_quality_estimator->NotifyRequestCompleted(
        *request(), request_->status().error());
  }

  RecordPerfHistograms(reason);
  request()->set_received_response_content_length(prefilter_bytes_read());
}

HttpResponseHeaders* URLRequestHttpJob::GetResponseHeaders() const {
  DCHECK(transaction_.get());
  DCHECK(transaction_->GetResponseInfo());
  return override_response_headers_.get() ?
             override_response_headers_.get() :
             transaction_->GetResponseInfo()->headers.get();
}

void URLRequestHttpJob::NotifyURLRequestDestroyed() {
  awaiting_callback_ = false;

  // Notify NetworkQualityEstimator.
  NetworkQualityEstimator* network_quality_estimator =
      request()->context()->network_quality_estimator();
  if (network_quality_estimator)
    network_quality_estimator->NotifyURLRequestDestroyed(*request());
}

}  // namespace net
