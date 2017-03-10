// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert_net/nss_ocsp.h"

#include <certt.h>
#include <certdb.h>
#include <nspr.h>
#include <nss.h>
#include <ocsp.h>
#include <pthread.h>
#include <secerr.h>

#include <algorithm>
#include <memory>
#include <string>
#include <utility>

#include "base/callback.h"
#include "base/compiler_specific.h"
#include "base/lazy_instance.h"
#include "base/location.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/message_loop/message_loop.h"
#include "base/metrics/histogram_macros.h"
#include "base/single_thread_task_runner.h"
#include "base/stl_util.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/synchronization/condition_variable.h"
#include "base/synchronization/lock.h"
#include "base/threading/thread_checker.h"
#include "base/time/time.h"
#include "net/base/elements_upload_data_stream.h"
#include "net/base/host_port_pair.h"
#include "net/base/io_buffer.h"
#include "net/base/load_flags.h"
#include "net/base/request_priority.h"
#include "net/base/upload_bytes_element_reader.h"
#include "net/http/http_request_headers.h"
#include "net/http/http_response_headers.h"
#include "net/url_request/redirect_info.h"
#include "net/url_request/url_request.h"
#include "net/url_request/url_request_context.h"
#include "url/gurl.h"

namespace net {

namespace {

// Protects |g_request_context|.
pthread_mutex_t g_request_context_lock = PTHREAD_MUTEX_INITIALIZER;
URLRequestContext* g_request_context = NULL;

// The default timeout for network fetches in NSS is 60 seconds. Choose a
// saner upper limit for OCSP/CRL/AIA fetches.
const int kNetworkFetchTimeoutInSecs = 15;

class OCSPRequestSession;

class OCSPIOLoop {
 public:
  // This class is only instantiated as a leaky LazyInstance, so its destructor
  // is never called.
  ~OCSPIOLoop() = delete;

  void StartUsing() {
    base::AutoLock autolock(lock_);
    used_ = true;
    io_loop_ = base::MessageLoopForIO::current();
    DCHECK(io_loop_);
  }

  // Called on IO loop.
  void Shutdown();

  bool used() const {
    base::AutoLock autolock(lock_);
    return used_;
  }

  // Called from worker thread.
  void PostTaskToIOLoop(const tracked_objects::Location& from_here,
                        const base::Closure& task);

  void AddRequest(OCSPRequestSession* request);
  void RemoveRequest(OCSPRequestSession* request);

  // Clears internal state and calls |StartUsing()|. Should be called only in
  // the context of testing.
  void ReuseForTesting() {
    {
      base::AutoLock autolock(lock_);
      DCHECK(base::MessageLoopForIO::current());
      thread_checker_.DetachFromThread();

      // CalledOnValidThread is the only available API to reassociate
      // thread_checker_ with the current thread. Result ignored intentionally.
      ignore_result(thread_checker_.CalledOnValidThread());
      shutdown_ = false;
      used_ = false;
    }
    StartUsing();
  }

 private:
  friend struct base::LazyInstanceTraitsBase<OCSPIOLoop>;

  OCSPIOLoop();

  void CancelAllRequests();

  mutable base::Lock lock_;
  bool shutdown_;  // Protected by |lock_|.
  std::set<OCSPRequestSession*> requests_;  // Protected by |lock_|.
  bool used_;  // Protected by |lock_|.
  // This should not be modified after |used_|.
  base::MessageLoopForIO* io_loop_;  // Protected by |lock_|.
  base::ThreadChecker thread_checker_;

  DISALLOW_COPY_AND_ASSIGN(OCSPIOLoop);
};

base::LazyInstance<OCSPIOLoop>::Leaky
    g_ocsp_io_loop = LAZY_INSTANCE_INITIALIZER;

const int kRecvBufferSize = 4096;

// All OCSP handlers should be called in the context of
// CertVerifier's thread (i.e. worker pool, not on the I/O thread).
// It supports blocking mode only.

SECStatus OCSPCreateSession(const char* host, PRUint16 portnum,
                            SEC_HTTP_SERVER_SESSION* pSession);
SECStatus OCSPKeepAliveSession(SEC_HTTP_SERVER_SESSION session,
                               PRPollDesc **pPollDesc);
SECStatus OCSPFreeSession(SEC_HTTP_SERVER_SESSION session);

SECStatus OCSPCreate(SEC_HTTP_SERVER_SESSION session,
                     const char* http_protocol_variant,
                     const char* path_and_query_string,
                     const char* http_request_method,
                     const PRIntervalTime timeout,
                     SEC_HTTP_REQUEST_SESSION* pRequest);
SECStatus OCSPSetPostData(SEC_HTTP_REQUEST_SESSION request,
                          const char* http_data,
                          const PRUint32 http_data_len,
                          const char* http_content_type);
SECStatus OCSPAddHeader(SEC_HTTP_REQUEST_SESSION request,
                        const char* http_header_name,
                        const char* http_header_value);
SECStatus OCSPTrySendAndReceive(SEC_HTTP_REQUEST_SESSION request,
                                PRPollDesc** pPollDesc,
                                PRUint16* http_response_code,
                                const char** http_response_content_type,
                                const char** http_response_headers,
                                const char** http_response_data,
                                PRUint32* http_response_data_len);
SECStatus OCSPFree(SEC_HTTP_REQUEST_SESSION request);

char* GetAlternateOCSPAIAInfo(CERTCertificate *cert);

class OCSPNSSInitialization {
 private:
  friend struct base::LazyInstanceTraitsBase<OCSPNSSInitialization>;

  OCSPNSSInitialization();
  // This class is only instantiated as a leaky LazyInstance, so its destructor
  // is never called.
  ~OCSPNSSInitialization() = delete;

  SEC_HttpClientFcn client_fcn_;

  DISALLOW_COPY_AND_ASSIGN(OCSPNSSInitialization);
};

base::LazyInstance<OCSPNSSInitialization>::Leaky g_ocsp_nss_initialization =
    LAZY_INSTANCE_INITIALIZER;

// Concrete class for SEC_HTTP_REQUEST_SESSION.
// Public methods except virtual methods of URLRequest::Delegate
// (On* methods) run on certificate verifier thread (worker thread).
// Virtual methods of URLRequest::Delegate and private methods run
// on IO thread.
class OCSPRequestSession
    : public base::RefCountedThreadSafe<OCSPRequestSession>,
      public URLRequest::Delegate {
 public:
  OCSPRequestSession(const GURL& url,
                     const char* http_request_method,
                     base::TimeDelta timeout)
      : url_(url),
        http_request_method_(http_request_method),
        timeout_(timeout),
        buffer_(new IOBuffer(kRecvBufferSize)),
        response_code_(-1),
        cv_(&lock_),
        io_loop_(NULL),
        finished_(false) {}

  void SetPostData(const char* http_data, PRUint32 http_data_len,
                   const char* http_content_type) {
    // |upload_content_| should not be modified if |request_| is active.
    DCHECK(!request_);
    upload_content_.assign(http_data, http_data_len);
    upload_content_type_.assign(http_content_type);
  }

  void AddHeader(const char* http_header_name, const char* http_header_value) {
    extra_request_headers_.SetHeader(http_header_name,
                                     http_header_value);
  }

  void Start() {
    // At this point, it runs on worker thread.
    // |io_loop_| was initialized to be NULL in constructor, and
    // set only in StartURLRequest, so no need to lock |lock_| here.
    DCHECK(!io_loop_);
    g_ocsp_io_loop.Get().PostTaskToIOLoop(
        FROM_HERE,
        base::Bind(&OCSPRequestSession::StartURLRequest, this));
  }

  bool Started() const {
    return request_.get() != NULL;
  }

  void Cancel() {
    // IO thread may set |io_loop_| to NULL, so protect by |lock_|.
    base::AutoLock autolock(lock_);
    CancelLocked();
  }

  bool Finished() const {
    base::AutoLock autolock(lock_);
    return finished_;
  }

  bool Wait() {
    base::TimeDelta timeout = timeout_;
    base::AutoLock autolock(lock_);
    while (!finished_) {
      base::TimeTicks last_time = base::TimeTicks::Now();
      cv_.TimedWait(timeout);
      // Check elapsed time
      base::TimeDelta elapsed_time = base::TimeTicks::Now() - last_time;
      timeout -= elapsed_time;
      if (timeout < base::TimeDelta()) {
        VLOG(1) << "OCSP Timed out";
        if (!finished_)
          CancelLocked();
        break;
      }
    }
    return finished_;
  }

  const GURL& url() const {
    return url_;
  }

  const std::string& http_request_method() const {
    return http_request_method_;
  }

  base::TimeDelta timeout() const {
    return timeout_;
  }

  PRUint16 http_response_code() const {
    DCHECK(finished_);
    return response_code_;
  }

  const std::string& http_response_content_type() const {
    DCHECK(finished_);
    return response_content_type_;
  }

  const std::string& http_response_headers() const {
    DCHECK(finished_);
    return response_headers_->raw_headers();
  }

  const std::string& http_response_data() const {
    DCHECK(finished_);
    return data_;
  }

  void OnReceivedRedirect(URLRequest* request,
                          const RedirectInfo& redirect_info,
                          bool* defer_redirect) override {
    DCHECK_EQ(request_.get(), request);
    DCHECK_EQ(base::MessageLoopForIO::current(), io_loop_);

    if (!redirect_info.new_url.SchemeIs("http")) {
      // Prevent redirects to non-HTTP schemes, including HTTPS. This matches
      // the initial check in OCSPServerSession::CreateRequest().
      CancelURLRequest();
    }
  }

  void OnResponseStarted(URLRequest* request, int net_error) override {
    DCHECK_EQ(request_.get(), request);
    DCHECK_EQ(base::MessageLoopForIO::current(), io_loop_);
    DCHECK_NE(ERR_IO_PENDING, net_error);

    int bytes_read = 0;
    if (net_error == OK) {
      response_code_ = request_->GetResponseCode();
      response_headers_ = request_->response_headers();
      response_headers_->GetMimeType(&response_content_type_);
      bytes_read = request_->Read(buffer_.get(), kRecvBufferSize);
    }
    OnReadCompleted(request_.get(), bytes_read);
  }

  void OnReadCompleted(URLRequest* request, int bytes_read) override {
    DCHECK_EQ(request_.get(), request);
    DCHECK_EQ(base::MessageLoopForIO::current(), io_loop_);

    while (bytes_read > 0) {
      data_.append(buffer_->data(), bytes_read);
      bytes_read = request_->Read(buffer_.get(), kRecvBufferSize);
    }

    if (bytes_read != ERR_IO_PENDING) {
      request_.reset();
      g_ocsp_io_loop.Get().RemoveRequest(this);
      {
        base::AutoLock autolock(lock_);
        finished_ = true;
        io_loop_ = NULL;
      }
      cv_.Signal();
      Release();  // Balanced with StartURLRequest().
    }
  }

  // Must be called on the IO loop thread.
  void CancelURLRequest() {
#ifndef NDEBUG
    {
      base::AutoLock autolock(lock_);
      if (io_loop_)
        DCHECK_EQ(base::MessageLoopForIO::current(), io_loop_);
    }
#endif
    if (request_) {
      request_.reset();
      g_ocsp_io_loop.Get().RemoveRequest(this);
      {
        base::AutoLock autolock(lock_);
        finished_ = true;
        io_loop_ = NULL;
      }
      cv_.Signal();
      Release();  // Balanced with StartURLRequest().
    }
  }

 private:
  friend class base::RefCountedThreadSafe<OCSPRequestSession>;

  ~OCSPRequestSession() override {
    // When this destructor is called, there should be only one thread that has
    // a reference to this object, and so that thread doesn't need to lock
    // |lock_| here.
    DCHECK(!request_);
    DCHECK(!io_loop_);
  }

  // Must call this method while holding |lock_|.
  void CancelLocked() {
    lock_.AssertAcquired();
    if (io_loop_) {
      io_loop_->task_runner()->PostTask(
          FROM_HERE, base::Bind(&OCSPRequestSession::CancelURLRequest, this));
    }
  }

  // Runs on |g_ocsp_io_loop|'s IO loop.
  void StartURLRequest() {
    DCHECK(!request_);

    pthread_mutex_lock(&g_request_context_lock);
    URLRequestContext* url_request_context = g_request_context;
    pthread_mutex_unlock(&g_request_context_lock);

    if (url_request_context == NULL)
      return;

    {
      base::AutoLock autolock(lock_);
      DCHECK(!io_loop_);
      io_loop_ = base::MessageLoopForIO::current();
      g_ocsp_io_loop.Get().AddRequest(this);
    }

    request_ = url_request_context->CreateRequest(url_, DEFAULT_PRIORITY, this);
    // To meet the privacy requirements of incognito mode.
    request_->SetLoadFlags(LOAD_DISABLE_CACHE | LOAD_DO_NOT_SAVE_COOKIES |
                           LOAD_DO_NOT_SEND_COOKIES);

    if (http_request_method_ == "POST") {
      DCHECK(!upload_content_.empty());
      DCHECK(!upload_content_type_.empty());

      request_->set_method("POST");
      extra_request_headers_.SetHeader(
          HttpRequestHeaders::kContentType, upload_content_type_);

      std::unique_ptr<UploadElementReader> reader(new UploadBytesElementReader(
          upload_content_.data(), upload_content_.size()));
      request_->set_upload(
          ElementsUploadDataStream::CreateWithReader(std::move(reader), 0));
    }
    if (!extra_request_headers_.IsEmpty())
      request_->SetExtraRequestHeaders(extra_request_headers_);

    request_->Start();
    AddRef();  // Release after |request_| deleted.
  }

  GURL url_;                        // The URL we eventually wound up at
  std::string http_request_method_;
  base::TimeDelta timeout_;         // The timeout for OCSP
  std::unique_ptr<URLRequest> request_;  // The actual request this wraps
  scoped_refptr<IOBuffer> buffer_;  // Read buffer
  HttpRequestHeaders extra_request_headers_;

  // HTTP POST payload. |request_| reads bytes from this.
  std::string upload_content_;
  std::string upload_content_type_;  // MIME type of POST payload

  int response_code_;             // HTTP status code for the request
  std::string response_content_type_;
  scoped_refptr<HttpResponseHeaders> response_headers_;
  std::string data_;              // Results of the request

  // |lock_| protects |finished_| and |io_loop_|.
  mutable base::Lock lock_;
  base::ConditionVariable cv_;

  base::MessageLoop* io_loop_;  // Message loop of the IO thread
  bool finished_;

  DISALLOW_COPY_AND_ASSIGN(OCSPRequestSession);
};

// Concrete class for SEC_HTTP_SERVER_SESSION.
class OCSPServerSession {
 public:
  OCSPServerSession(const char* host, PRUint16 port)
      : host_and_port_(host, port) {}
  ~OCSPServerSession() {}

  OCSPRequestSession* CreateRequest(const char* http_protocol_variant,
                                    const char* path_and_query_string,
                                    const char* http_request_method,
                                    const PRIntervalTime timeout) {
    // We dont' support "https" because we haven't thought about
    // whether it's safe to re-enter this code from talking to an OCSP
    // responder over SSL.
    if (strcmp(http_protocol_variant, "http") != 0) {
      PORT_SetError(PR_NOT_IMPLEMENTED_ERROR);
      return NULL;
    }

    std::string url_string(base::StringPrintf(
        "%s://%s%s",
        http_protocol_variant,
        host_and_port_.ToString().c_str(),
        path_and_query_string));
    VLOG(1) << "URL [" << url_string << "]";
    GURL url(url_string);

    // NSS does not expose public functions to adjust the fetch timeout when
    // using libpkix, so hardcode the upper limit for network fetches.
    base::TimeDelta actual_timeout = std::min(
        base::TimeDelta::FromSeconds(kNetworkFetchTimeoutInSecs),
        base::TimeDelta::FromMilliseconds(PR_IntervalToMilliseconds(timeout)));

    return new OCSPRequestSession(url, http_request_method, actual_timeout);
  }


 private:
  HostPortPair host_and_port_;

  DISALLOW_COPY_AND_ASSIGN(OCSPServerSession);
};

OCSPIOLoop::OCSPIOLoop()
    : shutdown_(false),
      used_(false),
      io_loop_(NULL) {
}

void OCSPIOLoop::Shutdown() {
  // Safe to read outside lock since we only write on IO thread anyway.
  DCHECK(thread_checker_.CalledOnValidThread());

  // Prevent the worker thread from trying to access |io_loop_|.
  {
    base::AutoLock autolock(lock_);
    io_loop_ = NULL;
    used_ = false;
    shutdown_ = true;
  }

  CancelAllRequests();

  pthread_mutex_lock(&g_request_context_lock);
  g_request_context = NULL;
  pthread_mutex_unlock(&g_request_context_lock);
}

void OCSPIOLoop::PostTaskToIOLoop(
    const tracked_objects::Location& from_here, const base::Closure& task) {
  base::AutoLock autolock(lock_);
  if (io_loop_)
    io_loop_->task_runner()->PostTask(from_here, task);
}

void OCSPIOLoop::AddRequest(OCSPRequestSession* request) {
  DCHECK(!base::ContainsKey(requests_, request));
  requests_.insert(request);
}

void OCSPIOLoop::RemoveRequest(OCSPRequestSession* request) {
  DCHECK(base::ContainsKey(requests_, request));
  requests_.erase(request);
}

void OCSPIOLoop::CancelAllRequests() {
  // CancelURLRequest() always removes the request from the requests_
  // set synchronously.
  while (!requests_.empty())
    (*requests_.begin())->CancelURLRequest();
}

OCSPNSSInitialization::OCSPNSSInitialization() {
  // NSS calls the functions in the function table to download certificates
  // or CRLs or talk to OCSP responders over HTTP.  These functions must
  // set an NSS/NSPR error code when they fail.  Otherwise NSS will get the
  // residual error code from an earlier failed function call.
  client_fcn_.version = 1;
  SEC_HttpClientFcnV1Struct *ft = &client_fcn_.fcnTable.ftable1;
  ft->createSessionFcn = OCSPCreateSession;
  ft->keepAliveSessionFcn = OCSPKeepAliveSession;
  ft->freeSessionFcn = OCSPFreeSession;
  ft->createFcn = OCSPCreate;
  ft->setPostDataFcn = OCSPSetPostData;
  ft->addHeaderFcn = OCSPAddHeader;
  ft->trySendAndReceiveFcn = OCSPTrySendAndReceive;
  ft->cancelFcn = NULL;
  ft->freeFcn = OCSPFree;
  SECStatus status = SEC_RegisterDefaultHttpClient(&client_fcn_);
  if (status != SECSuccess) {
    NOTREACHED() << "Error initializing OCSP: " << PR_GetError();
  }

  // Work around NSS bugs 524013 and 564334.  NSS incorrectly thinks the
  // CRLs for Network Solutions Certificate Authority have bad signatures,
  // which causes certificates issued by that CA to be reported as revoked.
  // By using OCSP for those certificates, which don't have AIA extensions,
  // we can work around these bugs.  See http://crbug.com/41730.
  CERT_StringFromCertFcn old_callback = NULL;
  status = CERT_RegisterAlternateOCSPAIAInfoCallBack(
      GetAlternateOCSPAIAInfo, &old_callback);
  if (status == SECSuccess) {
    DCHECK(!old_callback);
  } else {
    NOTREACHED() << "Error initializing OCSP: " << PR_GetError();
  }
}


// OCSP Http Client functions.
// Our Http Client functions operate in blocking mode.
SECStatus OCSPCreateSession(const char* host, PRUint16 portnum,
                            SEC_HTTP_SERVER_SESSION* pSession) {
  VLOG(1) << "OCSP create session: host=" << host << " port=" << portnum;
  pthread_mutex_lock(&g_request_context_lock);
  URLRequestContext* request_context = g_request_context;
  pthread_mutex_unlock(&g_request_context_lock);
  if (request_context == NULL) {
    LOG(ERROR) << "No URLRequestContext for NSS HTTP handler. host: " << host;
    // The application failed to call SetURLRequestContextForNSSHttpIO or
    // has already called ShutdownNSSHttpIO, so we can't create and use
    // URLRequest.  PR_NOT_IMPLEMENTED_ERROR is not an accurate error
    // code for these error conditions, but is close enough.
    PORT_SetError(PR_NOT_IMPLEMENTED_ERROR);
    return SECFailure;
  }
  *pSession = new OCSPServerSession(host, portnum);
  return SECSuccess;
}

SECStatus OCSPKeepAliveSession(SEC_HTTP_SERVER_SESSION session,
                               PRPollDesc **pPollDesc) {
  VLOG(1) << "OCSP keep alive";
  if (pPollDesc)
    *pPollDesc = NULL;
  return SECSuccess;
}

SECStatus OCSPFreeSession(SEC_HTTP_SERVER_SESSION session) {
  VLOG(1) << "OCSP free session";
  delete reinterpret_cast<OCSPServerSession*>(session);
  return SECSuccess;
}

SECStatus OCSPCreate(SEC_HTTP_SERVER_SESSION session,
                     const char* http_protocol_variant,
                     const char* path_and_query_string,
                     const char* http_request_method,
                     const PRIntervalTime timeout,
                     SEC_HTTP_REQUEST_SESSION* pRequest) {
  VLOG(1) << "OCSP create protocol=" << http_protocol_variant
          << " path_and_query=" << path_and_query_string
          << " http_request_method=" << http_request_method
          << " timeout=" << timeout;
  OCSPServerSession* ocsp_session =
      reinterpret_cast<OCSPServerSession*>(session);

  OCSPRequestSession* req = ocsp_session->CreateRequest(http_protocol_variant,
                                                        path_and_query_string,
                                                        http_request_method,
                                                        timeout);
  SECStatus rv = SECFailure;
  if (req) {
    req->AddRef();  // Release in OCSPFree().
    rv = SECSuccess;
  }
  *pRequest = req;
  return rv;
}

SECStatus OCSPSetPostData(SEC_HTTP_REQUEST_SESSION request,
                          const char* http_data,
                          const PRUint32 http_data_len,
                          const char* http_content_type) {
  VLOG(1) << "OCSP set post data len=" << http_data_len;
  OCSPRequestSession* req = reinterpret_cast<OCSPRequestSession*>(request);

  req->SetPostData(http_data, http_data_len, http_content_type);
  return SECSuccess;
}

SECStatus OCSPAddHeader(SEC_HTTP_REQUEST_SESSION request,
                        const char* http_header_name,
                        const char* http_header_value) {
  VLOG(1) << "OCSP add header name=" << http_header_name
          << " value=" << http_header_value;
  OCSPRequestSession* req = reinterpret_cast<OCSPRequestSession*>(request);

  req->AddHeader(http_header_name, http_header_value);
  return SECSuccess;
}

// Sets response of |req| in the output parameters.
// It is helper routine for OCSP trySendAndReceiveFcn.
// |http_response_data_len| could be used as input parameter.  If it has
// non-zero value, it is considered as maximum size of |http_response_data|.
SECStatus OCSPSetResponse(OCSPRequestSession* req,
                          PRUint16* http_response_code,
                          const char** http_response_content_type,
                          const char** http_response_headers,
                          const char** http_response_data,
                          PRUint32* http_response_data_len) {
  DCHECK(req->Finished());
  const std::string& data = req->http_response_data();
  if (http_response_data_len && *http_response_data_len) {
    if (*http_response_data_len < data.size()) {
      LOG(ERROR) << "response body too large: " << *http_response_data_len
                 << " < " << data.size();
      *http_response_data_len = data.size();
      PORT_SetError(SEC_ERROR_BAD_HTTP_RESPONSE);
      return SECFailure;
    }
  }
  VLOG(1) << "OCSP response "
          << " response_code=" << req->http_response_code()
          << " content_type=" << req->http_response_content_type()
          << " header=" << req->http_response_headers()
          << " data_len=" << data.size();
  if (http_response_code)
    *http_response_code = req->http_response_code();
  if (http_response_content_type)
    *http_response_content_type = req->http_response_content_type().c_str();
  if (http_response_headers)
    *http_response_headers = req->http_response_headers().c_str();
  if (http_response_data)
    *http_response_data = data.data();
  if (http_response_data_len)
    *http_response_data_len = data.size();
  return SECSuccess;
}

SECStatus OCSPTrySendAndReceive(SEC_HTTP_REQUEST_SESSION request,
                                PRPollDesc** pPollDesc,
                                PRUint16* http_response_code,
                                const char** http_response_content_type,
                                const char** http_response_headers,
                                const char** http_response_data,
                                PRUint32* http_response_data_len) {
  if (http_response_data_len) {
    // We must always set an output value, even on failure.  The output value 0
    // means the failure was unrelated to the acceptable response data length.
    *http_response_data_len = 0;
  }

  VLOG(1) << "OCSP try send and receive";
  OCSPRequestSession* req = reinterpret_cast<OCSPRequestSession*>(request);
  // We support blocking mode only.
  if (pPollDesc)
    *pPollDesc = NULL;

  if (req->Started() || req->Finished()) {
    // We support blocking mode only, so this function shouldn't be called
    // again when req has stareted or finished.
    NOTREACHED();
    PORT_SetError(SEC_ERROR_BAD_HTTP_RESPONSE);  // Simple approximation.
    return SECFailure;
  }

  const base::Time start_time = base::Time::Now();
  bool request_ok = true;
  req->Start();
  if (!req->Wait() || req->http_response_code() == static_cast<PRUint16>(-1)) {
    // If the response code is -1, the request failed and there is no response.
    request_ok = false;
  }
  const base::TimeDelta duration = base::Time::Now() - start_time;

  // For metrics, we want to know if the request was 'successful' or not.
  // |request_ok| determines if we'll pass the response back to NSS and |ok|
  // keep track of if we think the response was good.
  bool ok = true;
  if (!request_ok ||
      (req->http_response_code() >= 400 && req->http_response_code() < 600) ||
      req->http_response_data().size() == 0 ||
      // 0x30 is the ASN.1 DER encoding of a SEQUENCE. All valid OCSP/CRL/CRT
      // responses must start with this. If we didn't check for this then a
      // captive portal could provide an HTML reply that we would count as a
      // 'success' (although it wouldn't count in NSS, of course).
      req->http_response_data().data()[0] != 0x30) {
    ok = false;
  }

  // We want to know if this was:
  //   1) An OCSP request
  //   2) A CRL request
  //   3) A request for a missing intermediate certificate
  // There's no sure way to do this, so we use heuristics like MIME type and
  // URL.
  const char* mime_type = "";
  if (ok)
    mime_type = req->http_response_content_type().c_str();
  bool is_ocsp =
      strcasecmp(mime_type, "application/ocsp-response") == 0;
  bool is_crl = strcasecmp(mime_type, "application/x-pkcs7-crl") == 0 ||
                strcasecmp(mime_type, "application/x-x509-crl") == 0 ||
                strcasecmp(mime_type, "application/pkix-crl") == 0;
  bool is_cert =
      strcasecmp(mime_type, "application/x-x509-ca-cert") == 0 ||
      strcasecmp(mime_type, "application/x-x509-server-cert") == 0 ||
      strcasecmp(mime_type, "application/pkix-cert") == 0 ||
      strcasecmp(mime_type, "application/pkcs7-mime") == 0;

  if (!is_cert && !is_crl && !is_ocsp) {
    // We didn't get a hint from the MIME type, so do the best that we can.
    const std::string path = req->url().path();
    const std::string host = req->url().host();
    is_crl = strcasestr(path.c_str(), ".crl") != NULL;
    is_cert = strcasestr(path.c_str(), ".crt") != NULL ||
              strcasestr(path.c_str(), ".p7c") != NULL ||
              strcasestr(path.c_str(), ".cer") != NULL;
    is_ocsp = strcasestr(host.c_str(), "ocsp") != NULL ||
              req->http_request_method() == "POST";
  }

  if (is_ocsp) {
    if (ok) {
      UMA_HISTOGRAM_TIMES("Net.OCSPRequestTimeMs", duration);
      UMA_HISTOGRAM_BOOLEAN("Net.OCSPRequestSuccess", true);
    } else {
      UMA_HISTOGRAM_TIMES("Net.OCSPRequestFailedTimeMs", duration);
      UMA_HISTOGRAM_BOOLEAN("Net.OCSPRequestSuccess", false);
    }
  } else if (is_crl) {
    if (ok) {
      UMA_HISTOGRAM_TIMES("Net.CRLRequestTimeMs", duration);
      UMA_HISTOGRAM_BOOLEAN("Net.CRLRequestSuccess", true);
    } else {
      UMA_HISTOGRAM_TIMES("Net.CRLRequestFailedTimeMs", duration);
      UMA_HISTOGRAM_BOOLEAN("Net.CRLRequestSuccess", false);
    }
  } else if (is_cert) {
    if (ok)
      UMA_HISTOGRAM_TIMES("Net.CRTRequestTimeMs", duration);
  } else {
    if (ok)
      UMA_HISTOGRAM_TIMES("Net.UnknownTypeRequestTimeMs", duration);
  }

  if (!request_ok) {
    PORT_SetError(SEC_ERROR_BAD_HTTP_RESPONSE);  // Simple approximation.
    return SECFailure;
  }

  return OCSPSetResponse(
      req, http_response_code,
      http_response_content_type,
      http_response_headers,
      http_response_data,
      http_response_data_len);
}

SECStatus OCSPFree(SEC_HTTP_REQUEST_SESSION request) {
  VLOG(1) << "OCSP free";
  OCSPRequestSession* req = reinterpret_cast<OCSPRequestSession*>(request);
  req->Cancel();
  req->Release();
  return SECSuccess;
}

// Data for GetAlternateOCSPAIAInfo.

// CN=Network Solutions Certificate Authority,O=Network Solutions L.L.C.,C=US
//
// There are two CAs with this name.  Their key IDs are listed next.
const unsigned char network_solutions_ca_name[] = {
  0x30, 0x62, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
  0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x21, 0x30, 0x1f, 0x06,
  0x03, 0x55, 0x04, 0x0a, 0x13, 0x18, 0x4e, 0x65, 0x74, 0x77,
  0x6f, 0x72, 0x6b, 0x20, 0x53, 0x6f, 0x6c, 0x75, 0x74, 0x69,
  0x6f, 0x6e, 0x73, 0x20, 0x4c, 0x2e, 0x4c, 0x2e, 0x43, 0x2e,
  0x31, 0x30, 0x30, 0x2e, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13,
  0x27, 0x4e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x20, 0x53,
  0x6f, 0x6c, 0x75, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x20, 0x43,
  0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65,
  0x20, 0x41, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x69, 0x74, 0x79
};
const unsigned int network_solutions_ca_name_len = 100;

// This CA is an intermediate CA, subordinate to UTN-USERFirst-Hardware.
const unsigned char network_solutions_ca_key_id[] = {
  0x3c, 0x41, 0xe2, 0x8f, 0x08, 0x08, 0xa9, 0x4c, 0x25, 0x89,
  0x8d, 0x6d, 0xc5, 0x38, 0xd0, 0xfc, 0x85, 0x8c, 0x62, 0x17
};
const unsigned int network_solutions_ca_key_id_len = 20;

// This CA is a root CA.  It is also cross-certified by
// UTN-USERFirst-Hardware.
const unsigned char network_solutions_ca_key_id2[] = {
  0x21, 0x30, 0xc9, 0xfb, 0x00, 0xd7, 0x4e, 0x98, 0xda, 0x87,
  0xaa, 0x2a, 0xd0, 0xa7, 0x2e, 0xb1, 0x40, 0x31, 0xa7, 0x4c
};
const unsigned int network_solutions_ca_key_id2_len = 20;

// An entry in our OCSP responder table.  |issuer| and |issuer_key_id| are
// the key.  |ocsp_url| is the value.
struct OCSPResponderTableEntry {
  SECItem issuer;
  SECItem issuer_key_id;
  const char *ocsp_url;
};

const OCSPResponderTableEntry g_ocsp_responder_table[] = {
  {
    {
      siBuffer,
      const_cast<unsigned char*>(network_solutions_ca_name),
      network_solutions_ca_name_len
    },
    {
      siBuffer,
      const_cast<unsigned char*>(network_solutions_ca_key_id),
      network_solutions_ca_key_id_len
    },
    "http://ocsp.netsolssl.com"
  },
  {
    {
      siBuffer,
      const_cast<unsigned char*>(network_solutions_ca_name),
      network_solutions_ca_name_len
    },
    {
      siBuffer,
      const_cast<unsigned char*>(network_solutions_ca_key_id2),
      network_solutions_ca_key_id2_len
    },
    "http://ocsp.netsolssl.com"
  }
};

char* GetAlternateOCSPAIAInfo(CERTCertificate *cert) {
  if (cert && !cert->isRoot && cert->authKeyID) {
    for (unsigned int i=0; i < arraysize(g_ocsp_responder_table); i++) {
      if (SECITEM_CompareItem(&g_ocsp_responder_table[i].issuer,
                              &cert->derIssuer) == SECEqual &&
          SECITEM_CompareItem(&g_ocsp_responder_table[i].issuer_key_id,
                              &cert->authKeyID->keyID) == SECEqual) {
        return PORT_Strdup(g_ocsp_responder_table[i].ocsp_url);
      }
    }
  }

  return NULL;
}

}  // anonymous namespace

void SetMessageLoopForNSSHttpIO() {
  // Must have a MessageLoopForIO.
  DCHECK(base::MessageLoopForIO::current());

  bool used = g_ocsp_io_loop.Get().used();

  // Should not be called when g_ocsp_io_loop has already been used.
  DCHECK(!used);
}

void EnsureNSSHttpIOInit() {
  g_ocsp_io_loop.Get().StartUsing();
  g_ocsp_nss_initialization.Get();
}

void ShutdownNSSHttpIO() {
  g_ocsp_io_loop.Get().Shutdown();
}

void ResetNSSHttpIOForTesting() {
  g_ocsp_io_loop.Get().ReuseForTesting();
}

// This function would be called before NSS initialization.
void SetURLRequestContextForNSSHttpIO(URLRequestContext* request_context) {
  pthread_mutex_lock(&g_request_context_lock);
  if (request_context) {
    DCHECK(!g_request_context);
  }
  g_request_context = request_context;
  pthread_mutex_unlock(&g_request_context_lock);
}

}  // namespace net
