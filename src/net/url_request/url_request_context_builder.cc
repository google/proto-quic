// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/url_request/url_request_context_builder.h"

#include <string>
#include <utility>
#include <vector>

#include "base/compiler_specific.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/memory/ptr_util.h"
#include "base/message_loop/message_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_util.h"
#include "base/threading/thread.h"
#include "base/threading/thread_task_runner_handle.h"
#include "net/base/cache_type.h"
#include "net/base/net_errors.h"
#include "net/base/network_delegate_impl.h"
#include "net/base/sdch_manager.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/ct_known_logs.h"
#include "net/cert/ct_log_verifier.h"
#include "net/cert/ct_policy_enforcer.h"
#include "net/cert/ct_verifier.h"
#include "net/cert/multi_log_ct_verifier.h"
#include "net/cookies/cookie_monster.h"
#include "net/dns/host_resolver.h"
#include "net/http/http_auth_handler_factory.h"
#include "net/http/http_cache.h"
#include "net/http/http_network_layer.h"
#include "net/http/http_server_properties_impl.h"
#include "net/http/http_server_properties_manager.h"
#include "net/http/transport_security_persister.h"
#include "net/http/transport_security_state.h"
#include "net/net_features.h"
#include "net/nqe/network_quality_estimator.h"
#include "net/quic/chromium/quic_stream_factory.h"
#include "net/reporting/reporting_policy.h"
#include "net/reporting/reporting_service.h"
#include "net/ssl/channel_id_service.h"
#include "net/ssl/default_channel_id_store.h"
#include "net/ssl/ssl_config_service_defaults.h"
#include "net/url_request/data_protocol_handler.h"
#include "net/url_request/static_http_user_agent_settings.h"
#include "net/url_request/url_request_context.h"
#include "net/url_request/url_request_context_storage.h"
#include "net/url_request/url_request_intercepting_job_factory.h"
#include "net/url_request/url_request_interceptor.h"
#include "net/url_request/url_request_job_factory_impl.h"
#include "net/url_request/url_request_throttler_manager.h"
#include "url/url_constants.h"

#if !BUILDFLAG(DISABLE_FILE_SUPPORT)
#include "net/url_request/file_protocol_handler.h"  // nogncheck
#endif

#if !BUILDFLAG(DISABLE_FTP_SUPPORT)
#include "net/ftp/ftp_network_layer.h"             // nogncheck
#include "net/url_request/ftp_protocol_handler.h"  // nogncheck
#endif

namespace net {

namespace {

class BasicNetworkDelegate : public NetworkDelegateImpl {
 public:
  BasicNetworkDelegate() {}
  ~BasicNetworkDelegate() override {}

 private:
  int OnBeforeURLRequest(URLRequest* request,
                         const CompletionCallback& callback,
                         GURL* new_url) override {
    return OK;
  }

  int OnBeforeStartTransaction(URLRequest* request,
                               const CompletionCallback& callback,
                               HttpRequestHeaders* headers) override {
    return OK;
  }

  void OnStartTransaction(URLRequest* request,
                          const HttpRequestHeaders& headers) override {}

  int OnHeadersReceived(
      URLRequest* request,
      const CompletionCallback& callback,
      const HttpResponseHeaders* original_response_headers,
      scoped_refptr<HttpResponseHeaders>* override_response_headers,
      GURL* allowed_unsafe_redirect_url) override {
    return OK;
  }

  void OnBeforeRedirect(URLRequest* request,
                        const GURL& new_location) override {}

  void OnResponseStarted(URLRequest* request, int net_error) override {}

  void OnCompleted(URLRequest* request, bool started, int net_error) override {}

  void OnURLRequestDestroyed(URLRequest* request) override {}

  void OnPACScriptError(int line_number, const base::string16& error) override {
  }

  NetworkDelegate::AuthRequiredResponse OnAuthRequired(
      URLRequest* request,
      const AuthChallengeInfo& auth_info,
      const AuthCallback& callback,
      AuthCredentials* credentials) override {
    return NetworkDelegate::AUTH_REQUIRED_RESPONSE_NO_ACTION;
  }

  bool OnCanGetCookies(const URLRequest& request,
                       const CookieList& cookie_list) override {
    return true;
  }

  bool OnCanSetCookie(const URLRequest& request,
                      const std::string& cookie_line,
                      CookieOptions* options) override {
    return true;
  }

  bool OnCanAccessFile(const URLRequest& request,
                       const base::FilePath& original_path,
                       const base::FilePath& absolute_path) const override {
    return true;
  }

  DISALLOW_COPY_AND_ASSIGN(BasicNetworkDelegate);
};

// A URLRequestContext subclass that owns most of its components
// via a UrlRequestContextStorage object. When URLRequestContextBuilder::Build()
// is called, ownership of all URLRequestContext components is passed to the
// ContainerURLRequestContext. Since this cancels requests in its destructor,
// it's not safe to subclass this.
class ContainerURLRequestContext final : public URLRequestContext {
 public:
  explicit ContainerURLRequestContext(
      const scoped_refptr<base::SingleThreadTaskRunner>& file_task_runner)
      : file_task_runner_(file_task_runner), storage_(this) {}

  ~ContainerURLRequestContext() override {
    // Destroy the ReportingService before the rest of the URLRequestContext, so
    // it cancels any pending requests it may have.
    storage_.set_reporting_service(nullptr);

    // Shut down the ProxyService, as it may have pending URLRequests using this
    // context. Since this cancels requests, it's not safe to subclass this, as
    // some parts of the URLRequestContext may then be torn down before this
    // cancels the ProxyService's URLRequests.
    proxy_service()->OnShutdown();

    AssertNoURLRequests();
  }

  URLRequestContextStorage* storage() {
    return &storage_;
  }

  scoped_refptr<base::SingleThreadTaskRunner>& GetFileTaskRunner() {
    // Create a new thread to run file tasks, if needed.
    if (!file_task_runner_) {
      DCHECK(!file_thread_);
      file_thread_.reset(new base::Thread("Network File Thread"));
      file_thread_->StartWithOptions(
          base::Thread::Options(base::MessageLoop::TYPE_DEFAULT, 0));
      file_task_runner_ = file_thread_->task_runner();
    }
    return file_task_runner_;
  }

  void set_transport_security_persister(
      std::unique_ptr<TransportSecurityPersister>
          transport_security_persister) {
    transport_security_persister_ = std::move(transport_security_persister);
  }

 private:
  // The thread should be torn down last.
  std::unique_ptr<base::Thread> file_thread_;
  scoped_refptr<base::SingleThreadTaskRunner> file_task_runner_;

  URLRequestContextStorage storage_;
  std::unique_ptr<TransportSecurityPersister> transport_security_persister_;

  DISALLOW_COPY_AND_ASSIGN(ContainerURLRequestContext);
};

}  // namespace

URLRequestContextBuilder::HttpCacheParams::HttpCacheParams()
    : type(IN_MEMORY),
      max_size(0) {}
URLRequestContextBuilder::HttpCacheParams::~HttpCacheParams() {}

URLRequestContextBuilder::URLRequestContextBuilder()
    : name_(nullptr),
      enable_brotli_(false),
      network_quality_estimator_(nullptr),
      data_enabled_(false),
#if !BUILDFLAG(DISABLE_FILE_SUPPORT)
      file_enabled_(false),
#endif
#if !BUILDFLAG(DISABLE_FTP_SUPPORT)
      ftp_enabled_(false),
#endif
      http_cache_enabled_(true),
      throttling_enabled_(false),
      sdch_enabled_(false),
      cookie_store_set_by_client_(false),
      net_log_(nullptr),
      pac_quick_check_enabled_(true),
      pac_sanitize_url_policy_(ProxyService::SanitizeUrlPolicy::SAFE) {
}

URLRequestContextBuilder::~URLRequestContextBuilder() {}

void URLRequestContextBuilder::SetHttpNetworkSessionComponents(
    const URLRequestContext* request_context,
    HttpNetworkSession::Context* session_context) {
  session_context->host_resolver = request_context->host_resolver();
  session_context->cert_verifier = request_context->cert_verifier();
  session_context->transport_security_state =
      request_context->transport_security_state();
  session_context->cert_transparency_verifier =
      request_context->cert_transparency_verifier();
  session_context->ct_policy_enforcer = request_context->ct_policy_enforcer();
  session_context->proxy_service = request_context->proxy_service();
  session_context->ssl_config_service = request_context->ssl_config_service();
  session_context->http_auth_handler_factory =
      request_context->http_auth_handler_factory();
  session_context->http_server_properties =
      request_context->http_server_properties();
  session_context->net_log = request_context->net_log();
  session_context->channel_id_service = request_context->channel_id_service();
  session_context->network_quality_provider =
      request_context->network_quality_estimator();
  if (request_context->network_quality_estimator()) {
    session_context->socket_performance_watcher_factory =
        request_context->network_quality_estimator()
            ->GetSocketPerformanceWatcherFactory();
  }
}

void URLRequestContextBuilder::EnableHttpCache(const HttpCacheParams& params) {
  http_cache_enabled_ = true;
  http_cache_params_ = params;
}

void URLRequestContextBuilder::DisableHttpCache() {
  http_cache_enabled_ = false;
  http_cache_params_ = HttpCacheParams();
}

void URLRequestContextBuilder::SetSpdyAndQuicEnabled(bool spdy_enabled,
                                                     bool quic_enabled) {
  http_network_session_params_.enable_http2 = spdy_enabled;
  http_network_session_params_.enable_quic = quic_enabled;
}

void URLRequestContextBuilder::set_ct_verifier(
    std::unique_ptr<CTVerifier> ct_verifier) {
  ct_verifier_ = std::move(ct_verifier);
}

void URLRequestContextBuilder::SetCertVerifier(
    std::unique_ptr<CertVerifier> cert_verifier) {
  cert_verifier_ = std::move(cert_verifier);
}

void URLRequestContextBuilder::set_reporting_policy(
    std::unique_ptr<net::ReportingPolicy> reporting_policy) {
  reporting_policy_ = std::move(reporting_policy);
}

void URLRequestContextBuilder::SetInterceptors(
    std::vector<std::unique_ptr<URLRequestInterceptor>>
        url_request_interceptors) {
  url_request_interceptors_ = std::move(url_request_interceptors);
}

void URLRequestContextBuilder::SetCookieAndChannelIdStores(
    std::unique_ptr<CookieStore> cookie_store,
    std::unique_ptr<ChannelIDService> channel_id_service) {
  cookie_store_set_by_client_ = true;
  // If |cookie_store| is NULL, |channel_id_service| must be NULL too.
  DCHECK(cookie_store || !channel_id_service);
  cookie_store_ = std::move(cookie_store);
  channel_id_service_ = std::move(channel_id_service);
}

void URLRequestContextBuilder::SetFileTaskRunner(
    const scoped_refptr<base::SingleThreadTaskRunner>& task_runner) {
  file_task_runner_ = task_runner;
}

void URLRequestContextBuilder::SetProtocolHandler(
    const std::string& scheme,
    std::unique_ptr<URLRequestJobFactory::ProtocolHandler> protocol_handler) {
  DCHECK(protocol_handler);
  protocol_handlers_[scheme] = std::move(protocol_handler);
}

void URLRequestContextBuilder::SetHttpAuthHandlerFactory(
    std::unique_ptr<HttpAuthHandlerFactory> factory) {
  http_auth_handler_factory_ = std::move(factory);
}

void URLRequestContextBuilder::SetHttpServerProperties(
    std::unique_ptr<HttpServerProperties> http_server_properties) {
  http_server_properties_ = std::move(http_server_properties);
}

std::unique_ptr<URLRequestContext> URLRequestContextBuilder::Build() {
  std::unique_ptr<ContainerURLRequestContext> context(
      new ContainerURLRequestContext(file_task_runner_));
  URLRequestContextStorage* storage = context->storage();

  context->set_name(name_);
  context->set_enable_brotli(enable_brotli_);
  context->set_network_quality_estimator(network_quality_estimator_);

  storage->set_http_user_agent_settings(
      base::MakeUnique<StaticHttpUserAgentSettings>(accept_language_,
                                                    user_agent_));

  if (!network_delegate_)
    network_delegate_.reset(new BasicNetworkDelegate);
  storage->set_network_delegate(std::move(network_delegate_));

  if (net_log_) {
    // Unlike the other builder parameters, |net_log_| is not owned by the
    // builder or resulting context.
    context->set_net_log(net_log_);
  } else {
    storage->set_net_log(base::WrapUnique(new NetLog));
  }

  if (!host_resolver_) {
    host_resolver_ = HostResolver::CreateDefaultResolver(context->net_log());
  }
  storage->set_host_resolver(std::move(host_resolver_));

  if (ssl_config_service_) {
    // This takes a raw pointer, but |storage| will hold onto a reference to the
    // service.
    storage->set_ssl_config_service(ssl_config_service_.get());
  } else {
    storage->set_ssl_config_service(new SSLConfigServiceDefaults);
  }

  if (!http_auth_handler_factory_) {
    http_auth_handler_factory_ =
        HttpAuthHandlerRegistryFactory::CreateDefault(context->host_resolver());
  }

  storage->set_http_auth_handler_factory(std::move(http_auth_handler_factory_));

  if (cookie_store_set_by_client_) {
    storage->set_cookie_store(std::move(cookie_store_));
    storage->set_channel_id_service(std::move(channel_id_service_));
  } else {
    std::unique_ptr<CookieStore> cookie_store(
        new CookieMonster(nullptr, nullptr));
    std::unique_ptr<ChannelIDService> channel_id_service(
        new ChannelIDService(new DefaultChannelIDStore(NULL)));
    cookie_store->SetChannelIDServiceID(channel_id_service->GetUniqueID());
    storage->set_cookie_store(std::move(cookie_store));
    storage->set_channel_id_service(std::move(channel_id_service));
  }

  if (sdch_enabled_) {
    storage->set_sdch_manager(
        std::unique_ptr<net::SdchManager>(new SdchManager()));
  }

  storage->set_transport_security_state(
      base::MakeUnique<TransportSecurityState>());
  if (!transport_security_persister_path_.empty()) {
    context->set_transport_security_persister(
        base::WrapUnique<TransportSecurityPersister>(
            new TransportSecurityPersister(context->transport_security_state(),
                                           transport_security_persister_path_,
                                           context->GetFileTaskRunner(),
                                           false)));
  }

  if (http_server_properties_) {
    storage->set_http_server_properties(std::move(http_server_properties_));
  } else {
    storage->set_http_server_properties(
        std::unique_ptr<HttpServerProperties>(new HttpServerPropertiesImpl()));
  }

  if (cert_verifier_) {
    storage->set_cert_verifier(std::move(cert_verifier_));
  } else {
    storage->set_cert_verifier(CertVerifier::CreateDefault());
  }

  if (ct_verifier_) {
    storage->set_cert_transparency_verifier(std::move(ct_verifier_));
  } else {
    std::unique_ptr<MultiLogCTVerifier> ct_verifier =
        base::MakeUnique<MultiLogCTVerifier>();
    ct_verifier->AddLogs(ct::CreateLogVerifiersForKnownLogs());
    storage->set_cert_transparency_verifier(std::move(ct_verifier));
  }
  storage->set_ct_policy_enforcer(base::MakeUnique<CTPolicyEnforcer>());

  if (throttling_enabled_) {
    storage->set_throttler_manager(
        base::MakeUnique<URLRequestThrottlerManager>());
  }

  if (!proxy_service_) {
#if !defined(OS_LINUX) && !defined(OS_ANDROID)
    // TODO(willchan): Switch to using this code when
    // ProxyService::CreateSystemProxyConfigService()'s signature doesn't suck.
    if (!proxy_config_service_) {
      proxy_config_service_ = ProxyService::CreateSystemProxyConfigService(
          base::ThreadTaskRunnerHandle::Get().get(),
          context->GetFileTaskRunner());
    }
#endif  // !defined(OS_LINUX) && !defined(OS_ANDROID)
    proxy_service_ =
        CreateProxyService(std::move(proxy_config_service_), context.get(),
                           context->host_resolver(),
                           context->network_delegate(), context->net_log());
    proxy_service_->set_quick_check_enabled(pac_quick_check_enabled_);
    proxy_service_->set_sanitize_url_policy(pac_sanitize_url_policy_);
  }
  storage->set_proxy_service(std::move(proxy_service_));

  HttpNetworkSession::Context network_session_context;
  SetHttpNetworkSessionComponents(context.get(), &network_session_context);

  if (proxy_delegate_) {
    network_session_context.proxy_delegate = proxy_delegate_.get();
    storage->set_proxy_delegate(std::move(proxy_delegate_));
  }

  storage->set_http_network_session(base::MakeUnique<HttpNetworkSession>(
      http_network_session_params_, network_session_context));

  std::unique_ptr<HttpTransactionFactory> http_transaction_factory;
  if (http_cache_enabled_) {
    std::unique_ptr<HttpCache::BackendFactory> http_cache_backend;
    if (http_cache_params_.type != HttpCacheParams::IN_MEMORY) {
      BackendType backend_type =
          http_cache_params_.type == HttpCacheParams::DISK
              ? CACHE_BACKEND_DEFAULT
              : CACHE_BACKEND_SIMPLE;
      http_cache_backend.reset(new HttpCache::DefaultBackend(
          DISK_CACHE, backend_type, http_cache_params_.path,
          http_cache_params_.max_size, context->GetFileTaskRunner()));
    } else {
      http_cache_backend =
          HttpCache::DefaultBackend::InMemory(http_cache_params_.max_size);
    }

    http_transaction_factory.reset(new HttpCache(
        storage->http_network_session(), std::move(http_cache_backend), true));
  } else {
    http_transaction_factory.reset(
        new HttpNetworkLayer(storage->http_network_session()));
  }
  storage->set_http_transaction_factory(std::move(http_transaction_factory));

  URLRequestJobFactoryImpl* job_factory = new URLRequestJobFactoryImpl;
  // Adds caller-provided protocol handlers first so that these handlers are
  // used over data/file/ftp handlers below.
  for (auto& scheme_handler : protocol_handlers_) {
    job_factory->SetProtocolHandler(scheme_handler.first,
                                    std::move(scheme_handler.second));
  }
  protocol_handlers_.clear();

  if (data_enabled_)
    job_factory->SetProtocolHandler(url::kDataScheme,
                                    base::WrapUnique(new DataProtocolHandler));

#if !BUILDFLAG(DISABLE_FILE_SUPPORT)
  if (file_enabled_) {
    job_factory->SetProtocolHandler(
        url::kFileScheme,
        base::MakeUnique<FileProtocolHandler>(context->GetFileTaskRunner()));
  }
#endif  // !BUILDFLAG(DISABLE_FILE_SUPPORT)

#if !BUILDFLAG(DISABLE_FTP_SUPPORT)
  if (ftp_enabled_) {
    job_factory->SetProtocolHandler(
        url::kFtpScheme, FtpProtocolHandler::Create(context->host_resolver()));
  }
#endif  // !BUILDFLAG(DISABLE_FTP_SUPPORT)

  std::unique_ptr<net::URLRequestJobFactory> top_job_factory(job_factory);
  if (!url_request_interceptors_.empty()) {
    // Set up interceptors in the reverse order.

    for (auto i = url_request_interceptors_.rbegin();
         i != url_request_interceptors_.rend(); ++i) {
      top_job_factory.reset(new net::URLRequestInterceptingJobFactory(
          std::move(top_job_factory), std::move(*i)));
    }
    url_request_interceptors_.clear();
  }
  storage->set_job_factory(std::move(top_job_factory));

  if (reporting_policy_) {
    storage->set_reporting_service(
        ReportingService::Create(*reporting_policy_, context.get()));
  }

  return std::move(context);
}

std::unique_ptr<ProxyService> URLRequestContextBuilder::CreateProxyService(
    std::unique_ptr<ProxyConfigService> proxy_config_service,
    URLRequestContext* url_request_context,
    HostResolver* host_resolver,
    NetworkDelegate* network_delegate,
    NetLog* net_log) {
  return ProxyService::CreateUsingSystemProxyResolver(
      std::move(proxy_config_service), net_log);
}

}  // namespace net
