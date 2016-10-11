// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/proxy/proxy_resolver_factory_mojo.h"

#include <set>
#include <utility>

#include "base/bind.h"
#include "base/callback.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/stl_util.h"
#include "base/threading/thread_checker.h"
#include "base/values.h"
#include "mojo/common/common_type_converters.h"
#include "mojo/public/cpp/bindings/binding.h"
#include "net/base/load_states.h"
#include "net/base/net_errors.h"
#include "net/dns/mojo_host_resolver_impl.h"
#include "net/interfaces/host_resolver_service.mojom.h"
#include "net/interfaces/proxy_resolver_service.mojom.h"
#include "net/log/net_log.h"
#include "net/log/net_log_capture_mode.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_with_source.h"
#include "net/proxy/mojo_proxy_resolver_factory.h"
#include "net/proxy/mojo_proxy_type_converters.h"
#include "net/proxy/proxy_info.h"
#include "net/proxy/proxy_resolver.h"
#include "net/proxy/proxy_resolver_error_observer.h"
#include "net/proxy/proxy_resolver_script_data.h"

namespace net {

namespace {

std::unique_ptr<base::Value> NetLogErrorCallback(
    int line_number,
    const base::string16* message,
    NetLogCaptureMode /* capture_mode */) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetInteger("line_number", line_number);
  dict->SetString("message", *message);
  return std::move(dict);
}

// A mixin that forwards logging to (Bound)NetLog and ProxyResolverErrorObserver
// and DNS requests to a MojoHostResolverImpl, which is implemented in terms of
// a HostResolver.
template <typename ClientInterface>
class ClientMixin : public ClientInterface {
 public:
  ClientMixin(HostResolver* host_resolver,
              ProxyResolverErrorObserver* error_observer,
              NetLog* net_log,
              const NetLogWithSource& net_log_with_source)
      : host_resolver_(host_resolver, net_log_with_source),
        error_observer_(error_observer),
        net_log_(net_log),
        net_log_with_source_(net_log_with_source) {}

  // Overridden from ClientInterface:
  void Alert(const mojo::String& message) override {
    base::string16 message_str = message.To<base::string16>();
    auto callback = NetLog::StringCallback("message", &message_str);
    net_log_with_source_.AddEvent(NetLogEventType::PAC_JAVASCRIPT_ALERT,
                                  callback);
    if (net_log_)
      net_log_->AddGlobalEntry(NetLogEventType::PAC_JAVASCRIPT_ALERT, callback);
  }

  void OnError(int32_t line_number, const mojo::String& message) override {
    base::string16 message_str = message.To<base::string16>();
    auto callback = base::Bind(&NetLogErrorCallback, line_number, &message_str);
    net_log_with_source_.AddEvent(NetLogEventType::PAC_JAVASCRIPT_ERROR,
                                  callback);
    if (net_log_)
      net_log_->AddGlobalEntry(NetLogEventType::PAC_JAVASCRIPT_ERROR, callback);
    if (error_observer_)
      error_observer_->OnPACScriptError(line_number, message_str);
  }

  void ResolveDns(interfaces::HostResolverRequestInfoPtr request_info,
                  interfaces::HostResolverRequestClientPtr client) override {
    host_resolver_.Resolve(std::move(request_info), std::move(client));
  }

 protected:
  bool dns_request_in_progress() {
    return host_resolver_.request_in_progress();
  }

 private:
  MojoHostResolverImpl host_resolver_;
  ProxyResolverErrorObserver* const error_observer_;
  NetLog* const net_log_;
  const NetLogWithSource net_log_with_source_;
};

// Implementation of ProxyResolver that connects to a Mojo service to evaluate
// PAC scripts. This implementation only knows about Mojo services, and
// therefore that service may live in or out of process.
//
// This implementation reports disconnections from the Mojo service (i.e. if the
// service is out-of-process and that process crashes) using the error code
// ERR_PAC_SCRIPT_TERMINATED.
class ProxyResolverMojo : public ProxyResolver {
 public:
  // Constructs a ProxyResolverMojo that connects to a mojo proxy resolver
  // implementation using |resolver_ptr|. The implementation uses
  // |host_resolver| as the DNS resolver, using |host_resolver_binding| to
  // communicate with it. When deleted, the closure contained within
  // |on_delete_callback_runner| will be run.
  ProxyResolverMojo(
      interfaces::ProxyResolverPtr resolver_ptr,
      HostResolver* host_resolver,
      std::unique_ptr<base::ScopedClosureRunner> on_delete_callback_runner,
      std::unique_ptr<ProxyResolverErrorObserver> error_observer,
      NetLog* net_log);
  ~ProxyResolverMojo() override;

  // ProxyResolver implementation:
  int GetProxyForURL(const GURL& url,
                     ProxyInfo* results,
                     const net::CompletionCallback& callback,
                     RequestHandle* request,
                     const NetLogWithSource& net_log) override;
  void CancelRequest(RequestHandle request) override;
  LoadState GetLoadState(RequestHandle request) const override;

 private:
  class Job;

  // Mojo error handler.
  void OnConnectionError();

  void RemoveJob(Job* job);

  // Connection to the Mojo proxy resolver.
  interfaces::ProxyResolverPtr mojo_proxy_resolver_ptr_;

  HostResolver* host_resolver_;

  std::unique_ptr<ProxyResolverErrorObserver> error_observer_;

  NetLog* net_log_;

  std::set<Job*> pending_jobs_;

  base::ThreadChecker thread_checker_;

  std::unique_ptr<base::ScopedClosureRunner> on_delete_callback_runner_;

  DISALLOW_COPY_AND_ASSIGN(ProxyResolverMojo);
};

class ProxyResolverMojo::Job
    : public ClientMixin<interfaces::ProxyResolverRequestClient> {
 public:
  Job(ProxyResolverMojo* resolver,
      const GURL& url,
      ProxyInfo* results,
      const CompletionCallback& callback,
      const NetLogWithSource& net_log);
  ~Job() override;

  // Cancels the job and prevents the callback from being run.
  void Cancel();

  // Returns the LoadState of this job.
  LoadState GetLoadState();

 private:
  // Mojo error handler.
  void OnConnectionError();

  // Overridden from interfaces::ProxyResolverRequestClient:
  void ReportResult(
      int32_t error,
      mojo::Array<interfaces::ProxyServerPtr> proxy_servers) override;

  ProxyResolverMojo* resolver_;
  const GURL url_;
  ProxyInfo* results_;
  CompletionCallback callback_;

  base::ThreadChecker thread_checker_;
  mojo::Binding<interfaces::ProxyResolverRequestClient> binding_;
};

ProxyResolverMojo::Job::Job(ProxyResolverMojo* resolver,
                            const GURL& url,
                            ProxyInfo* results,
                            const CompletionCallback& callback,
                            const NetLogWithSource& net_log)
    : ClientMixin<interfaces::ProxyResolverRequestClient>(
          resolver->host_resolver_,
          resolver->error_observer_.get(),
          resolver->net_log_,
          net_log),
      resolver_(resolver),
      url_(url),
      results_(results),
      callback_(callback),
      binding_(this) {
  resolver_->mojo_proxy_resolver_ptr_->GetProxyForUrl(
      url_, binding_.CreateInterfacePtrAndBind());
  binding_.set_connection_error_handler(base::Bind(
      &ProxyResolverMojo::Job::OnConnectionError, base::Unretained(this)));
}

ProxyResolverMojo::Job::~Job() {
  DCHECK(thread_checker_.CalledOnValidThread());
  if (!callback_.is_null())
    callback_.Run(ERR_PAC_SCRIPT_TERMINATED);
}

void ProxyResolverMojo::Job::Cancel() {
  DCHECK(thread_checker_.CalledOnValidThread());
  DCHECK(!callback_.is_null());
  callback_.Reset();
}

LoadState ProxyResolverMojo::Job::GetLoadState() {
  return dns_request_in_progress() ? LOAD_STATE_RESOLVING_HOST_IN_PROXY_SCRIPT
                                   : LOAD_STATE_RESOLVING_PROXY_FOR_URL;
}

void ProxyResolverMojo::Job::OnConnectionError() {
  DCHECK(thread_checker_.CalledOnValidThread());
  DVLOG(1) << "ProxyResolverMojo::Job::OnConnectionError";
  resolver_->RemoveJob(this);
}

void ProxyResolverMojo::Job::ReportResult(
    int32_t error,
    mojo::Array<interfaces::ProxyServerPtr> proxy_servers) {
  DCHECK(thread_checker_.CalledOnValidThread());
  DVLOG(1) << "ProxyResolverMojo::Job::ReportResult: " << error;

  if (error == OK) {
    *results_ = proxy_servers.To<ProxyInfo>();
    DVLOG(1) << "Servers: " << results_->ToPacString();
  }

  CompletionCallback callback = callback_;
  callback_.Reset();
  resolver_->RemoveJob(this);
  callback.Run(error);
}

ProxyResolverMojo::ProxyResolverMojo(
    interfaces::ProxyResolverPtr resolver_ptr,
    HostResolver* host_resolver,
    std::unique_ptr<base::ScopedClosureRunner> on_delete_callback_runner,
    std::unique_ptr<ProxyResolverErrorObserver> error_observer,
    NetLog* net_log)
    : mojo_proxy_resolver_ptr_(std::move(resolver_ptr)),
      host_resolver_(host_resolver),
      error_observer_(std::move(error_observer)),
      net_log_(net_log),
      on_delete_callback_runner_(std::move(on_delete_callback_runner)) {
  mojo_proxy_resolver_ptr_.set_connection_error_handler(base::Bind(
      &ProxyResolverMojo::OnConnectionError, base::Unretained(this)));
}

ProxyResolverMojo::~ProxyResolverMojo() {
  DCHECK(thread_checker_.CalledOnValidThread());
  // All pending requests should have been cancelled.
  DCHECK(pending_jobs_.empty());
}

void ProxyResolverMojo::OnConnectionError() {
  DCHECK(thread_checker_.CalledOnValidThread());
  DVLOG(1) << "ProxyResolverMojo::OnConnectionError";

  // Disconnect from the Mojo proxy resolver service.
  mojo_proxy_resolver_ptr_.reset();
}

void ProxyResolverMojo::RemoveJob(Job* job) {
  DCHECK(thread_checker_.CalledOnValidThread());
  size_t num_erased = pending_jobs_.erase(job);
  DCHECK(num_erased);
  delete job;
}

int ProxyResolverMojo::GetProxyForURL(const GURL& url,
                                      ProxyInfo* results,
                                      const CompletionCallback& callback,
                                      RequestHandle* request,
                                      const NetLogWithSource& net_log) {
  DCHECK(thread_checker_.CalledOnValidThread());

  if (!mojo_proxy_resolver_ptr_)
    return ERR_PAC_SCRIPT_TERMINATED;

  Job* job = new Job(this, url, results, callback, net_log);
  bool inserted = pending_jobs_.insert(job).second;
  DCHECK(inserted);
  *request = job;

  return ERR_IO_PENDING;
}

void ProxyResolverMojo::CancelRequest(RequestHandle request) {
  DCHECK(thread_checker_.CalledOnValidThread());
  Job* job = static_cast<Job*>(request);
  DCHECK(job);
  job->Cancel();
  RemoveJob(job);
}

LoadState ProxyResolverMojo::GetLoadState(RequestHandle request) const {
  Job* job = static_cast<Job*>(request);
  CHECK_EQ(1u, pending_jobs_.count(job));
  return job->GetLoadState();
}

}  // namespace

// A Job to create a ProxyResolver instance.
//
// Note: a Job instance is not tied to a particular resolve request, and hence
// there is no per-request logging to be done (any netlog events are only sent
// globally) so this always uses an empty NetLogWithSource.
class ProxyResolverFactoryMojo::Job
    : public ClientMixin<interfaces::ProxyResolverFactoryRequestClient>,
      public ProxyResolverFactory::Request {
 public:
  Job(ProxyResolverFactoryMojo* factory,
      const scoped_refptr<ProxyResolverScriptData>& pac_script,
      std::unique_ptr<ProxyResolver>* resolver,
      const CompletionCallback& callback,
      std::unique_ptr<ProxyResolverErrorObserver> error_observer)
      : ClientMixin<interfaces::ProxyResolverFactoryRequestClient>(
            factory->host_resolver_,
            error_observer.get(),
            factory->net_log_,
            NetLogWithSource()),
        factory_(factory),
        resolver_(resolver),
        callback_(callback),
        binding_(this),
        error_observer_(std::move(error_observer)) {
    on_delete_callback_runner_ = factory_->mojo_proxy_factory_->CreateResolver(
        mojo::String::From(pac_script->utf16()), mojo::GetProxy(&resolver_ptr_),
        binding_.CreateInterfacePtrAndBind());
    resolver_ptr_.set_connection_error_handler(
        base::Bind(&ProxyResolverFactoryMojo::Job::OnConnectionError,
                   base::Unretained(this)));
    binding_.set_connection_error_handler(
        base::Bind(&ProxyResolverFactoryMojo::Job::OnConnectionError,
                   base::Unretained(this)));
  }

  void OnConnectionError() { ReportResult(ERR_PAC_SCRIPT_TERMINATED); }

 private:
  void ReportResult(int32_t error) override {
    resolver_ptr_.set_connection_error_handler(base::Closure());
    binding_.set_connection_error_handler(base::Closure());
    if (error == OK) {
      resolver_->reset(new ProxyResolverMojo(
          std::move(resolver_ptr_), factory_->host_resolver_,
          std::move(on_delete_callback_runner_), std::move(error_observer_),
          factory_->net_log_));
    }
    on_delete_callback_runner_.reset();
    callback_.Run(error);
  }

  ProxyResolverFactoryMojo* const factory_;
  std::unique_ptr<ProxyResolver>* resolver_;
  const CompletionCallback callback_;
  interfaces::ProxyResolverPtr resolver_ptr_;
  mojo::Binding<interfaces::ProxyResolverFactoryRequestClient> binding_;
  std::unique_ptr<base::ScopedClosureRunner> on_delete_callback_runner_;
  std::unique_ptr<ProxyResolverErrorObserver> error_observer_;
};

ProxyResolverFactoryMojo::ProxyResolverFactoryMojo(
    MojoProxyResolverFactory* mojo_proxy_factory,
    HostResolver* host_resolver,
    const base::Callback<std::unique_ptr<ProxyResolverErrorObserver>()>&
        error_observer_factory,
    NetLog* net_log)
    : ProxyResolverFactory(true),
      mojo_proxy_factory_(mojo_proxy_factory),
      host_resolver_(host_resolver),
      error_observer_factory_(error_observer_factory),
      net_log_(net_log) {}

ProxyResolverFactoryMojo::~ProxyResolverFactoryMojo() = default;

int ProxyResolverFactoryMojo::CreateProxyResolver(
    const scoped_refptr<ProxyResolverScriptData>& pac_script,
    std::unique_ptr<ProxyResolver>* resolver,
    const CompletionCallback& callback,
    std::unique_ptr<ProxyResolverFactory::Request>* request) {
  DCHECK(resolver);
  DCHECK(request);
  if (pac_script->type() != ProxyResolverScriptData::TYPE_SCRIPT_CONTENTS ||
      pac_script->utf16().empty()) {
    return ERR_PAC_SCRIPT_FAILED;
  }
  request->reset(new Job(this, pac_script, resolver, callback,
                         error_observer_factory_.is_null()
                             ? nullptr
                             : error_observer_factory_.Run()));
  return ERR_IO_PENDING;
}

}  // namespace net
