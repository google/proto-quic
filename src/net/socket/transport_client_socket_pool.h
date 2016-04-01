// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_SOCKET_TRANSPORT_CLIENT_SOCKET_POOL_H_
#define NET_SOCKET_TRANSPORT_CLIENT_SOCKET_POOL_H_

#include <string>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/scoped_ptr.h"
#include "base/time/time.h"
#include "base/timer/timer.h"
#include "net/base/host_port_pair.h"
#include "net/dns/host_resolver.h"
#include "net/dns/single_request_host_resolver.h"
#include "net/socket/client_socket_pool.h"
#include "net/socket/client_socket_pool_base.h"
#include "net/socket/connection_attempts.h"

namespace net {

class ClientSocketFactory;

typedef base::Callback<int(const AddressList&, const BoundNetLog& net_log)>
OnHostResolutionCallback;

class NET_EXPORT_PRIVATE TransportSocketParams
    : public base::RefCounted<TransportSocketParams> {
 public:
  // CombineConnectAndWrite currently translates to using TCP FastOpen.
  // TCP FastOpen should not be used if the first write to the socket may
  // be non-idempotent, as the underlying socket could retransmit the data
  // on failure of the first transmission.
  // NOTE: Currently, COMBINE_CONNECT_AND_WRITE_DESIRED is used if the data in
  // the write is known to be idempotent, and COMBINE_CONNECT_AND_WRITE_DEFAULT
  // is used as a default for other cases (including non-idempotent writes).
  enum CombineConnectAndWritePolicy {
    COMBINE_CONNECT_AND_WRITE_DEFAULT,    // Default policy, implemented in
                                          // TransportSocketParams constructor.
    COMBINE_CONNECT_AND_WRITE_DESIRED,    // Combine if supported by socket.
    COMBINE_CONNECT_AND_WRITE_PROHIBITED  // Do not combine.
  };

  // |host_resolution_callback| will be invoked after the the hostname is
  // resolved.  If |host_resolution_callback| does not return OK, then the
  // connection will be aborted with that value. |combine_connect_and_write|
  // defines the policy for use of TCP FastOpen on this socket.
  TransportSocketParams(
      const HostPortPair& host_port_pair,
      bool disable_resolver_cache,
      const OnHostResolutionCallback& host_resolution_callback,
      CombineConnectAndWritePolicy combine_connect_and_write);

  const HostResolver::RequestInfo& destination() const { return destination_; }
  const OnHostResolutionCallback& host_resolution_callback() const {
    return host_resolution_callback_;
  }

  CombineConnectAndWritePolicy combine_connect_and_write() const {
    return combine_connect_and_write_;
  }

 private:
  friend class base::RefCounted<TransportSocketParams>;
  ~TransportSocketParams();

  HostResolver::RequestInfo destination_;
  const OnHostResolutionCallback host_resolution_callback_;
  CombineConnectAndWritePolicy combine_connect_and_write_;

  DISALLOW_COPY_AND_ASSIGN(TransportSocketParams);
};

// Common data and logic shared between TransportConnectJob and
// WebSocketTransportConnectJob.
class NET_EXPORT_PRIVATE TransportConnectJobHelper {
 public:
  enum State {
    STATE_RESOLVE_HOST,
    STATE_RESOLVE_HOST_COMPLETE,
    STATE_TRANSPORT_CONNECT,
    STATE_TRANSPORT_CONNECT_COMPLETE,
    STATE_NONE,
  };

  // For recording the connection time in the appropriate bucket.
  enum ConnectionLatencyHistogram {
    CONNECTION_LATENCY_UNKNOWN,
    CONNECTION_LATENCY_IPV4_WINS_RACE,
    CONNECTION_LATENCY_IPV4_NO_RACE,
    CONNECTION_LATENCY_IPV6_RACEABLE,
    CONNECTION_LATENCY_IPV6_SOLO,
  };

  TransportConnectJobHelper(const scoped_refptr<TransportSocketParams>& params,
                            ClientSocketFactory* client_socket_factory,
                            HostResolver* host_resolver,
                            LoadTimingInfo::ConnectTiming* connect_timing);
  ~TransportConnectJobHelper();

  ClientSocketFactory* client_socket_factory() {
    return client_socket_factory_;
  }

  const AddressList& addresses() const { return addresses_; }
  State next_state() const { return next_state_; }
  void set_next_state(State next_state) { next_state_ = next_state; }
  CompletionCallback on_io_complete() const { return on_io_complete_; }
  const TransportSocketParams* params() { return params_.get(); }

  int DoResolveHost(RequestPriority priority, const BoundNetLog& net_log);
  int DoResolveHostComplete(int result, const BoundNetLog& net_log);

  template <class T>
  int DoConnectInternal(T* job);

  template <class T>
  void SetOnIOComplete(T* job);

  template <class T>
  void OnIOComplete(T* job, int result);

  // Record the histograms Net.DNS_Resolution_And_TCP_Connection_Latency2 and
  // Net.TCP_Connection_Latency and return the connect duration.
  base::TimeDelta HistogramDuration(ConnectionLatencyHistogram race_result);

  static const int kIPv6FallbackTimerInMs;

 private:
  template <class T>
  int DoLoop(T* job, int result);

  scoped_refptr<TransportSocketParams> params_;
  ClientSocketFactory* const client_socket_factory_;
  SingleRequestHostResolver resolver_;
  AddressList addresses_;
  State next_state_;
  CompletionCallback on_io_complete_;
  LoadTimingInfo::ConnectTiming* connect_timing_;

  DISALLOW_COPY_AND_ASSIGN(TransportConnectJobHelper);
};

// TransportConnectJob handles the host resolution necessary for socket creation
// and the transport (likely TCP) connect. TransportConnectJob also has fallback
// logic for IPv6 connect() timeouts (which may happen due to networks / routers
// with broken IPv6 support). Those timeouts take 20s, so rather than make the
// user wait 20s for the timeout to fire, we use a fallback timer
// (kIPv6FallbackTimerInMs) and start a connect() to a IPv4 address if the timer
// fires. Then we race the IPv4 connect() against the IPv6 connect() (which has
// a headstart) and return the one that completes first to the socket pool.
class NET_EXPORT_PRIVATE TransportConnectJob : public ConnectJob {
 public:
  TransportConnectJob(const std::string& group_name,
                      RequestPriority priority,
                      ClientSocketPool::RespectLimits respect_limits,
                      const scoped_refptr<TransportSocketParams>& params,
                      base::TimeDelta timeout_duration,
                      ClientSocketFactory* client_socket_factory,
                      HostResolver* host_resolver,
                      Delegate* delegate,
                      NetLog* net_log);
  ~TransportConnectJob() override;

  // ConnectJob methods.
  LoadState GetLoadState() const override;
  void GetAdditionalErrorState(ClientSocketHandle* handle) override;

  // Rolls |addrlist| forward until the first IPv4 address, if any.
  // WARNING: this method should only be used to implement the prefer-IPv4 hack.
  static void MakeAddressListStartWithIPv4(AddressList* addrlist);

 private:
  enum ConnectInterval {
    CONNECT_INTERVAL_LE_10MS,
    CONNECT_INTERVAL_LE_20MS,
    CONNECT_INTERVAL_GT_20MS,
  };

  friend class TransportConnectJobHelper;

  int DoResolveHost();
  int DoResolveHostComplete(int result);
  int DoTransportConnect();
  int DoTransportConnectComplete(int result);

  // Not part of the state machine.
  void DoIPv6FallbackTransportConnect();
  void DoIPv6FallbackTransportConnectComplete(int result);

  // Begins the host resolution and the TCP connect.  Returns OK on success
  // and ERR_IO_PENDING if it cannot immediately service the request.
  // Otherwise, it returns a net error code.
  int ConnectInternal() override;

  void CopyConnectionAttemptsFromSockets();

  TransportConnectJobHelper helper_;

  scoped_ptr<StreamSocket> transport_socket_;

  scoped_ptr<StreamSocket> fallback_transport_socket_;
  scoped_ptr<AddressList> fallback_addresses_;
  base::TimeTicks fallback_connect_start_time_;
  base::OneShotTimer fallback_timer_;

  // Track the interval between this connect and previous connect.
  ConnectInterval interval_between_connects_;

  int resolve_result_;

  // Used in the failure case to save connection attempts made on the main and
  // fallback sockets and pass them on in |GetAdditionalErrorState|. (In the
  // success case, connection attempts are passed through the returned socket;
  // attempts are copied from the other socket, if one exists, into it before
  // it is returned.)
  ConnectionAttempts connection_attempts_;
  ConnectionAttempts fallback_connection_attempts_;

  DISALLOW_COPY_AND_ASSIGN(TransportConnectJob);
};

class NET_EXPORT_PRIVATE TransportClientSocketPool : public ClientSocketPool {
 public:
  typedef TransportSocketParams SocketParams;

  TransportClientSocketPool(
      int max_sockets,
      int max_sockets_per_group,
      HostResolver* host_resolver,
      ClientSocketFactory* client_socket_factory,
      NetLog* net_log);

  ~TransportClientSocketPool() override;

  // ClientSocketPool implementation.
  int RequestSocket(const std::string& group_name,
                    const void* resolve_info,
                    RequestPriority priority,
                    RespectLimits respect_limits,
                    ClientSocketHandle* handle,
                    const CompletionCallback& callback,
                    const BoundNetLog& net_log) override;
  void RequestSockets(const std::string& group_name,
                      const void* params,
                      int num_sockets,
                      const BoundNetLog& net_log) override;
  void CancelRequest(const std::string& group_name,
                     ClientSocketHandle* handle) override;
  void ReleaseSocket(const std::string& group_name,
                     scoped_ptr<StreamSocket> socket,
                     int id) override;
  void FlushWithError(int error) override;
  void CloseIdleSockets() override;
  int IdleSocketCount() const override;
  int IdleSocketCountInGroup(const std::string& group_name) const override;
  LoadState GetLoadState(const std::string& group_name,
                         const ClientSocketHandle* handle) const override;
  scoped_ptr<base::DictionaryValue> GetInfoAsValue(
      const std::string& name,
      const std::string& type,
      bool include_nested_pools) const override;
  base::TimeDelta ConnectionTimeout() const override;

  // HigherLayeredPool implementation.
  bool IsStalled() const override;
  void AddHigherLayeredPool(HigherLayeredPool* higher_pool) override;
  void RemoveHigherLayeredPool(HigherLayeredPool* higher_pool) override;

 protected:
  // Methods shared with WebSocketTransportClientSocketPool
  void NetLogTcpClientSocketPoolRequestedSocket(
      const BoundNetLog& net_log,
      const scoped_refptr<TransportSocketParams>* casted_params);

 private:
  typedef ClientSocketPoolBase<TransportSocketParams> PoolBase;

  class TransportConnectJobFactory
      : public PoolBase::ConnectJobFactory {
   public:
    TransportConnectJobFactory(ClientSocketFactory* client_socket_factory,
                         HostResolver* host_resolver,
                         NetLog* net_log)
        : client_socket_factory_(client_socket_factory),
          host_resolver_(host_resolver),
          net_log_(net_log) {}

    ~TransportConnectJobFactory() override {}

    // ClientSocketPoolBase::ConnectJobFactory methods.

    scoped_ptr<ConnectJob> NewConnectJob(
        const std::string& group_name,
        const PoolBase::Request& request,
        ConnectJob::Delegate* delegate) const override;

    base::TimeDelta ConnectionTimeout() const override;

   private:
    ClientSocketFactory* const client_socket_factory_;
    HostResolver* const host_resolver_;
    NetLog* net_log_;

    DISALLOW_COPY_AND_ASSIGN(TransportConnectJobFactory);
  };

  PoolBase base_;

  DISALLOW_COPY_AND_ASSIGN(TransportClientSocketPool);
};

template <class T>
int TransportConnectJobHelper::DoConnectInternal(T* job) {
  next_state_ = STATE_RESOLVE_HOST;
  return this->DoLoop(job, OK);
}

template <class T>
void TransportConnectJobHelper::SetOnIOComplete(T* job) {
  // These usages of base::Unretained() are safe because IO callbacks are
  // guaranteed not to be called after the object is destroyed.
  on_io_complete_ = base::Bind(&TransportConnectJobHelper::OnIOComplete<T>,
                               base::Unretained(this),
                               base::Unretained(job));
}

template <class T>
void TransportConnectJobHelper::OnIOComplete(T* job, int result) {
  result = this->DoLoop(job, result);
  if (result != ERR_IO_PENDING)
    job->NotifyDelegateOfCompletion(result);  // Deletes |job| and |this|
}

template <class T>
int TransportConnectJobHelper::DoLoop(T* job, int result) {
  DCHECK_NE(next_state_, STATE_NONE);

  int rv = result;
  do {
    State state = next_state_;
    next_state_ = STATE_NONE;
    switch (state) {
      case STATE_RESOLVE_HOST:
        DCHECK_EQ(OK, rv);
        rv = job->DoResolveHost();
        break;
      case STATE_RESOLVE_HOST_COMPLETE:
        rv = job->DoResolveHostComplete(rv);
        break;
      case STATE_TRANSPORT_CONNECT:
        DCHECK_EQ(OK, rv);
        rv = job->DoTransportConnect();
        break;
      case STATE_TRANSPORT_CONNECT_COMPLETE:
        rv = job->DoTransportConnectComplete(rv);
        break;
      default:
        NOTREACHED();
        rv = ERR_FAILED;
        break;
    }
  } while (rv != ERR_IO_PENDING && next_state_ != STATE_NONE);

  return rv;
}

}  // namespace net

#endif  // NET_SOCKET_TRANSPORT_CLIENT_SOCKET_POOL_H_
