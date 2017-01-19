// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// NOTE: No header guards are used, since this file is intended to be expanded
// directly into net_log.h. DO NOT include this file anywhere else.

// In the event of a failure, a many end events will have a |net_error|
// parameter with the integer error code associated with the failure.  Most
// of these parameters are not individually documented.

// --------------------------------------------------------------------------
// General pseudo-events
// --------------------------------------------------------------------------

// Something got cancelled (we determine what is cancelled based on the
// log context around it.)
EVENT_TYPE(CANCELLED)

// Something failed (we determine what failed based on the log context
// around it.)
// The event has the following parameters:
//
//   {
//     "net_error": <The net error code integer for the failure>,
//   }
EVENT_TYPE(FAILED)

// Marks the creation/destruction of a request (net::URLRequest).
EVENT_TYPE(REQUEST_ALIVE)

// ------------------------------------------------------------------------
// HostResolverImpl
// ------------------------------------------------------------------------

// The start/end of a host resolve (DNS) request.  Note that these events are
// logged for all DNS requests, though not all requests result in the creation
// of a HostResolvedImpl::Request object.
//
// The BEGIN phase contains the following parameters:
//
//   {
//     "host": <Hostname associated with the request>,
//     "address_family": <The address family to restrict results to>,
//     "allow_cached_response": <Whether it is ok to return a result from
//                               the host cache>,
//     "is_speculative": <Whether this request was started by the DNS
//                        prefetcher>
//   }
//
// If an error occurred, the END phase will contain these parameters:
//   {
//     "net_error": <The net error code integer for the failure>,
//   }
EVENT_TYPE(HOST_RESOLVER_IMPL_REQUEST)

// This event is created (in a source of the same name) when the host resolver
// creates a UDP socket to check for global IPv6 connectivity.
// It contains the following parameter:
//
//   {
//     "ipv6_available": <True if the probe indicates ipv6 connectivity>,
//   }
EVENT_TYPE(HOST_RESOLVER_IMPL_IPV6_REACHABILITY_CHECK)

// This event is logged when a request is handled by a cache entry.
EVENT_TYPE(HOST_RESOLVER_IMPL_CACHE_HIT)

// This event is logged when a request is handled by a HOSTS entry.
EVENT_TYPE(HOST_RESOLVER_IMPL_HOSTS_HIT)

// This event is created when a new HostResolverImpl::Job is about to be created
// for a request.
EVENT_TYPE(HOST_RESOLVER_IMPL_CREATE_JOB)

// The creation/completion of a HostResolverImpl::Job which is created for
// Requests that cannot be resolved synchronously.
//
// The BEGIN phase contains the following parameters:
//
//   {
//     "host": <Hostname associated with the request>,
//     "source_dependency": <Source id, if any, of what created the request>,
//   }
//
// On success, the END phase has these parameters:
//   {
//     "address_list": <The host name being resolved>,
//   }
// If an error occurred, the END phase will contain these parameters:
//   {
//     "net_error": <The net error code integer for the failure>,
//   }
EVENT_TYPE(HOST_RESOLVER_IMPL_JOB)

// This event is created when a HostResolverImpl::Job is evicted from
// PriorityDispatch before it can start, because the limit on number of queued
// Jobs was reached.
EVENT_TYPE(HOST_RESOLVER_IMPL_JOB_EVICTED)

// This event is created when a HostResolverImpl::Job is started by
// PriorityDispatch.
EVENT_TYPE(HOST_RESOLVER_IMPL_JOB_STARTED)

// This event is created when HostResolverImpl::ProcJob is about to start a new
// attempt to resolve the host.
//
// The ATTEMPT_STARTED event has the parameters:
//
//   {
//     "attempt_number": <the number of the attempt that is resolving the host>,
//   }
EVENT_TYPE(HOST_RESOLVER_IMPL_ATTEMPT_STARTED)

// This event is created when HostResolverImpl::ProcJob has finished resolving
// the host.
//
// The ATTEMPT_FINISHED event has the parameters:
//
//   {
//     "attempt_number": <the number of the attempt that has resolved the host>,
//   }
// If an error occurred, the END phase will contain these additional parameters:
//   {
//     "net_error": <The net error code integer for the failure>,
//     "os_error": <The exact error code integer that getaddrinfo() returned>,
//   }
EVENT_TYPE(HOST_RESOLVER_IMPL_ATTEMPT_FINISHED)

// This is logged for a request when it's attached to a
// HostResolverImpl::Job. When this occurs without a preceding
// HOST_RESOLVER_IMPL_CREATE_JOB entry, it means the request was attached to an
// existing HostResolverImpl::Job.
//
// The event contains the following parameters:
//
//   {
//     "source_dependency": <Source identifier for the attached Job>,
//   }
//
EVENT_TYPE(HOST_RESOLVER_IMPL_JOB_ATTACH)

// This event is logged for the job to which the request is attached.
// In that case, the event contains the following parameters:
//
//   {
//     "source_dependency": <Source identifier for the attached Request>,
//     "priority": <New priority of the job>,
//   }
EVENT_TYPE(HOST_RESOLVER_IMPL_JOB_REQUEST_ATTACH)

// This is logged for a job when a request is cancelled and detached.
//
// The event contains the following parameters:
//
//   {
//     "source_dependency": <Source identifier for the detached Request>,
//     "priority": <New priority of the job>,
//   }
EVENT_TYPE(HOST_RESOLVER_IMPL_JOB_REQUEST_DETACH)

// The creation/completion of a HostResolverImpl::ProcTask to call getaddrinfo.
// The BEGIN phase contains the following parameters:
//
//   {
//     "hostname": <Hostname associated with the request>,
//   }
//
// On success, the END phase has these parameters:
//   {
//     "address_list": <The resolved addresses>,
//   }
// If an error occurred, the END phase will contain these parameters:
//   {
//     "net_error": <The net error code integer for the failure>,
//     "os_error": <The exact error code integer that getaddrinfo() returned>,
//   }
EVENT_TYPE(HOST_RESOLVER_IMPL_PROC_TASK)

// The creation/completion of a HostResolverImpl::DnsTask to manage a
// DnsTransaction. The BEGIN phase contains the following parameters:
//
//   {
//     "source_dependency": <Source id of DnsTransaction>,
//   }
//
// On success, the END phase has these parameters:
//   {
//     "address_list": <The resolved addresses>,
//   }
// If an error occurred, the END phase will contain these parameters:
//   {
//     "net_error": <The net error code integer for the failure>,
//     "dns_error": <The detailed DnsResponse::Result>
//   }
EVENT_TYPE(HOST_RESOLVER_IMPL_DNS_TASK)

// ------------------------------------------------------------------------
// InitProxyResolver
// ------------------------------------------------------------------------

// The start/end of auto-detect + custom PAC URL configuration.
EVENT_TYPE(PROXY_SCRIPT_DECIDER)

// The start/end of when proxy autoconfig was artificially paused following
// a network change event. (We wait some amount of time after being told of
// network changes to avoid hitting spurious errors during auto-detect).
EVENT_TYPE(PROXY_SCRIPT_DECIDER_WAIT)

// The start/end of download of a PAC script. This could be the well-known
// WPAD URL (if testing auto-detect), or a custom PAC URL.
//
// The START event has the parameters:
//   {
//     "source": <String describing where PAC script comes from>,
//   }
//
// If the fetch failed, then the END phase has these parameters:
//   {
//      "net_error": <Net error code integer>,
//   }
EVENT_TYPE(PROXY_SCRIPT_DECIDER_FETCH_PAC_SCRIPT)

// This event means that initialization failed because there was no
// configured script fetcher. (This indicates a configuration error).
EVENT_TYPE(PROXY_SCRIPT_DECIDER_HAS_NO_FETCHER)

// This event is emitted after deciding to fall-back to the next source
// of PAC scripts in the list.
EVENT_TYPE(PROXY_SCRIPT_DECIDER_FALLING_BACK_TO_NEXT_PAC_SOURCE)

// ------------------------------------------------------------------------
// ProxyService
// ------------------------------------------------------------------------

// The start/end of a proxy resolve request.
EVENT_TYPE(PROXY_SERVICE)

// The time while a request is waiting on InitProxyResolver to configure
// against either WPAD or custom PAC URL. The specifics on this time
// are found from ProxyService::init_proxy_resolver_log().
EVENT_TYPE(PROXY_SERVICE_WAITING_FOR_INIT_PAC)

// This event is emitted to show what the PAC script returned. It can contain
// extra parameters that are either:
//   {
//      "pac_string": <List of valid proxy servers, in PAC format>,
//   }
//
//  Or if the the resolver failed:
//   {
//      "net_error": <Net error code that resolver failed with>,
//   }
EVENT_TYPE(PROXY_SERVICE_RESOLVED_PROXY_LIST)

// This event is emitted after proxies marked as bad have been deprioritized.
//
// It contains these parameters:
//   {
//      "pac_string": <List of valid proxy servers, in PAC format>,
//   }
EVENT_TYPE(PROXY_SERVICE_DEPRIORITIZED_BAD_PROXIES)

// This event is emitted whenever the proxy settings used by ProxyService
// change.
//
// It contains these parameters:
//  {
//     "old_config": <Dump of the previous proxy settings>,
//     "new_config": <Dump of the new proxy settings>,
//  }
//
// Note that the "old_config" key will be omitted on the first fetch of the
// proxy settings (since there wasn't a previous value).
EVENT_TYPE(PROXY_CONFIG_CHANGED)

// Emitted when a list of bad proxies is reported to the proxy service.
//
// Parameters:
//   {
//     "bad_proxy_list": <List of bad proxies>,
//   }
EVENT_TYPE(BAD_PROXY_LIST_REPORTED)

// ------------------------------------------------------------------------
// ProxyList
// ------------------------------------------------------------------------

// Emitted when the first proxy server in a list is being marked as
// bad and proxy resolution is going to failover to the next one in
// the list.  The fallback is local to the request.
//
// Parameters:
//   {
//     "bad_proxy": <URI representation of the failed proxy server>,
//   }
EVENT_TYPE(PROXY_LIST_FALLBACK)

// ------------------------------------------------------------------------
// ProxyResolverV8Tracing
// ------------------------------------------------------------------------

// This event is emitted when a javascript error has been triggered by a
// PAC script. It contains the following event parameters:
//   {
//      "line_number": <The line number in the PAC script
//                      (or -1 if not applicable)>,
//      "message": <The error message>,
//   }
EVENT_TYPE(PAC_JAVASCRIPT_ERROR)

// This event is emitted when a PAC script called alert(). It contains the
// following event parameters:
//   {
//      "message": <The string of the alert>,
//   }
EVENT_TYPE(PAC_JAVASCRIPT_ALERT)

// ------------------------------------------------------------------------
// MultiThreadedProxyResolver
// ------------------------------------------------------------------------

// Measures the time that a proxy resolve request was stalled waiting for a
// proxy resolver thread to free-up.
EVENT_TYPE(WAITING_FOR_PROXY_RESOLVER_THREAD)

// This event is emitted just before a PAC request is bound to a thread. It
// contains these parameters:
//
//   {
//     "thread_number": <Identifier for the PAC thread that is going to
//                       run this request>,
//   }
EVENT_TYPE(SUBMITTED_TO_RESOLVER_THREAD)

// ------------------------------------------------------------------------
// Socket (Shared by stream and datagram sockets)
// ------------------------------------------------------------------------

// Marks the begin/end of a socket (TCP/SOCKS/SSL/UDP/"SpdyProxyClientSocket").
//
// The BEGIN phase contains the following parameters:
//
//   {
//     "source_dependency": <Source identifier for the controlling entity>,
//   }
EVENT_TYPE(SOCKET_ALIVE)

// ------------------------------------------------------------------------
// StreamSocket
// ------------------------------------------------------------------------

// The start/end of a TCP connect(). This corresponds with a call to
// TCPClientSocket::Connect().
//
// The START event contains these parameters:
//
//   {
//     "address_list": <List of network address strings>,
//   }
//
// And the END event will contain the following parameters:
//
//   {
//     "net_error": <Net integer error code, on error>,
//     "source_address": <Local source address of the connection, on success>,
//   }
EVENT_TYPE(TCP_CONNECT)

// Nested within TCP_CONNECT, there may be multiple attempts to connect
// to the individual addresses. The START event will describe the
// address the attempt is for:
//
//   {
//     "address": <String of the network address>,
//   }
//
// And the END event will contain the system error code if it failed:
//
//   {
//     "os_error": <Integer error code the operating system returned>,
//   }
EVENT_TYPE(TCP_CONNECT_ATTEMPT)

// The start/end of a TCP accept(). This corresponds with a call to
// TCPServerSocket::Accept().
//
// The END event will contain the following parameters on success:
//   {
//     "address": <Remote address of the accepted connection>,
//   }
// On failure it contains the following parameters
//   {
//     "net_error": <Net integer error code>,
//   }
EVENT_TYPE(TCP_ACCEPT)

// This event is logged to the socket stream whenever the socket is
// acquired/released via a ClientSocketHandle.
//
// The BEGIN phase contains the following parameters:
//
//   {
//     "source_dependency": <Source identifier for the controlling entity>,
//   }
EVENT_TYPE(SOCKET_IN_USE)

// The start/end of a SOCKS connect().
EVENT_TYPE(SOCKS_CONNECT)

// The start/end of a SOCKS5 connect().
EVENT_TYPE(SOCKS5_CONNECT)

// This event is emitted when the SOCKS connect fails because the provided
// was longer than 255 characters.
EVENT_TYPE(SOCKS_HOSTNAME_TOO_BIG)

// These events are emitted when insufficient data was read while
// trying to establish a connection to the SOCKS proxy server
// (during the greeting phase or handshake phase, respectively).
EVENT_TYPE(SOCKS_UNEXPECTEDLY_CLOSED_DURING_GREETING)
EVENT_TYPE(SOCKS_UNEXPECTEDLY_CLOSED_DURING_HANDSHAKE)

// This event indicates that a bad version number was received in the
// proxy server's response. The extra parameters show its value:
//   {
//     "version": <Integer version number in the response>,
//   }
EVENT_TYPE(SOCKS_UNEXPECTED_VERSION)

// This event indicates that the SOCKS proxy server returned an error while
// trying to create a connection. The following parameters will be attached
// to the event:
//   {
//     "error_code": <Integer error code returned by the server>,
//   }
EVENT_TYPE(SOCKS_SERVER_ERROR)

// This event indicates that the SOCKS proxy server asked for an authentication
// method that we don't support. The following parameters are attached to the
// event:
//   {
//     "method": <Integer method code>,
//   }
EVENT_TYPE(SOCKS_UNEXPECTED_AUTH)

// This event indicates that the SOCKS proxy server's response indicated an
// address type which we are not prepared to handle.
// The following parameters are attached to the event:
//   {
//     "address_type": <Integer code for the address type>,
//   }
EVENT_TYPE(SOCKS_UNKNOWN_ADDRESS_TYPE)

// The start/end of an SSL "connect" (aka client handshake).
// The following parameters are attached to the END event:
//
//  {
//    "version": <String name of the TLS version negotiated>,
//    "cipher_suite": <Integer code for the cipher suite>,
//    "is_resumed": <Whether we resumed a session>,
//    "next_proto": <The next protocol negotiated via ALPN>,
//  }
EVENT_TYPE(SSL_CONNECT)

// The start/end of an SSL server handshake (aka "accept").
EVENT_TYPE(SSL_SERVER_HANDSHAKE)

// The SSL server requested a client certificate.
EVENT_TYPE(SSL_CLIENT_CERT_REQUESTED)

// The SSL stack blocked on a private key operation. The following parameters
// are attached to the event.
//   {
//     "type": <type of the key>,
//     "hash": <hash function used>,
//   }
EVENT_TYPE(SSL_PRIVATE_KEY_OP)

// The start/end of getting a domain-bound certificate and private key.
//
// The END event will contain the following parameters on failure:
//
//   {
//     "net_error": <Net integer error code>,
//   }
// TODO(nharper): remove this event.
EVENT_TYPE(SSL_GET_DOMAIN_BOUND_CERT)

// The start/end of getting a Channel ID key.
//
// The START event contains these parameters:
//   {
//     "ephemeral": <Whether or not the Channel ID store is ephemeral>,
//     "service": <Unique identifier for the ChannelIDService used>,
//     "store": <Unique identifier for the ChannelIDStore used>,
//   }
//
// The END event may contain these parameters:
//   {
//     "net_error": <Net error code>,
//     "key": <Hex-encoded EC point of public key (uncompressed point format)>,
//   }
EVENT_TYPE(SSL_GET_CHANNEL_ID)

// The SSL server requested a channel id.
// TODO(nharper): Remove this event.
EVENT_TYPE(SSL_CHANNEL_ID_REQUESTED)

// A channel ID was provided to the SSL library to be sent to the SSL server.
// TODO(nharper): Remove this event.
EVENT_TYPE(SSL_CHANNEL_ID_PROVIDED)

// A client certificate (or none) was provided to the SSL library to be sent
// to the SSL server.
// The following parameters are attached to the event:
//   {
//     "cert_count": <Number of certificates>,
//   }
//   A cert_count of 0 means no client certificate was provided.
//   A cert_count of -1 means a client certificate was provided but we don't
//   know the size of the certificate chain.
EVENT_TYPE(SSL_CLIENT_CERT_PROVIDED)

// An SSL error occurred while trying to do the indicated activity.
// The following parameters are attached to the event:
//   {
//     "net_error": <Integer code for the specific error type>,
//     "ssl_lib_error": <SSL library's integer code for the specific error type>
//   }
EVENT_TYPE(SSL_HANDSHAKE_ERROR)
EVENT_TYPE(SSL_READ_ERROR)
EVENT_TYPE(SSL_WRITE_ERROR)

// An SSL connection needs to be retried with a lower protocol version because
// the server may be intolerant of the protocol version we offered.
// The following parameters are attached to the event:
//   {
//     "host_and_port": <String encoding the host and port>,
//     "net_error": <Net integer error code>,
//     "version_before": <SSL version before the fallback>,
//     "version_after": <SSL version after the fallback>,
//   }
//
// TODO(davidben): Remove this event and the corresponding log_view_painter.js
// logic in M56.
EVENT_TYPE(SSL_VERSION_FALLBACK)

// An SSL connection needs to be retried with more cipher suites because the
// server may require a deprecated cipher suite. The following parameters are
// attached to the event:
//   {
//     "host_and_port": <String encoding the host and port>,
//     "net_error": <Net integer error code>,
//   }
EVENT_TYPE(SSL_CIPHER_FALLBACK)

// We found that our prediction of the server's certificates was correct and
// we merged the verification with the SSLHostInfo. (Note: now obsolete.)
EVENT_TYPE(SSL_VERIFICATION_MERGED)

// An SSL error occurred while calling an NSS function not directly related to
// one of the above activities.  Can also be used when more information than
// is provided by just an error code is needed:
//   {
//     "function": <Name of the NSS function, as a string>,
//     "param": <Most relevant parameter, if any>,
//     "ssl_lib_error": <NSS library's integer code for the specific error type>
//   }
EVENT_TYPE(SSL_NSS_ERROR)

// The specified number of bytes were sent on the socket.  Depending on the
// source of the event, may be logged either once the data is sent, or when it
// is queued to be sent.
// The following parameters are attached:
//   {
//     "byte_count": <Number of bytes that were just sent>,
//     "hex_encoded_bytes": <The exact bytes sent, as a hexadecimal string.
//                           Only present when byte logging is enabled>,
//   }
EVENT_TYPE(SOCKET_BYTES_SENT)
EVENT_TYPE(SSL_SOCKET_BYTES_SENT)

// The specified number of bytes were received on the socket.
// The following parameters are attached:
//   {
//     "byte_count": <Number of bytes that were just received>,
//     "hex_encoded_bytes": <The exact bytes received, as a hexadecimal string.
//                           Only present when byte logging is enabled>,
//   }
EVENT_TYPE(SOCKET_BYTES_RECEIVED)
EVENT_TYPE(SSL_SOCKET_BYTES_RECEIVED)

// A socket error occurred while trying to do the indicated activity.
// The following parameters are attached to the event:
//   {
//     "net_error": <Integer code for the specific error type>,
//     "os_error": <Integer error code the operating system returned>
//   }
EVENT_TYPE(SOCKET_READ_ERROR)
EVENT_TYPE(SOCKET_WRITE_ERROR)

// The socket was closed locally (The socket may or may not have been closed
// by the remote side already)
EVENT_TYPE(SOCKET_CLOSED)

// Certificates were received from the SSL server (during a handshake or
// renegotiation). The following parameters are attached to the event:
//  {
//    "certificates": <A list of PEM encoded certificates in the order that
//                     they were sent by the server>,
//  }
EVENT_TYPE(SSL_CERTIFICATES_RECEIVED)

// Signed Certificate Timestamps were received from the server.
// The following parameters are attached to the event:
// {
//    "embedded_scts": Base64-encoded SignedCertificateTimestampList,
//    "scts_from_ocsp_response": Base64-encoded SignedCertificateTimestampList,
//    "scts_from_tls_extension": Base64-encoded SignedCertificateTimestampList,
// }
//
// The SignedCertificateTimestampList is defined in RFC6962 and is exactly as
// received from the server.
EVENT_TYPE(SIGNED_CERTIFICATE_TIMESTAMPS_RECEIVED)

// Signed Certificate Timestamps were checked.
// The following parameters are attached to the event:
// {
//    "verified_scts": <A list of SCTs>,
//    "invalid_scts": <A list of SCTs>,
//    "scts_from_unknown_logs": <A list of SCTs>,
// }
//
// Where each SCT is an object:
// {
//    "origin": <one of: "Embedded in certificate", "tls_extension", "ocsp">,
//    "version": <numeric version>,
//    "log_id": <base64-encoded log id>,
//    "timestamp": <numeric timestamp in milliseconds since the Unix epoch>,
//    "hash_algorithm": <name of the hash algorithm>,
//    "signature_algorithm": <name of the signature algorithm>,
//    "signature_data": <base64-encoded signature bytes>,
// }
EVENT_TYPE(SIGNED_CERTIFICATE_TIMESTAMPS_CHECKED)

// The certificate was checked for compliance with Certificate Transparency
// requirements.
//
// The following parameters are attached to the event:
// {
//    "certificate": <An X.509 certificate, same format as in
//                   CERT_VERIFIER_JOB.>
//    "build_timely": <boolean>
//    "ct_compliance_status": <string describing compliance status>
// }
EVENT_TYPE(CERT_CT_COMPLIANCE_CHECKED)

// The EV certificate was checked for compliance with Certificate Transparency
// requirements.
//
// The following parameters are attached to the event:
// {
//    "certificate": <An X.509 certificate, same format as in
//                   CERT_VERIFIER_JOB.>
//    "policy_enforcement_required": <boolean>
//    "build_timely": <boolean>
//    "ct_compliance_status": <string describing compliance status>
//    "ev_whitelist_version": <optional; string representing whitelist version>
// }
EVENT_TYPE(EV_CERT_CT_COMPLIANCE_CHECKED)

// ------------------------------------------------------------------------
// DatagramSocket
// ------------------------------------------------------------------------

// The start/end of a UDP client connecting.
//
// The START event contains these parameters:
//
//   {
//     "address": <Remote address being connected to>,
//     "bound_to_network": <optional; network handle for the network that this
//                          socket is bound to.  Only present when this socket
//                          is bound to a network.>
//   }
//
// And the END event will contain the following parameter:
//
//   {
//     "net_error": <Net integer error code, on failure>,
//   }
EVENT_TYPE(UDP_CONNECT)

// The local address of the UDP socket, retrieved via getsockname.
// The following parameters are attached:
//   {
//     "address": <Local address bound to the socket>,
//     "bound_to_network": <optional; network handle for the network that this
//                          socket is bound to.  Only present when this socket
//                          is bound to a network.>
//   }
EVENT_TYPE(UDP_LOCAL_ADDRESS)

// The specified number of bytes were transferred on the socket.
// The following parameters are attached:
//   {
//     "address": <Remote address of data transfer.  Not present when not
//                 specified for UDP_BYTES_SENT events>,
//     "byte_count": <Number of bytes that were just received>,
//     "hex_encoded_bytes": <The exact bytes received, as a hexadecimal string.
//                           Only present when byte logging is enabled>,
//   }
EVENT_TYPE(UDP_BYTES_RECEIVED)
EVENT_TYPE(UDP_BYTES_SENT)

// Logged when an error occurs while reading or writing to/from a UDP socket.
// The following parameters are attached:
//   {
//     "net_error": <Net error code>,
//   }
EVENT_TYPE(UDP_RECEIVE_ERROR)
EVENT_TYPE(UDP_SEND_ERROR)

// ------------------------------------------------------------------------
// ClientSocketPoolBase::ConnectJob
// ------------------------------------------------------------------------

// The start/end of a ConnectJob.
//
// The BEGIN phase has these parameters:
//
//   {
//     "group_name": <The group name for the socket request.>,
//   }
EVENT_TYPE(SOCKET_POOL_CONNECT_JOB)

// The start/end of the ConnectJob::Connect().
EVENT_TYPE(SOCKET_POOL_CONNECT_JOB_CONNECT)

// This event is logged whenever the ConnectJob gets a new socket
// association. The event parameters point to that socket:
//
//   {
//     "source_dependency": <The source identifier for the new socket.>,
//   }
EVENT_TYPE(CONNECT_JOB_SET_SOCKET)

// Whether the connect job timed out.
EVENT_TYPE(SOCKET_POOL_CONNECT_JOB_TIMED_OUT)

// ------------------------------------------------------------------------
// ClientSocketPoolBaseHelper
// ------------------------------------------------------------------------

// The start/end of a client socket pool request for a socket.
EVENT_TYPE(SOCKET_POOL)

// The request stalled because there are too many sockets in the pool.
EVENT_TYPE(SOCKET_POOL_STALLED_MAX_SOCKETS)

// The request stalled because there are too many sockets in the group.
EVENT_TYPE(SOCKET_POOL_STALLED_MAX_SOCKETS_PER_GROUP)

// Indicates that we reused an existing socket. Attached to the event are
// the parameters:
//   {
//     "idle_ms": <The number of milliseconds the socket was sitting idle for>,
//   }
EVENT_TYPE(SOCKET_POOL_REUSED_AN_EXISTING_SOCKET)

// This event simply describes the host:port that were requested from the
// socket pool. Its parameters are:
//   {
//     "host_and_port": <String encoding the host and port>,
//   }
EVENT_TYPE(TCP_CLIENT_SOCKET_POOL_REQUESTED_SOCKET)

// This event simply describes the host:port that were requested from the
// socket pool. Its parameters are:
//   {
//     "host_and_port": <String encoding the host and port>,
//   }
EVENT_TYPE(TCP_CLIENT_SOCKET_POOL_REQUESTED_SOCKETS)

// A backup connect job is created due to slow connect.
EVENT_TYPE(BACKUP_CONNECT_JOB_CREATED)

// This event is sent when a connect job is eventually bound to a request
// (because of late binding and socket backup jobs, we don't assign the job to
// a request until it has completed).
//
// The event parameters are:
//   {
//      "source_dependency": <Source identifier for the connect job we are
//                            bound to>,
//   }
EVENT_TYPE(SOCKET_POOL_BOUND_TO_CONNECT_JOB)

// Identifies the NetLogSource() for the Socket assigned to the pending
// request. The event parameters are:
//   {
//      "source_dependency": <Source identifier for the socket we acquired>,
//   }
EVENT_TYPE(SOCKET_POOL_BOUND_TO_SOCKET)

// The start/end of a client socket pool request for multiple sockets.
// The event parameters are:
//   {
//      "num_sockets": <Number of sockets we're trying to ensure are connected>,
//   }
EVENT_TYPE(SOCKET_POOL_CONNECTING_N_SOCKETS)

// ------------------------------------------------------------------------
// URLRequest
// ------------------------------------------------------------------------

// Measures the time it took a net::URLRequestJob to start. For the most part
// this corresponds with the time between net::URLRequest::Start() and
// net::URLRequest::ResponseStarted(), however it is also repeated for every
// redirect, and every intercepted job that handles the request.
//
// For the BEGIN phase, the following parameters are attached:
//   {
//      "url": <String of URL being loaded>,
//      "method": <The method ("POST" or "GET" or "HEAD" etc..)>,
//      "load_flags": <Numeric value of the combined load flags>,
//      "priority": <Numeric priority of the request>,
//      "upload_id" <String of upload body identifier, if present>,
//   }
//
// For the END phase, if there was an error, the following parameters are
// attached:
//   {
//      "net_error": <Net error code of the failure>,
//   }
EVENT_TYPE(URL_REQUEST_START_JOB)

// This event is sent once a net::URLRequest receives a redirect. The parameters
// attached to the event are:
//   {
//     "location": <The URL that was redirected to>,
//   }
EVENT_TYPE(URL_REQUEST_REDIRECTED)

// Measures the time between when a net::URLRequest calls a delegate that can
// block it, and when the delegate allows the request to resume.
EVENT_TYPE(URL_REQUEST_DELEGATE)

// Logged when a delegate informs the URL_REQUEST of what's currently blocking
// the request. The parameters attached to the begin event are:
//   {
//     "delegate_blocked_by": <Information about what's blocking the request>,
//   }
EVENT_TYPE(DELEGATE_INFO)

// The specified number of bytes were read from the net::URLRequest.
// The filtered event is used when the bytes were passed through a filter before
// being read.  This event is only present when byte logging is enabled.
// The following parameters are attached:
//   {
//     "byte_count": <Number of bytes that were just sent>,
//     "hex_encoded_bytes": <The exact bytes sent, as a hexadecimal string>,
//   }
EVENT_TYPE(URL_REQUEST_JOB_BYTES_READ)
EVENT_TYPE(URL_REQUEST_JOB_FILTERED_BYTES_READ)

// This event is sent when the priority of a net::URLRequest is
// changed after it has started. The following parameters are attached:
//   {
//     "priority": <Numerical value of the priority (higher is more important)>,
//   }
EVENT_TYPE(URL_REQUEST_SET_PRIORITY)

EVENT_TYPE(URL_REQUEST_REDIRECT_JOB)
// This event is logged when a URLRequestRedirectJob is started for a request.
// The following parameters are attached:
//   {
//     "reason": <Reason for the redirect, as a string>,
//   }

EVENT_TYPE(URL_REQUEST_FAKE_RESPONSE_HEADERS_CREATED)
// This event is logged when a URLRequestRedirectJob creates the fake response
// headers for a request, prior to returning them.
// The following parameters are attached:
//   {
//     "headers": <The list of header:value pairs>,
//   }

EVENT_TYPE(URL_REQUEST_FILTERS_SET)
// This event is logged when a URLRequestJob sets up the filters, if any
// filters were added to the job.  It logs the filters added.
// The following parameters are attached:
//   {
//     "filters": <The list of filter names>
//   }

// ------------------------------------------------------------------------
// HttpCache
// ------------------------------------------------------------------------

// Measures the time while getting a reference to the back end.
EVENT_TYPE(HTTP_CACHE_GET_BACKEND)

// Measures the time while opening a disk cache entry.
EVENT_TYPE(HTTP_CACHE_OPEN_ENTRY)

// Measures the time while creating a disk cache entry.
EVENT_TYPE(HTTP_CACHE_CREATE_ENTRY)

// Measures the time it takes to add a HttpCache::Transaction to an http cache
// entry's list of active Transactions.
EVENT_TYPE(HTTP_CACHE_ADD_TO_ENTRY)

// Measures the time while deleting a disk cache entry.
EVENT_TYPE(HTTP_CACHE_DOOM_ENTRY)

// Measures the time while reading/writing a disk cache entry's response headers
// or metadata.
EVENT_TYPE(HTTP_CACHE_READ_INFO)
EVENT_TYPE(HTTP_CACHE_WRITE_INFO)

// Measures the time while reading/writing a disk cache entry's body.
EVENT_TYPE(HTTP_CACHE_READ_DATA)
EVENT_TYPE(HTTP_CACHE_WRITE_DATA)

// The request headers received by the HTTP cache.
// The following parameters are attached:
//   {
//     "line": <empty>,
//     "headers": <The list of header:value pairs>,
//   }
EVENT_TYPE(HTTP_CACHE_CALLER_REQUEST_HEADERS)

// Signal a significant change on the flow of the state machine: start again
// from scratch or create a new network request for byte-range operations.
// There are no parameters.
EVENT_TYPE(HTTP_CACHE_RESTART_PARTIAL_REQUEST)
EVENT_TYPE(HTTP_CACHE_RE_SEND_PARTIAL_REQUEST)

// ------------------------------------------------------------------------
// Disk Cache / Memory Cache
// ------------------------------------------------------------------------

// The creation/destruction of a disk_cache::EntryImpl object.  The "creation"
// is considered to be the point at which an Entry is first considered to be
// good and associated with a key.  Note that disk and memory cache entries
// share event types.
//
// For the BEGIN phase, the following parameters are attached:
//   {
//     "created": <true if the Entry was created, rather than being opened>,
//     "key": <The Entry's key>,
//   }
EVENT_TYPE(DISK_CACHE_ENTRY_IMPL)
EVENT_TYPE(DISK_CACHE_MEM_ENTRY_IMPL)

// Logs the time required to read/write data from/to a cache entry.
//
// For the BEGIN phase, the following parameters are attached:
//   {
//     "index": <Index being read/written>,
//     "offset": <Offset being read/written>,
//     "buf_len": <Length of buffer being read to/written from>,
//     "truncate": <If present for a write, the truncate flag is set to true.
//                  Not present in reads or writes where it is false>,
//   }
//
// For the END phase, the following parameters are attached:
//   {
//     "bytes_copied": <Number of bytes copied.  Not present on error>,
//     "net_error": <Network error code.  Only present on error>,
//   }
EVENT_TYPE(ENTRY_READ_DATA)
EVENT_TYPE(ENTRY_WRITE_DATA)

// Logged when sparse read/write operation starts/stops for an Entry.
//
// For the BEGIN phase, the following parameters are attached:
//   {
//     "offset": <Offset at which to start reading>,
//     "buf_len": <Bytes to read/write>,
//   }
EVENT_TYPE(SPARSE_READ)
EVENT_TYPE(SPARSE_WRITE)

// Logged when a parent Entry starts/stops reading/writing a child Entry's data.
//
// For the BEGIN phase, the following parameters are attached:
//   {
//     "source_dependency": <Source id of the child entry>,
//     "child_len": <Bytes to read/write from/to child>,
//   }
EVENT_TYPE(SPARSE_READ_CHILD_DATA)
EVENT_TYPE(SPARSE_WRITE_CHILD_DATA)

// Logged when sparse GetAvailableRange operation starts/stops for an Entry.
//
// For the BEGIN phase, the following parameters are attached:
//   {
//     "buf_len": <Bytes to read/write>,
//     "offset": <Offset at which to start reading>,
//   }
//
// For the END phase, the following parameters are attached.  No parameters are
// attached when cancelled:
//   {
//     "length": <Length of returned range. Only present on success>,
//     "start": <Position where returned range starts. Only present on success>,
//     "net_error": <Resulting error code. Only present on failure. This may be
//                   "OK" when there's no error, but no available bytes in the
//                   range>,
//   }
EVENT_TYPE(SPARSE_GET_RANGE)

// Indicates the children of a sparse EntryImpl are about to be deleted.
// Not logged for MemEntryImpls.
EVENT_TYPE(SPARSE_DELETE_CHILDREN)

// Logged when an EntryImpl is closed.  Not logged for MemEntryImpls.
EVENT_TYPE(ENTRY_CLOSE)

// Logged when an entry is doomed.
EVENT_TYPE(ENTRY_DOOM)

// ------------------------------------------------------------------------
// HttpStreamFactoryImpl
// ------------------------------------------------------------------------

// Measures the time taken to fulfill the HttpStreamRequest.
EVENT_TYPE(HTTP_STREAM_REQUEST)

// Measures the time taken to execute the HttpStreamFactoryImpl::Job
// The event parameters are:
//   {
//      "source_dependency": <Source identifier for the Request with started
//                            this Job>,
//      "original_url": <The URL to create a stream for>,
//      "url": <The URL actually being used, possibly different from
//              original_url if using an alternate service>,
//      "alternate_service": <The alternate service being used>,
//      "priority": <The priority of the Job>,
//   }
EVENT_TYPE(HTTP_STREAM_JOB)

// Identifies the NetLogSource() for a Job started by the Request.
// The event parameters are:
//   {
//      "source_dependency": <Source identifier for Job we started>,
//   }
EVENT_TYPE(HTTP_STREAM_REQUEST_STARTED_JOB)

// Identifies the NetLogSource() for the Job that fulfilled the Request.
// The event parameters are:
//   {
//      "source_dependency": <Source identifier for Job we acquired>,
//   }
EVENT_TYPE(HTTP_STREAM_REQUEST_BOUND_TO_JOB)

// Identifies the NetLogSource() for the Request that the Job was attached to.
// The event parameters are:
//   {
//      "source_dependency": <Source identifier for the Request to which we were
//                            attached>,
//   }
EVENT_TYPE(HTTP_STREAM_JOB_BOUND_TO_REQUEST)

// Logs the protocol negotiated with the server. The event parameters are:
//   {
//      "status": <The NPN status ("negotiated", "unsupported", "no-overlap")>,
//      "proto": <The NPN protocol negotiated>,
//      "server_protos": <The list of server advertised protocols>,
//   }
EVENT_TYPE(HTTP_STREAM_REQUEST_PROTO)

// Emitted when a Job is orphaned because the Request was bound to a different
// Job. The orphaned Job will continue to run to completion.
EVENT_TYPE(HTTP_STREAM_JOB_ORPHANED)

// Emitted when a job is asked to resume after non-zero microseconds.
//   {
//     "resume_after_ms": <Number of milliseconds until job will be unblocked>
//   }
EVENT_TYPE(HTTP_STREAM_JOB_DELAYED)

// ------------------------------------------------------------------------
// HttpNetworkTransaction
// ------------------------------------------------------------------------

// Measures the time taken to send the tunnel request to the server.
EVENT_TYPE(HTTP_TRANSACTION_TUNNEL_SEND_REQUEST)

// This event is sent for a tunnel request.
// The following parameters are attached:
//   {
//     "line": <The HTTP request line, CRLF terminated>,
//     "headers": <The list of header:value pairs>,
//   }
EVENT_TYPE(HTTP_TRANSACTION_SEND_TUNNEL_HEADERS)

// Measures the time to read the tunnel response headers from the server.
EVENT_TYPE(HTTP_TRANSACTION_TUNNEL_READ_HEADERS)

// This event is sent on receipt of the HTTP response headers to a tunnel
// request.
// The following parameters are attached:
//   {
//     "headers": <The list of header:value pairs>,
//   }
EVENT_TYPE(HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS)

// Measures the time taken to send the request to the server.
EVENT_TYPE(HTTP_TRANSACTION_SEND_REQUEST)

// This event is sent for a HTTP request.
// The following parameters are attached:
//   {
//     "line": <The HTTP request line, CRLF terminated>,
//     "headers": <The list of header:value pairs>,
//   }
EVENT_TYPE(HTTP_TRANSACTION_SEND_REQUEST_HEADERS)

// Logged when a request body is sent.
// The following parameters are attached:
//   {
//     "did_merge": <True if the body was merged with the headers for writing>,
//     "is_chunked": <True if chunked>,
//     "length": <The length of the body.  May not be accurate when body is not
//                in memory>
//   }
EVENT_TYPE(HTTP_TRANSACTION_SEND_REQUEST_BODY)

// This event is sent for a HTTP request over an HTTP/2 stream.
// The following parameters are attached:
//   {
//     "headers": <The list of header:value pairs>,
//   }
EVENT_TYPE(HTTP_TRANSACTION_HTTP2_SEND_REQUEST_HEADERS)

// This event is sent for a HTTP request over a QUIC stream.
// The following parameters are attached:
//   {
//     "headers": <The list of header:value pairs>,
//     "quic_priority": <Integer representing the priority of this request>,
//     "quic_stream_id": <Id of the QUIC stream sending this request>,
//   }
EVENT_TYPE(HTTP_TRANSACTION_QUIC_SEND_REQUEST_HEADERS)

// Measures the time to read HTTP response headers from the server.
EVENT_TYPE(HTTP_TRANSACTION_READ_HEADERS)

// This event is sent on receipt of the HTTP response headers.
// The following parameters are attached:
//   {
//     "headers": <The list of header:value pairs>,
//   }
EVENT_TYPE(HTTP_TRANSACTION_READ_RESPONSE_HEADERS)

// Measures the time to read the entity body from the server.
EVENT_TYPE(HTTP_TRANSACTION_READ_BODY)

// Measures the time taken to read the response out of the socket before
// restarting for authentication, on keep alive connections.
EVENT_TYPE(HTTP_TRANSACTION_DRAIN_BODY_FOR_AUTH_RESTART)

// Measures the time taken to look up the key used for Token Binding.
EVENT_TYPE(HTTP_TRANSACTION_GET_TOKEN_BINDING_KEY)

// Measures the time taken due to throttling by the NetworkThrottleManager.
EVENT_TYPE(HTTP_TRANSACTION_THROTTLED)

// Record priority changes on the network transaction.
EVENT_TYPE(HTTP_TRANSACTION_SET_PRIORITY)

// This event is sent when we try to restart a transaction after an error.
// The following parameters are attached:
//   {
//     "net_error": <The net error code integer for the failure, if applicable>,
//     "http_status_code": <HTTP status code indicating an error, if
//                          applicable>,
//   }
EVENT_TYPE(HTTP_TRANSACTION_RESTART_AFTER_ERROR)

// ------------------------------------------------------------------------
// BidirectionalStream
// ------------------------------------------------------------------------

// Marks the creation/destruction of a net::BidirectionalStream.
// The following parameters are attached:
//   {
//      "url": <The URL being used>,
//      "method": <The HTTP method being used>,
//      "headers": <The list of header:value pairs>,
//   }
EVENT_TYPE(BIDIRECTIONAL_STREAM_ALIVE)

// Marks the ReadData call of a net::BidirectionalStream.
// The following parameters are attached:
// {
//     "rv": <The value in int that is returned to the caller>
// }
EVENT_TYPE(BIDIRECTIONAL_STREAM_READ_DATA)

// Marks the SendData call of a net::BidirectionalStream.
EVENT_TYPE(BIDIRECTIONAL_STREAM_SEND_DATA)

// Marks the SendvData call of a net::BidirectionalStream.
// The following parameters are attached:
// {
//     "num_buffers": <The number of buffers passed to SendvData>
// }
EVENT_TYPE(BIDIRECTIONAL_STREAM_SENDV_DATA)

// Marks the beginning/end of buffers sent in a net::BidirectionalStream.
// The following parameters are attached:
//   {
//      "num_buffers_coalesced": <number of buffers that were sent together>,
//   }
EVENT_TYPE(BIDIRECTIONAL_STREAM_BYTES_SENT_COALESCED)

// The specified number of bytes were sent on the stream.  Depending on the
// source of the event, may be logged either once the data is sent, or when it
// is queued to be sent.
// The following parameters are attached:
//   {
//     "byte_count": <Number of bytes that were just sent>,
//     "hex_encoded_bytes": <The exact bytes sent, as a hexadecimal string.
//                           Only present when byte logging is enabled>,
//   }
EVENT_TYPE(BIDIRECTIONAL_STREAM_BYTES_SENT)

// The specified number of bytes were received on the stream.
// The following parameters are attached:
//   {
//     "byte_count": <Number of bytes that were just received>,
//     "hex_encoded_bytes": <The exact bytes received, as a hexadecimal string.
//                           Only present when byte logging is enabled>,
//   }
EVENT_TYPE(BIDIRECTIONAL_STREAM_BYTES_RECEIVED)

// This event is sent for receiving headers on the stream.
// The following parameters are attached:
//   {
//     "headers": <The list of header:value pairs>,
//   }
EVENT_TYPE(BIDIRECTIONAL_STREAM_RECV_HEADERS)

// This event is sent for receiving trailers on the stream.
// The following parameters are attached:
//   {
//     "headers": <The list of header:value pairs>,
//   }
EVENT_TYPE(BIDIRECTIONAL_STREAM_RECV_TRAILERS)

// This event is used when stream is successfully negotiated and is ready for
// sending data and reading data.
// The following parameters are attached:
//   {
//     "request_headers_sent": <boolean>,
//   }
EVENT_TYPE(BIDIRECTIONAL_STREAM_READY)

// This event is used when stream has failed.
// The following parameters are attached:
//   {
//     "net_error": <Net error code for the failure>,
//   }
EVENT_TYPE(BIDIRECTIONAL_STREAM_FAILED)

// ------------------------------------------------------------------------
// SpdySession
// ------------------------------------------------------------------------

// The start/end of a SpdySession.
//   {
//     "host": <The host-port string>,
//     "proxy": <The Proxy PAC string>,
//   }
EVENT_TYPE(HTTP2_SESSION)

// The SpdySession has been initialized with a socket.
//   {
//     "source_dependency":  <Source identifier for the underlying socket>,
//   }
EVENT_TYPE(HTTP2_SESSION_INITIALIZED)

// This event is sent for sending an HTTP/2 HEADERS frame.
// The following parameters are attached:
//   {
//     "headers": <The list of header:value pairs>,
//     "fin": <True if this is the final data set by the peer on this stream>,
//     "stream_id": <The stream id>,
//     "has_priority": <True if the PRIORITY flag is set>,
//     "parent_stream_id": <Optional; the stream id of the parent stream>,
//     "priority": <Optional; the priority value of the stream>,
//     "exclusive": <Optional; true if the exclusive bit is set>.
//   }
EVENT_TYPE(HTTP2_SESSION_SEND_HEADERS)

// This event is sent for receiving an HTTP/2 HEADERS frame.
// The following parameters are attached:
//   {
//     "flags": <The control frame flags>,
//     "headers": <The list of header:value pairs>,
//     "id": <The stream id>,
//   }
EVENT_TYPE(HTTP2_SESSION_RECV_HEADERS)

// On sending an HTTP/2 SETTINGS frame.
// The following parameters are attached:
//   {
//     "settings": <The list of setting id, flags and value>,
//   }
EVENT_TYPE(HTTP2_SESSION_SEND_SETTINGS)

// Receipt of an HTTP/2 SETTINGS frame.
// The following parameters are attached:
//   {
//     "host": <The host-port string>,
//     "clear_persisted": <Boolean indicating whether to clear all persisted
//                         settings data for the given host>,
//   }
EVENT_TYPE(HTTP2_SESSION_RECV_SETTINGS)

// Receipt of an individual HTTP/2 setting.
// The following parameters are attached:
//   {
//     "id":    <The setting id>,
//     "flags": <The setting flags>,
//     "value": <The setting value>,
//   }
EVENT_TYPE(HTTP2_SESSION_RECV_SETTING)

// The receipt of a RST_STREAM frame.
// The following parameters are attached:
//   {
//     "stream_id": <The stream ID for the window update>,
//     "status": <The reason for the RST_STREAM>,
//   }
EVENT_TYPE(HTTP2_SESSION_RST_STREAM)

// Sending of a RST_STREAM
// The following parameters are attached:
//   {
//     "stream_id": <The stream ID for the window update>,
//     "status": <The reason for the RST_STREAM>,
//     "description": <The textual description for the RST_STREAM>,
//   }
EVENT_TYPE(HTTP2_SESSION_SEND_RST_STREAM)

// Sending of an HTTP/2 PING frame.
// The following parameters are attached:
//   {
//     "unique_id": <The unique id of the PING message>,
//     "type": <The PING type ("sent", "received")>,
//   }
EVENT_TYPE(HTTP2_SESSION_PING)

// Receipt of an HTTP/2 GOAWAY frame.
// The following parameters are attached:
//   {
//     "last_accepted_stream_id": <Last stream id accepted by the server, duh>,
//     "active_streams":          <Number of active streams>,
//     "unclaimed_streams":       <Number of unclaimed push streams>,
//     "status":                  <The reason for the GOAWAY>,
//   }
EVENT_TYPE(HTTP2_SESSION_GOAWAY)

// Receipt of an HTTP/2 WINDOW_UPDATE frame (which controls the send window).
//   {
//     "stream_id": <The stream ID for the window update>,
//     "delta"    : <The delta window size>,
//   }
EVENT_TYPE(HTTP2_SESSION_RECEIVED_WINDOW_UPDATE_FRAME)

// Sending of an HTTP/2 WINDOW_UPDATE frame (which controls the
// receive window).
//   {
//     "stream_id": <The stream ID for the window update>,
//     "delta"    : <The delta window size>,
//   }
EVENT_TYPE(HTTP2_SESSION_SENT_WINDOW_UPDATE_FRAME)

// This event indicates that the send window has been updated for a session.
//   {
//     "delta":      <The window size delta>,
//     "new_window": <The new window size>,
//   }
EVENT_TYPE(HTTP2_SESSION_UPDATE_SEND_WINDOW)

// This event indicates that the recv window has been updated for a session.
//   {
//     "delta":      <The window size delta>,
//     "new_window": <The new window size>,
//   }
EVENT_TYPE(HTTP2_SESSION_UPDATE_RECV_WINDOW)

// Sending a data frame
//   {
//     "stream_id": <The stream ID for the window update>,
//     "length"   : <The size of data sent>,
//     "flags"    : <Send data flags>,
//   }
EVENT_TYPE(HTTP2_SESSION_SEND_DATA)

// Receiving a data frame
//   {
//     "stream_id": <The stream ID for the window update>,
//     "length"   : <The size of data received>,
//     "flags"    : <Receive data flags>,
//   }
EVENT_TYPE(HTTP2_SESSION_RECV_DATA)

// This event is sent for receiving an HTTP/2 PUSH_PROMISE frame.
// The following parameters are attached:
//   {
//     "headers": <The list of header:value pairs>,
//     "id": <The stream id>,
//     "promised_stream_id": <The stream id>,
//   }
EVENT_TYPE(HTTP2_SESSION_RECV_PUSH_PROMISE)

// A stream is stalled by the session send window being closed.
EVENT_TYPE(HTTP2_SESSION_STREAM_STALLED_BY_SESSION_SEND_WINDOW)

// A stream is stalled by its send window being closed.
EVENT_TYPE(HTTP2_SESSION_STREAM_STALLED_BY_STREAM_SEND_WINDOW)

// Session is closing
//   {
//     "net_error"  : <The error status of the closure>,
//     "description": <The textual description for the closure>,
//   }
EVENT_TYPE(HTTP2_SESSION_CLOSE)

// Event when the creation of a stream is stalled because we're at
// the maximum number of concurrent streams.
//  {
//
//    "num_active_streams": <Number of active streams>,
//    "num_created_streams": <Number of created streams>,
//    "num_pushed_streams": <Number of pushed streams>,
//    "max_concurrent_streams": <Maximum number of concurrent streams>,
//    "url": <Request URL>,
//  }
EVENT_TYPE(HTTP2_SESSION_STALLED_MAX_STREAMS)

// Received an out-of-range value for initial window size in SETTINGS
// frame.
//   {
//     "initial_window_size"  : <The initial window size>,
//   }
EVENT_TYPE(HTTP2_SESSION_INITIAL_WINDOW_SIZE_OUT_OF_RANGE)

// Updating streams send window size by the delta window size.
//   {
//     "delta_window_size"    : <The delta window size>,
//   }
EVENT_TYPE(HTTP2_SESSION_UPDATE_STREAMS_SEND_WINDOW_SIZE)

// ------------------------------------------------------------------------
// SpdySessionPool
// ------------------------------------------------------------------------

// This event indicates the pool is reusing an existing session
//   {
//     "source_dependency": <The session id>,
//   }
EVENT_TYPE(HTTP2_SESSION_POOL_FOUND_EXISTING_SESSION)

// This event indicates the pool is reusing an existing session from an
// IP pooling match.
//   {
//     "source_dependency": <The session id>,
//   }
EVENT_TYPE(HTTP2_SESSION_POOL_FOUND_EXISTING_SESSION_FROM_IP_POOL)

// This event indicates the pool created a new session
//   {
//     "source_dependency": <The session id>,
//   }
EVENT_TYPE(HTTP2_SESSION_POOL_CREATED_NEW_SESSION)

// This event indicates that a SSL socket has been upgraded to an HTTP/2
// session.
//   {
//     "source_dependency": <The session id>,
//   }
EVENT_TYPE(HTTP2_SESSION_POOL_IMPORTED_SESSION_FROM_SOCKET)

// This event indicates that the session has been removed.
//   {
//     "source_dependency": <The session id>,
//   }
EVENT_TYPE(HTTP2_SESSION_POOL_REMOVE_SESSION)

// ------------------------------------------------------------------------
// SpdyStream
// ------------------------------------------------------------------------

// The begin and end of an HTTP/2 STREAM.
EVENT_TYPE(HTTP2_STREAM)

// A stream is attached to a pushed stream.
//   {
//     "stream_id":  <The stream id>,
//     "url":        <The url of the pushed resource>,
//   }
EVENT_TYPE(HTTP2_STREAM_ADOPTED_PUSH_STREAM)

// A stream is unstalled by flow control.
EVENT_TYPE(HTTP2_STREAM_FLOW_CONTROL_UNSTALLED)

// This event indicates that the send window has been updated for a stream.
//   {
//     "id":         <The stream id>,
//     "delta":      <The window size delta>,
//     "new_window": <The new window size>,
//   }
EVENT_TYPE(HTTP2_STREAM_UPDATE_SEND_WINDOW)

// This event indicates that the recv window has been updated for a stream.
//   {
//     "id":         <The stream id>,
//     "delta":      <The window size delta>,
//     "new_window": <The new window size>,
//   }
EVENT_TYPE(HTTP2_STREAM_UPDATE_RECV_WINDOW)

// This event indicates a stream error
//   {
//     "id":          <The stream id>,
//     "status":      <The error status>,
//     "description": <The textual description for the error>,
//   }
EVENT_TYPE(HTTP2_STREAM_ERROR)

// A PRIORITY update is sent to the server.
//   {
//     "stream_id":        <The stream id>,
//     "parent_stream_id": <The stream's new parent stream>,
//     "weight":           <The stream's new weight>,
//     "exclusive":        <Whether the new dependency is exclusive>,
//   }
EVENT_TYPE(HTTP2_STREAM_SEND_PRIORITY)

// ------------------------------------------------------------------------
// SpdyProxyClientSocket
// ------------------------------------------------------------------------

EVENT_TYPE(HTTP2_PROXY_CLIENT_SESSION)
// Identifies the HTTP/2 session a source is using.
//   {
//     "source_dependency":  <Source identifier for the underlying session>,
//   }

// ------------------------------------------------------------------------
// QuicSession
// ------------------------------------------------------------------------

// The start/end of a QuicSession.
//   {
//     "host": <The host-port string>,
//   }
EVENT_TYPE(QUIC_SESSION)

// Session is closing because of an error.
//   {
//     "net_error": <Net error code for the closure>,
//   }
EVENT_TYPE(QUIC_SESSION_CLOSE_ON_ERROR)

// Session verification of a certificate from the server failed.
//   {
//   }
EVENT_TYPE(QUIC_SESSION_CERTIFICATE_VERIFY_FAILED)

// Session verified a certificate from the server.
//   {
//     "subjects": <list of DNS names that the certificate is valid for>,
//   }
EVENT_TYPE(QUIC_SESSION_CERTIFICATE_VERIFIED)

// Session received a QUIC packet.
//   {
//     "peer_address": <The ip:port of the peer>,
//     "self_address": <The local ip:port which received the packet>,
//   }
EVENT_TYPE(QUIC_SESSION_PACKET_RECEIVED)

// Session sent a QUIC packet.
//   {
//     "encryption_level": <The EncryptionLevel of the packet>,
//     "transmission_type": <The TransmissionType of the packet>,
//     "packet_sequence_number": <The packet's full 64-bit sequence number,
//                                as a base-10 string.>,
//     "size": <The size of the packet in bytes>
//   }
EVENT_TYPE(QUIC_SESSION_PACKET_SENT)

// Session retransmitted a QUIC packet.
//   {
//     "old_packet_sequence_number": <The old packet's full 64-bit sequence
//                                    number, as a base-10 string.>,
//     "new_packet_sequence_number": <The new packet's full 64-bit sequence
//                                    number, as a base-10 string.>,
//   }
EVENT_TYPE(QUIC_SESSION_PACKET_RETRANSMITTED)

// Session received a QUIC packet with a sequence number that had previously
// been received.
//   {
//     "packet_sequence_number": <The packet's full 64-bit sequence number>
//   }
EVENT_TYPE(QUIC_SESSION_DUPLICATE_PACKET_RECEIVED)

// Session received a QUIC packet header, which has not yet been authenticated.
//   {
//     "connection_id": <The 64-bit CONNECTION_ID for this connection, as a
//                       base-10 string>,
//     "reset_flag": <True if the reset flag is set for this packet>,
//     "version_flag": <True if the version flag is set for this packet>,
//     "packet_sequence_number": <The packet's full 64-bit sequence number,
//                                as a base-10 string.>,
//     "private_flags": <The private flags set for this packet>,
//     "fec_group": <The FEC group of this packet>,
//   }
EVENT_TYPE(QUIC_SESSION_UNAUTHENTICATED_PACKET_HEADER_RECEIVED)

// Session has authenticated a QUIC packet.
EVENT_TYPE(QUIC_SESSION_PACKET_AUTHENTICATED)

// Session received a STREAM frame.
//   {
//     "stream_id": <The id of the stream which this data is for>,
//     "fin": <True if this is the final data set by the peer on this stream>,
//     "offset": <Offset in the byte stream where this data starts>,
//     "length": <Length of the data in this frame>,
//   }
EVENT_TYPE(QUIC_SESSION_STREAM_FRAME_RECEIVED)

// Session sent a STREAM frame.
//   {
//     "stream_id": <The id of the stream which this data is for>,
//     "fin": <True if this is the final data set by the peer on this stream>,
//     "offset": <Offset in the byte stream where this data starts>,
//     "length": <Length of the data in this frame>,
//   }
EVENT_TYPE(QUIC_SESSION_STREAM_FRAME_SENT)

// Session received an ACK frame.
//   {
//     "sent_info": <Details of packet sent by the peer>
//       {
//         "least_unacked": <Lowest sequence number of a packet sent by the peer
//                           for which it has not received an ACK>,
//       }
//     "received_info": <Details of packet received by the peer>
//       {
//         "largest_observed": <The largest sequence number of a packet received
//                               by (or inferred by) the peer>,
//         "missing": <List of sequence numbers of packets lower than
//                     largest_observed which have not been received by the
//                     peer>,
//       }
//   }
EVENT_TYPE(QUIC_SESSION_ACK_FRAME_RECEIVED)

// Session sent an ACK frame.
//   {
//     "sent_info": <Details of packet sent by the peer>
//       {
//         "least_unacked": <Lowest sequence number of a packet sent by the peer
//                           for which it has not received an ACK>,
//       }
//     "received_info": <Details of packet received by the peer>
//       {
//         "largest_observed": <The largest sequence number of a packet received
//                               by (or inferred by) the peer>,
//         "missing": <List of sequence numbers of packets lower than
//                     largest_observed which have not been received by the
//                     peer>,
//       }
//   }
EVENT_TYPE(QUIC_SESSION_ACK_FRAME_SENT)

// Session received a WINDOW_UPDATE frame.
//   {
//     "stream_id": <The id of the stream which this data is for>,
//     "byte_offset": <Byte offset in the stream>,
//   }
EVENT_TYPE(QUIC_SESSION_WINDOW_UPDATE_FRAME_RECEIVED)

// Session sent a WINDOW_UPDATE frame.
//   {
//     "stream_id": <The id of the stream which this data is for>,
//     "byte_offset": <Byte offset in the stream>,
//   }
EVENT_TYPE(QUIC_SESSION_WINDOW_UPDATE_FRAME_SENT)

// Session received a BLOCKED frame.
//   {
//     "stream_id": <The id of the stream which this data is for>,
//   }
EVENT_TYPE(QUIC_SESSION_BLOCKED_FRAME_RECEIVED)

// Session sent a BLOCKED frame.
//   {
//     "stream_id": <The id of the stream which this data is for>,
//   }
EVENT_TYPE(QUIC_SESSION_BLOCKED_FRAME_SENT)

// Session received a GOAWAY frame.
//   {
//     "quic_error":          <QuicErrorCode in the frame>,
//     "last_good_stream_id": <Last correctly received stream id by the server>,
//     "reason_phrase":       <Prose justifying go-away request>,
//   }
EVENT_TYPE(QUIC_SESSION_GOAWAY_FRAME_RECEIVED)

// Session sent a GOAWAY frame.
//   {
//     "quic_error":          <QuicErrorCode in the frame>,
//     "last_good_stream_id": <Last correctly received stream id by the server>,
//     "reason_phrase":       <Prose justifying go-away request>,
//   }
EVENT_TYPE(QUIC_SESSION_GOAWAY_FRAME_SENT)

// Session received a PING frame.
EVENT_TYPE(QUIC_SESSION_PING_FRAME_RECEIVED)

// Session sent a PING frame.
EVENT_TYPE(QUIC_SESSION_PING_FRAME_SENT)

// Session sent an MTU discovery frame (PING on wire).
EVENT_TYPE(QUIC_SESSION_MTU_DISCOVERY_FRAME_SENT)

// Session received a STOP_WAITING frame.
//   {
//     "sent_info": <Details of packet sent by the peer>
//       {
//         "least_unacked": <Lowest sequence number of a packet sent by the peer
//                           for which it has not received an ACK>,
//       }
//   }
EVENT_TYPE(QUIC_SESSION_STOP_WAITING_FRAME_RECEIVED)

// Session sent an STOP_WAITING frame.
//   {
//     "sent_info": <Details of packet sent by the peer>
//       {
//         "least_unacked": <Lowest sequence number of a packet sent by the peer
//                           for which it has not received an ACK>,
//       }
//   }
EVENT_TYPE(QUIC_SESSION_STOP_WAITING_FRAME_SENT)

// Session recevied a RST_STREAM frame.
//   {
//     "offset": <Offset in the byte stream which triggered the reset>,
//     "quic_rst_stream_error": <QuicRstStreamErrorCode in the frame>,
//     "details": <Human readable description>,
//   }
EVENT_TYPE(QUIC_SESSION_RST_STREAM_FRAME_RECEIVED)

// Session sent a RST_STREAM frame.
//   {
//     "offset": <Offset in the byte stream which triggered the reset>,
//     "quic_rst_stream_error": <QuicRstStreamErrorCode in the frame>,
//     "details": <Human readable description>,
//   }
EVENT_TYPE(QUIC_SESSION_RST_STREAM_FRAME_SENT)

// Session received a CONNECTION_CLOSE frame.
//   {
//     "quic_error": <QuicErrorCode in the frame>,
//     "details": <Human readable description>,
//   }
EVENT_TYPE(QUIC_SESSION_CONNECTION_CLOSE_FRAME_RECEIVED)

// Session received a CONNECTION_CLOSE frame.
//   {
//     "quic_error": <QuicErrorCode in the frame>,
//     "details": <Human readable description>,
//   }
EVENT_TYPE(QUIC_SESSION_CONNECTION_CLOSE_FRAME_SENT)

// Session received a public reset packet.
//   {
//   }
EVENT_TYPE(QUIC_SESSION_PUBLIC_RESET_PACKET_RECEIVED)

// Session received a version negotiation packet.
//   {
//     "versions": <List of QUIC versions supported by the server>,
//   }
EVENT_TYPE(QUIC_SESSION_VERSION_NEGOTIATION_PACKET_RECEIVED)

// Session successfully negotiated QUIC version number.
//   {
//     "version": <String of QUIC version negotiated with the server>,
//   }
EVENT_TYPE(QUIC_SESSION_VERSION_NEGOTIATED)

// Session revived a QUIC packet packet via FEC.
//   {
//     "connection_id": <The 64-bit CONNECTION_ID for this connection, as a
//                       base-10 string>,
//     "public_flags": <The public flags set for this packet>,
//     "packet_sequence_number": <The packet's full 64-bit sequence number,
//                                as a base-10 string.>,
//     "private_flags": <The private flags set for this packet>,
//     "fec_group": <The FEC group of this packet>,
//   }
EVENT_TYPE(QUIC_SESSION_PACKET_HEADER_REVIVED)

// Session received a crypto handshake message.
//   {
//     "quic_crypto_handshake_message": <The human readable dump of the message
//                                       contents>
//   }
EVENT_TYPE(QUIC_SESSION_CRYPTO_HANDSHAKE_MESSAGE_RECEIVED)

// Session sent a crypto handshake message.
//   {
//     "quic_crypto_handshake_message": <The human readable dump of the message
//                                       contents>
//   }
EVENT_TYPE(QUIC_SESSION_CRYPTO_HANDSHAKE_MESSAGE_SENT)

// A QUIC connection received a PUSH_PROMISE frame.  The following
// parameters are attached:
//   {
//     "headers": <The list of header:value pairs>,
//     "id": <The stream id>,
//     "promised_stream_id": <The stream id>,
//   }
EVENT_TYPE(QUIC_SESSION_PUSH_PROMISE_RECEIVED)

// Session was closed, either remotely or by the peer.
//   {
//     "quic_error": <QuicErrorCode which caused the connection to be closed>,
//     "from_peer":  <True if the peer closed the connection>
//   }
EVENT_TYPE(QUIC_SESSION_CLOSED)

// ------------------------------------------------------------------------
// QuicHttpStream
// ------------------------------------------------------------------------

// A stream request's url matches a received push promise.  The
// promised stream can be adopted for this request once vary header
// validation is complete (as part of response header processing).
//   {
//     "stream_id":  <The stream id>,
//     "url":        <The url of the pushed resource>,
//   }
EVENT_TYPE(QUIC_HTTP_STREAM_PUSH_PROMISE_RENDEZVOUS)

// Vary validation has succeeded, a http stream is attached to
// a pushed QUIC stream.
//   {
//     "stream_id":  <The stream id>,
//     "url":        <The url of the pushed resource>,
//   }
EVENT_TYPE(QUIC_HTTP_STREAM_ADOPTED_PUSH_STREAM)

// Identifies the NetLogSource() for the QuicSesssion that handled the stream.
// The event parameters are:
//   {
//      "source_dependency": <Source identifier for session that was used>,
//   }
EVENT_TYPE(HTTP_STREAM_REQUEST_BOUND_TO_QUIC_SESSION)

// ------------------------------------------------------------------------
// QuicChromiumClientStream
// ------------------------------------------------------------------------

// The stream is sending the request headers.
//   {
//     "headers": <The list of header:value pairs>
//   }
EVENT_TYPE(QUIC_CHROMIUM_CLIENT_STREAM_SEND_REQUEST_HEADERS)

// The stream has read the response headers.
//   {
//     "headers": <The list of header:value pairs>
//   }
EVENT_TYPE(QUIC_CHROMIUM_CLIENT_STREAM_READ_RESPONSE_HEADERS)

// The stream has read the response trailers.
//   {
//     "headers": <The list of header:value pairs>
//   }
EVENT_TYPE(QUIC_CHROMIUM_CLIENT_STREAM_READ_RESPONSE_TRAILERS)

// ------------------------------------------------------------------------
// QuicConnectionMigration
// ------------------------------------------------------------------------

// Records that QUIC connection migration has been triggered.
//  {
//     "trigger": <The reason for the migration attempt>
//  }
EVENT_TYPE(QUIC_CONNECTION_MIGRATION_TRIGGERED)

// Records that a QUIC connection migration attempt of the session
// identified by connection_id failed.
//  {
//     "connection_id": <Connection ID of the session>
//     "reason": <Failure reason>
//  }
EVENT_TYPE(QUIC_CONNECTION_MIGRATION_FAILURE)

// Records that a QUIC connection migration attempt of the session
// identified by connection_id succeeded.
//  {
//     "connection_id": <Connection ID of the session>
//  }
EVENT_TYPE(QUIC_CONNECTION_MIGRATION_SUCCESS)

// ------------------------------------------------------------------------
// HttpStreamParser
// ------------------------------------------------------------------------

// Measures the time to read HTTP response headers from the server.
EVENT_TYPE(HTTP_STREAM_PARSER_READ_HEADERS)

// ------------------------------------------------------------------------
// SOCKS5ClientSocket
// ------------------------------------------------------------------------

// The time spent sending the "greeting" to the SOCKS server.
EVENT_TYPE(SOCKS5_GREET_WRITE)

// The time spent waiting for the "greeting" response from the SOCKS server.
EVENT_TYPE(SOCKS5_GREET_READ)

// The time spent sending the CONNECT request to the SOCKS server.
EVENT_TYPE(SOCKS5_HANDSHAKE_WRITE)

// The time spent waiting for the response to the CONNECT request.
EVENT_TYPE(SOCKS5_HANDSHAKE_READ)

// ------------------------------------------------------------------------
// HTTP Authentication
// ------------------------------------------------------------------------

// The time spent authenticating to the proxy.
EVENT_TYPE(AUTH_PROXY)

// The time spent authentication to the server.
EVENT_TYPE(AUTH_SERVER)

// The channel bindings generated for the connection.
EVENT_TYPE(AUTH_CHANNEL_BINDINGS)

// ------------------------------------------------------------------------
// HTML5 Application Cache
// ------------------------------------------------------------------------

// This event is emitted whenever a request is satisfied directly from
// the appcache.
EVENT_TYPE(APPCACHE_DELIVERING_CACHED_RESPONSE)

// This event is emitted whenever the appcache uses a fallback response.
EVENT_TYPE(APPCACHE_DELIVERING_FALLBACK_RESPONSE)

// This event is emitted whenever the appcache generates an error response.
EVENT_TYPE(APPCACHE_DELIVERING_ERROR_RESPONSE)

// This event is emitted whenever the appcache executes script to compute
// a response.
EVENT_TYPE(APPCACHE_DELIVERING_EXECUTABLE_RESPONSE)

// ------------------------------------------------------------------------
// Service Worker
// ------------------------------------------------------------------------
// This event is emitted when Service Worker starts to handle a request.
EVENT_TYPE(SERVICE_WORKER_START_REQUEST)

// This event is emitted when Service Worker results in a fallback to network
// response.
EVENT_TYPE(SERVICE_WORKER_FALLBACK_RESPONSE)

// This event is emitted when Service Worker results in a fallback to network
// response, and asks the renderer rather than the browser to do the fallback
// due to CORS.
EVENT_TYPE(SERVICE_WORKER_FALLBACK_FOR_CORS)

// This event is emitted when Service Worker responds with a headers-only
// response.
EVENT_TYPE(SERVICE_WORKER_HEADERS_ONLY_RESPONSE)

// This event is emitted when Service Worker responds with a stream.
EVENT_TYPE(SERVICE_WORKER_STREAM_RESPONSE)

// This event is emitted when Service Worker responds with a blob.
EVENT_TYPE(SERVICE_WORKER_BLOB_RESPONSE)

// This event is emitted when Service Worker instructs the browser
// to respond with a network error.
EVENT_TYPE(SERVICE_WORKER_ERROR_RESPONSE_STATUS_ZERO)

// This event is emitted when Service Worker attempts to respond with
// a blob, but it was not readable.
EVENT_TYPE(SERVICE_WORKER_ERROR_BAD_BLOB)

// This event is emitted when Service Worker fails to respond because
// the provider host was null.
EVENT_TYPE(SERVICE_WORKER_ERROR_NO_PROVIDER_HOST)

// This event is emitted when Service Worker fails to respond because
// the registration had no active version.
EVENT_TYPE(SERVICE_WORKER_ERROR_NO_ACTIVE_VERSION)

// This event is emitted when Service Worker fails to respond because
// the underlying request was detached.
EVENT_TYPE(SERVICE_WORKER_ERROR_NO_REQUEST)

// This event is emitted when Service Worker fails to respond because
// the job delegate behaved incorrectly.
EVENT_TYPE(SERVICE_WORKER_ERROR_BAD_DELEGATE)

// This event is emitted when Service Worker fails to respond because
// the fetch event could not be dispatched to the worker.
EVENT_TYPE(SERVICE_WORKER_ERROR_FETCH_EVENT_DISPATCH)

// This event is emitted when Service Worker fails to respond because
// of an error when reading the blob response.
EVENT_TYPE(SERVICE_WORKER_ERROR_BLOB_READ)

// This event is emitted when Service Worker fails to respond because
// of an error when reading the stream response.
EVENT_TYPE(SERVICE_WORKER_ERROR_STREAM_ABORTED)

// This event is emitted when Service Worker is destroyed before it
// responds.
EVENT_TYPE(SERVICE_WORKER_ERROR_KILLED)

// This event is emitted when Service Worker is destroyed before it
// finishes responding with a blob.
EVENT_TYPE(SERVICE_WORKER_ERROR_KILLED_WITH_BLOB)

// This event is emitted when Service Worker is destroyed before it
// finishes responding with a stream.
EVENT_TYPE(SERVICE_WORKER_ERROR_KILLED_WITH_STREAM)

// This event is emitted when a request to be forwarded to a Service Worker has
// request body, and it may be necessary to wait for sizes of files in the body
// to be resolved. The END phase event parameter is:
//   {
//     "success": Whether file sizes in the request body have been resolved
//     successfully
//   }
EVENT_TYPE(SERVICE_WORKER_WAITING_FOR_REQUEST_BODY_FILES)

// This event is emitted when a request failed to be forwarded to a Service
// Worker, because it had a request body with a blob that failed to be
// constructed.
EVENT_TYPE(SERVICE_WORKER_ERROR_REQUEST_BODY_BLOB_FAILED)

// The start/end of dispatching a fetch event to a service worker. This includes
// waiting for the worker to activate and starting the worker if neccessary.
//
// The BEGIN phase consists of the following parameters:
// {
//   "event_type": A string indicating the type of fetch event. Generally it is
//   either a fetch or foreignfetch event; fetch events are additionally
//   categorized by resource type.
// }
//
// For the END phase, the following parameters are attached. No parameters are
// attached when cancelled:
// {
//   "status": The ServiceWorkerStatusCode as a string.
//   "has_response": True if the service worker provided a response to the fetch
//   event. False means to fall back to network.
// }
EVENT_TYPE(SERVICE_WORKER_DISPATCH_FETCH_EVENT)

// Measures the time waiting for a service worker to go from ACTIVATING to
// ACTIVATED.
EVENT_TYPE(SERVICE_WORKER_WAIT_FOR_ACTIVATION)

// The start/end of starting a service worker.
// For the END phase, the following parameters are attached:
// {
//   "status": The ServiceWorkerStatusCode as a string. Only present on failure.
// }
EVENT_TYPE(SERVICE_WORKER_START_WORKER)

// The start/end of dispatching a fetch event to an activated, running service
// worker.
// For the END phase, the following parameters are attached:
// {
//   "status": The ServiceWorkerStatusCode as a string. Only present on failure.
// }
EVENT_TYPE(SERVICE_WORKER_FETCH_EVENT)

// This event is emitted when a request for a service worker script or its
// imported scripts could not be handled.
// {
//   "error": The error reason as a string.
// }
EVENT_TYPE(SERVICE_WORKER_SCRIPT_LOAD_UNHANDLED_REQUEST_ERROR)

// ------------------------------------------------------------------------
// Global events
// ------------------------------------------------------------------------
// These are events which are not grouped by source id, as they have no
// context.

// This event is emitted whenever NetworkChangeNotifier determines that an
// active network adapter's IP address has changed.
EVENT_TYPE(NETWORK_IP_ADDRESSES_CHANGED)

// This event is emitted whenever NetworkChangeNotifier determines that an
// active network adapter's connectivity status has changed.
//   {
//     "new_connection_type": <Type of the new connection>
//   }
EVENT_TYPE(NETWORK_CONNECTIVITY_CHANGED)

// This event is emitted whenever NetworkChangeNotifier determines that a change
// occurs to the host computer's hardware or software that affects the route
// network packets take to any network server.
//   {
//     "new_connection_type": <Type of the new connection>
//   }
EVENT_TYPE(NETWORK_CHANGED)

// This event is emitted whenever HostResolverImpl receives a new DnsConfig
// from the DnsConfigService.
//   {
//     "nameservers":                <List of name server IPs>,
//     "search":                     <List of domain suffixes>,
//     "num_hosts":                  <Number of entries in the HOSTS file>,
//     <other>:                      <See DnsConfig>
//   }
EVENT_TYPE(DNS_CONFIG_CHANGED)

// This event is emitted whenever NetworkChangeNotifier determines that a
// network has connected and network-specific information is available
// (i.e. the NetworkChangeNotifier::NetworkHandle of the network is known).
//   {
//     "changed_network_handle":        <Network handle>
//     "changed_network_type":          <Type of network>
//     "default_active_network_handle": <Network handle of default network>
//     "current_active_networks":       <Mapping from network handle to network
//                                       type, containing entries for all active
//                                       networks.>
//   }
EVENT_TYPE(SPECIFIC_NETWORK_CONNECTED)

// This event is emitted whenever NetworkChangeNotifier determines that a
// network has disconnected and network-specific information is available
// (i.e. the NetworkChangeNotifier::NetworkHandle of the network is known).
//   {
//     "changed_network_handle":        <Network handle>
//     "changed_network_type":          <Type of network>
//     "default_active_network_handle": <Network handle of default network>
//     "current_active_networks":       <Mapping from network handle to network
//                                       type, containing entries for all active
//                                       networks.>
//   }
EVENT_TYPE(SPECIFIC_NETWORK_DISCONNECTED)

// This event is emitted whenever NetworkChangeNotifier determines that a
// network is soon to disconnect and network-specific information is available
// (i.e. the NetworkChangeNotifier::NetworkHandle of the network is known).
//   {
//     "changed_network_handle":        <Network handle>
//     "changed_network_type":          <Type of network>
//     "default_active_network_handle": <Network handle of default network>
//     "current_active_networks":       <Mapping from network handle to network
//                                       type, containing entries for all active
//                                       networks.>
//   }
EVENT_TYPE(SPECIFIC_NETWORK_SOON_TO_DISCONNECT)

// This event is emitted whenever NetworkChangeNotifier determines that a
// network has become the default and network-specific information is available
// (i.e. the NetworkChangeNotifier::NetworkHandle of the network is known).
//   {
//     "changed_network_handle":        <Network handle>
//     "changed_network_type":          <Type of network>
//     "default_active_network_handle": <Network handle of default network>
//     "current_active_networks":       <Mapping from network handle to network
//                                       type, containing entries for all active
//                                       networks.>
//   }
EVENT_TYPE(SPECIFIC_NETWORK_MADE_DEFAULT)

// ------------------------------------------------------------------------
// Exponential back-off throttling events
// ------------------------------------------------------------------------

// Emitted when back-off is disabled for a given host, or the first time
// a localhost URL is used (back-off is always disabled for localhost).
//   {
//     "host": <The hostname back-off was disabled for>
//   }
EVENT_TYPE(THROTTLING_DISABLED_FOR_HOST)

// Emitted when a request is denied due to exponential back-off throttling.
//   {
//     "url":              <URL that was being requested>,
//     "num_failures":     <Failure count for the URL>,
//     "release_after_ms": <Number of milliseconds until URL will be unblocked>
//   }
EVENT_TYPE(THROTTLING_REJECTED_REQUEST)

// ------------------------------------------------------------------------
// DnsTransaction
// ------------------------------------------------------------------------

// The start/end of a DnsTransaction.
//
// The BEGIN phase contains the following parameters:
//
// {
//   "hostname": <The hostname it is trying to resolve>,
//   "query_type": <Type of the query>,
// }
//
// The END phase contains the following parameters:
//
// {
//   "net_error": <The net error code for the failure, if any>,
// }
EVENT_TYPE(DNS_TRANSACTION)

// The start/end of a DnsTransaction query for a fully-qualified domain name.
//
// The BEGIN phase contains the following parameters:
//
// {
//   "qname": <The fully-qualified domain name it is trying to resolve>,
// }
//
// The END phase contains the following parameters:
//
// {
//   "net_error": <The net error code for the failure, if any>,
// }
EVENT_TYPE(DNS_TRANSACTION_QUERY)

// This event is created when DnsTransaction creates a new UDP socket and
// tries to resolve the fully-qualified name.
//
// It has a single parameter:
//
//   {
//     "source_dependency": <Source id of the UDP socket created for the
//                           attempt>,
//   }
EVENT_TYPE(DNS_TRANSACTION_ATTEMPT)

// This event is created when DnsTransaction creates a new TCP socket and
// tries to resolve the fully-qualified name.
//
// It has a single parameter:
//
//   {
//     "source_dependency": <Source id of the TCP socket created for the
//                           attempt>,
//   }
EVENT_TYPE(DNS_TRANSACTION_TCP_ATTEMPT)

// This event is created when DnsTransaction receives a matching response.
//
// It has the following parameters:
//
//   {
//     "rcode": <rcode in the received response>,
//     "answer_count": <answer_count in the received response>,
//     "source_dependency": <Source id of the UDP socket that received the
//                           response>,
//   }
EVENT_TYPE(DNS_TRANSACTION_RESPONSE)

// ------------------------------------------------------------------------
// ChromeExtension
// ------------------------------------------------------------------------

// TODO(eroman): This is a layering violation. Fix this in the context
// of http://crbug.com/90674.

// This event is created when a Chrome extension aborts a request.
//
//  {
//    "extension_id": <Extension ID that caused the abortion>
//  }
EVENT_TYPE(CHROME_EXTENSION_ABORTED_REQUEST)

// This event is created when a Chrome extension redirects a request.
//
//  {
//    "extension_id": <Extension ID that caused the redirection>
//  }
EVENT_TYPE(CHROME_EXTENSION_REDIRECTED_REQUEST)

// This event is created when a Chrome extension modifies the headers of a
// request.
//
//  {
//    "extension_id":     <Extension ID that caused the modification>,
//    "modified_headers": [ "<header>: <value>", ... ],
//    "deleted_headers":  [ "<header>", ... ]
//  }
EVENT_TYPE(CHROME_EXTENSION_MODIFIED_HEADERS)

// This event is created when a Chrome extension tried to modify a request
// but was ignored due to a conflict.
//
//  {
//    "extension_id": <Extension ID that was ignored>
//  }
EVENT_TYPE(CHROME_EXTENSION_IGNORED_DUE_TO_CONFLICT)

// This event is created when a Chrome extension provides authentication
// credentials.
//
//  {
//    "extension_id": <Extension ID that provides credentials>
//  }
EVENT_TYPE(CHROME_EXTENSION_PROVIDE_AUTH_CREDENTIALS)

// ------------------------------------------------------------------------
// HostBlacklistManager
// ------------------------------------------------------------------------

// TODO(joaodasilva): Layering violation, see comment above.
// http://crbug.com/90674.

// This event is created when a request is blocked by a policy.
EVENT_TYPE(CHROME_POLICY_ABORTED_REQUEST)

// ------------------------------------------------------------------------
// CertVerifier
// ------------------------------------------------------------------------

// This event is created when we start a CertVerifier request.
EVENT_TYPE(CERT_VERIFIER_REQUEST)

// This event is created when we start a CertVerifier job.
// The BEGIN phase event parameters are:
// {
//   "certificates": <A list of PEM encoded certificates, the first one
//                    being the certificate to verify and the remaining
//                    being intermediate certificates to assist path
//                    building. Only present when byte logging is enabled.>
// }
//
// The END phase event parameters are:
//   {
//     "cert_status": <Bitmask of CERT_STATUS_*
//                     from net/base/cert_status_flags.h>
//     "common_name_fallback_used": <True if a fallback to the common name
//                                   was used when matching the host
//                                   name, rather than using the
//                                   subjectAltName.>
//     "has_md2": <True if a certificate in the certificate chain is signed with
//                 a MD2 signature.>
//     "has_md4": <True if a certificate in the certificate chain is signed with
//                 a MD4 signature.>
//     "has_md5": <True if a certificate in the certificate chain is signed with
//                 a MD5 signature.>
//     "is_issued_by_additional_trust_anchor": <True if the root CA used for
//                                              this verification came from the
//                                              list of additional trust
//                                              anchors.>
//     "is_issued_by_known_root": <True if we recognise the root CA as a
//                                 standard root.  If it isn't then it's
//                                 probably the case that this certificate
//                                 was generated by a MITM proxy whose root
//                                 has been installed locally. This is
//                                 meaningless if the certificate was not
//                                 trusted.>
//     "public_key_hashes": <If the certificate was successfully verified then
//                           this contains the hashes, in several hash
//                           algorithms, of the SubjectPublicKeyInfos of the
//                           chain.>
//     "verified_cert": <The certificate chain that was constructed
//                       during verification. Note that though the verified
//                       certificate will match the originally supplied
//                       certificate, the intermediate certificates stored
//                       within may be substantially different. In the event
//                       of a verification failure, this will contain the
//                       chain as supplied by the server. This may be NULL
//                       if running within the sandbox.>
//   }
EVENT_TYPE(CERT_VERIFIER_JOB)

// This event is created when a CertVerifier request attaches to a job.
//
// The event parameters are:
//   {
//      "source_dependency": <Source identifier for the job we are bound to>,
//   }
EVENT_TYPE(CERT_VERIFIER_REQUEST_BOUND_TO_JOB)

// ------------------------------------------------------------------------
// Download start events.
// ------------------------------------------------------------------------

// This event is created when a download is started, and lets the URL request
// event source know what download source it is using.
//   {
//     "source_dependency": <Source id of the download>,
//   }
EVENT_TYPE(DOWNLOAD_STARTED)

// This event is created when a download is started, and lets the download
// event source know what URL request it's associated with.
//   {
//     "source_dependency": <Source id of the request being waited on>,
//   }
EVENT_TYPE(DOWNLOAD_URL_REQUEST)

// ------------------------------------------------------------------------
// DownloadItem events.
// ------------------------------------------------------------------------

// This event lives for as long as a download item is active.
// The BEGIN event occurs right after construction, and has the following
// parameters:
//   {
//     "type": <New/history/save page>,
//     "id": <Download ID>,
//     "original_url": <URL that initiated the download>,
//     "final_url": <URL of the actual download file>,
//     "file_name": <initial file name, based on DownloadItem's members:
//                   For History downloads it's the |full_path_|
//                   For other downloads, uses the first non-empty variable of:
//                     |state_info.force_filename|
//                     |suggested_filename_|
//                     the filename specified in the final URL>,
//     "danger_type": <NOT_DANGEROUS, DANGEROUS_FILE, DANGEROUS_URL,
//                     DANGEROUS_CONTENT, MAYBE_DANGEROUS_CONTENT,
//                     UNCOMMON_CONTENT, USER_VALIDATED, DANGEROUS_HOST,
//                     POTENTIALLY_UNWANTED>,
//     "start_offset": <Where to start writing (defaults to 0)>,
//     "has_user_gesture": <Whether or not we think the user initiated
//                          the download>
//   }
// The END event will occur when the download is interrupted, canceled or
// completed.
// DownloadItems that are loaded from history and are never active simply ADD
// one of these events.
EVENT_TYPE(DOWNLOAD_ITEM_ACTIVE)

// Recorded when the DownloadFile is created.
//   {
//     "source_dependency": <Source ID of DownloadFile>
//   }
EVENT_TYPE(DOWNLOAD_FILE_CREATED)

// This event is created when a download item's danger type
// has been modified.
//   {
//     "danger_type": <The new danger type.  See above for possible values.>,
//   }
EVENT_TYPE(DOWNLOAD_ITEM_SAFETY_STATE_UPDATED)

// This event is created when a download item is updated.
//   {
//     "bytes_so_far": <Number of bytes received>,
//     "hash_state": <Current hash state, as a hex-encoded binary string>,
//   }
EVENT_TYPE(DOWNLOAD_ITEM_UPDATED)

// This event is created when a download item is renamed.
//   {
//     "old_filename": <Old file name>,
//     "new_filename": <New file name>,
//   }
EVENT_TYPE(DOWNLOAD_ITEM_RENAMED)

// This event is created when a download item is interrupted.
//   {
//     "interrupt_reason": <The reason for the interruption>,
//     "bytes_so_far": <Number of bytes received>,
//     "hash_state": <Current hash state, as a hex-encoded binary string>,
//   }
EVENT_TYPE(DOWNLOAD_ITEM_INTERRUPTED)

// This event is created when a download item is resumed.
//   {
//     "user_initiated": <True if user initiated resume>,
//     "reason": <The reason for the interruption>,
//     "bytes_so_far": <Number of bytes received>,
//     "hash_state": <Current hash state, as a hex-encoded binary string>,
//   }
EVENT_TYPE(DOWNLOAD_ITEM_RESUMED)

// This event is created when a download item is completing.
//   {
//     "bytes_so_far": <Number of bytes received>,
//     "final_hash": <Final hash, as a hex-encoded binary string>,
//   }
EVENT_TYPE(DOWNLOAD_ITEM_COMPLETING)

// This event is created when a download item is finished.
//   {
//     "auto_opened": <Whether or not the download was auto-opened>
//   }
EVENT_TYPE(DOWNLOAD_ITEM_FINISHED)

// This event is created when a download item is canceled.
//   {
//     "bytes_so_far": <Number of bytes received>,
//     "hash_state": <Current hash state, as a hex-encoded binary string>,
//   }
EVENT_TYPE(DOWNLOAD_ITEM_CANCELED)

// ------------------------------------------------------------------------
// DownloadFile events.
// ------------------------------------------------------------------------

// A new download file was created.
//   {
//     "source_dependency": <Source ID of owning DownloadItem>
//   }
EVENT_TYPE(DOWNLOAD_FILE_ACTIVE)

// This event is created when a download file is opened, and lasts until
// the file is closed.
// The BEGIN event has the following parameters:
//   {
//     "file_name": <The name of the file>,
//     "start_offset": <The position at which to start writing>,
//   }
EVENT_TYPE(DOWNLOAD_FILE_OPENED)

// This event is created when the stream between download source
// and download file is drained.
//   {
//     "stream_size": <Total size of all bytes drained from the stream>
//     "num_buffers": <How many separate buffers those bytes were in>
//   }
EVENT_TYPE(DOWNLOAD_STREAM_DRAINED)

// Created when a buffer is written to the download file. The END event has the
// following paramters:
//   {
//     "bytes": <Count of bytes written>
//   }
EVENT_TYPE(DOWNLOAD_FILE_WRITTEN)

// This event is created when a download file is renamed.
//   {
//     "old_filename": <Old filename>,
//     "new_filename": <New filename>,
//   }
EVENT_TYPE(DOWNLOAD_FILE_RENAMED)

// This event is created when a download file is detached.
EVENT_TYPE(DOWNLOAD_FILE_DETACHED)

// This event is created when a download file is deleted.
EVENT_TYPE(DOWNLOAD_FILE_DELETED)

// This event is created when a download file operation has an error.
//   {
//     "operation": <open, write, close, etc>,
//     "net_error": <net::Error code>,
//     "os_error": <OS dependent error code>
//     "interrupt_reason": <Download interrupt reason>
//   }
EVENT_TYPE(DOWNLOAD_FILE_ERROR)

// This event is created when a download file is annotating with source
// information (for Mark Of The Web and anti-virus integration).
EVENT_TYPE(DOWNLOAD_FILE_ANNOTATED)

// ------------------------------------------------------------------------
// FileStream events.
// ------------------------------------------------------------------------

// This event lasts the lifetime of a file stream.
EVENT_TYPE(FILE_STREAM_ALIVE)

// This event is created when a file stream is associated with a NetLog source.
// It indicates what file stream event source is used.
//   {
//     "source_dependency": <Source id of the file stream>,
//   }
EVENT_TYPE(FILE_STREAM_SOURCE)

// This event is created when a file stream is associated with a NetLog source.
// It indicates what event source owns the file stream source.
//   {
//     "source_dependency": <Source id of the owner of the file stream>,
//   }
EVENT_TYPE(FILE_STREAM_BOUND_TO_OWNER)

// Mark the opening/closing of a file stream.
// The BEGIN event has the following parameters:
//   {
//     "file_name".
//   }
EVENT_TYPE(FILE_STREAM_OPEN)

// This event is created when a file stream operation has an error.
//   {
//     "operation": <open, write, close, etc>,
//     "os_error": <OS-dependent error code>,
//     "net_error": <net::Error code>,
//   }
EVENT_TYPE(FILE_STREAM_ERROR)

// -----------------------------------------------------------------------------
// FTP events.
// -----------------------------------------------------------------------------

// This event is created when an FTP command is sent. It contains following
// parameters:
//   {
//     "command": <String - the command sent to remote server>
//   }
EVENT_TYPE(FTP_COMMAND_SENT)

// This event is created when FTP control connection is made. It contains
// following parameters:
//   {
//     "source_dependency": <id of log for control connection socket>
//   }
EVENT_TYPE(FTP_CONTROL_CONNECTION)

// This event is created when FTP data connection is made. It contains
// following parameters:
//   {
//     "source_dependency": <id of log for data connection socket>
//   }
EVENT_TYPE(FTP_DATA_CONNECTION)

// This event is created when FTP control connection response is processed.
// It contains following parameters:
//   {
//     "lines": <list of strings - each representing a line of the response>
//     "status_code": <numeric status code of the response>
//   }
EVENT_TYPE(FTP_CONTROL_RESPONSE)

// -----------------------------------------------------------------------------
// Simple Cache events.
// -----------------------------------------------------------------------------

// This event lasts the lifetime of a Simple Cache entry.
// It contains the following parameter:
//   {
//     "entry_hash": <hash of the entry, formatted as a hex string>
//   }
EVENT_TYPE(SIMPLE_CACHE_ENTRY)

// This event is created when the entry's key is set.
// It contains the following parameter:
//   {
//     "key": <key of the entry>
//   }
EVENT_TYPE(SIMPLE_CACHE_ENTRY_SET_KEY)

// This event is created when OpenEntry is called.  It has no parameters.
EVENT_TYPE(SIMPLE_CACHE_ENTRY_OPEN_CALL)

// This event is created when the Simple Cache actually begins opening the
// cache entry.  It has no parameters.
EVENT_TYPE(SIMPLE_CACHE_ENTRY_OPEN_BEGIN)

// This event is created when the Simple Cache finishes the OpenEntry call.
// It contains the following parameter:
// {
//   "net_error": <net error code returned from the call>
// }
EVENT_TYPE(SIMPLE_CACHE_ENTRY_OPEN_END)

// This event is created when CreateEntry is called.  It has no parameters.
EVENT_TYPE(SIMPLE_CACHE_ENTRY_CREATE_CALL)

// This event is created when the Simple Cache optimistically returns a result
// from a CreateEntry call before it performs the create operation.
// It contains the following parameter:
// {
//   "net_error": <net error code returned from the call>
// }
EVENT_TYPE(SIMPLE_CACHE_ENTRY_CREATE_OPTIMISTIC)

// This event is created when the Simple Cache actually begins creating the
// cache entry.  It has no parameters.
EVENT_TYPE(SIMPLE_CACHE_ENTRY_CREATE_BEGIN)

// This event is created when the Simple Cache finishes the CreateEntry call.
// It contains the following parameter:
// {
//   "net_error": <net error code returned from the call>
// }
EVENT_TYPE(SIMPLE_CACHE_ENTRY_CREATE_END)

// This event is created when ReadData is called.
// It contains the following parameters:
//   {
//     "index": <Index being read/written>,
//     "offset": <Offset being read/written>,
//     "buf_len": <Length of buffer being read to/written from>,
//   }
EVENT_TYPE(SIMPLE_CACHE_ENTRY_READ_CALL)

// This event is created when the Simple Cache actually begins reading data
// from the cache entry.
// It contains the following parameters:
//   {
//     "index": <Index being read/written>,
//     "offset": <Offset being read/written>,
//     "buf_len": <Length of buffer being read to/written from>,
//   }
EVENT_TYPE(SIMPLE_CACHE_ENTRY_READ_BEGIN)

// This event is created when the Simple Cache finishes a ReadData call.
// It contains the following parameters:
//   {
//     "bytes_copied": <Number of bytes copied.  Not present on error>,
//     "net_error": <Network error code.  Only present on error>,
//   }
EVENT_TYPE(SIMPLE_CACHE_ENTRY_READ_END)

// This event is created when the Simple Cache begins to verify the checksum of
// cached data it has just read.  It occurs before READ_END, and contains no
// parameters.
EVENT_TYPE(SIMPLE_CACHE_ENTRY_CHECKSUM_BEGIN)

// This event is created when the Simple Cache finishes verifying the checksum
// of cached data.  It occurs after CHECKSUM_BEGIN but before READ_END, and
// contains one parameter:
// {
//   "net_error": <net error code returned from the internal checksum call>
// }
EVENT_TYPE(SIMPLE_CACHE_ENTRY_CHECKSUM_END)

// This event is created when WriteData is called.
// It contains the following parameters:
//   {
//     "index": <Index being read/written>,
//     "offset": <Offset being read/written>,
//     "buf_len": <Length of buffer being read to/written from>,
//     "truncate": <If present for a write, the truncate flag is set to true.
//                  Not present in reads or writes where it is false>,
//   }
EVENT_TYPE(SIMPLE_CACHE_ENTRY_WRITE_CALL)

// This event is created when the Simple Cache optimistically returns a result
// from a WriteData call before it performs the write operation.
// It contains the following parameters:
//   {
//     "bytes_copied": <Number of bytes copied.  Not present on error>,
//     "net_error": <Network error code.  Only present on error>,
//   }
EVENT_TYPE(SIMPLE_CACHE_ENTRY_WRITE_OPTIMISTIC)

// This event is created when the Simple Cache actually begins writing data to
// the cache entry.
// It contains the following parameters:
//   {
//     "index": <Index being read/written>,
//     "offset": <Offset being read/written>,
//     "buf_len": <Length of buffer being read to/written from>,
//     "truncate": <If present for a write, the truncate flag is set to true.
//                  Not present in reads or writes where it is false>,
//   }
EVENT_TYPE(SIMPLE_CACHE_ENTRY_WRITE_BEGIN)

// This event is created when the Simple Cache finishes a WriteData call.
// It contains the following parameters:
//   {
//     "bytes_copied": <Number of bytes copied.  Not present on error>,
//     "net_error": <Network error code.  Only present on error>,
//   }
EVENT_TYPE(SIMPLE_CACHE_ENTRY_WRITE_END)

// This event is created when ReadSparseData is called.
// It contains the following parameters:
//   {
//     "offset": <Offset being read/written>,
//     "buf_len": <Length of buffer being read to/written from>,
//     "truncate": <If present for a write, the truncate flag is set to true.
//                  Not present in reads or writes where it is false>,
//   }
EVENT_TYPE(SIMPLE_CACHE_ENTRY_READ_SPARSE_CALL)

// This event is created when the Simple Cache actually begins reading sparse
// data from the cache entry.
// It contains the following parameters:
//   {
//     "offset": <Offset being read/written>,
//     "buf_len": <Length of buffer being read to/written from>,
//     "truncate": <If present for a write, the truncate flag is set to true.
//                  Not present in reads or writes where it is false>,
//   }
EVENT_TYPE(SIMPLE_CACHE_ENTRY_READ_SPARSE_BEGIN)

// This event is created when the Simple Cache finishes a ReadSparseData call.
// It contains the following parameters:
//   {
//     "bytes_copied": <Number of bytes copied.  Not present on error>,
//     "net_error": <Network error code.  Only present on error>,
//   }
EVENT_TYPE(SIMPLE_CACHE_ENTRY_READ_SPARSE_END)

// This event is created when WriteSparseData is called.
// It contains the following parameters:
//   {
//     "offset": <Offset being read/written>,
//     "buf_len": <Length of buffer being read to/written from>,
//   }
EVENT_TYPE(SIMPLE_CACHE_ENTRY_WRITE_SPARSE_CALL)

// This event is created when the Simple Cache actually begins writing sparse
// data to the cache entry.
// It contains the following parameters:
//   {
//     "offset": <Offset being read/written>,
//     "buf_len": <Length of buffer being read to/written from>,
//   }
EVENT_TYPE(SIMPLE_CACHE_ENTRY_WRITE_SPARSE_BEGIN)

// This event is created when the Simple Cache finishes a WriteSparseData call.
// It contains the following parameters:
//   {
//     "bytes_copied": <Number of bytes copied.  Not present on error>,
//     "net_error": <Network error code.  Only present on error>,
//   }
EVENT_TYPE(SIMPLE_CACHE_ENTRY_WRITE_SPARSE_END)

// This event is created when DoomEntry is called.  It contains no parameters.
EVENT_TYPE(SIMPLE_CACHE_ENTRY_DOOM_CALL)

// This event is created when the Simple Cache actually starts dooming a cache
// entry.  It contains no parameters.
EVENT_TYPE(SIMPLE_CACHE_ENTRY_DOOM_BEGIN)

// This event is created when the Simple Cache finishes dooming an entry.
EVENT_TYPE(SIMPLE_CACHE_ENTRY_DOOM_END)

// This event is created when CloseEntry is called.  It contains no parameters.
// A Close call may not result in CLOSE_BEGIN and CLOSE_END if there are still
// more references to the entry remaining.
EVENT_TYPE(SIMPLE_CACHE_ENTRY_CLOSE_CALL)

// This event is created when the Simple Cache actually starts closing a cache
// entry.  It contains no parameters.
EVENT_TYPE(SIMPLE_CACHE_ENTRY_CLOSE_BEGIN)

// This event is created when the Simple Cache finishes a CloseEntry call.  It
// contains no parameters.
EVENT_TYPE(SIMPLE_CACHE_ENTRY_CLOSE_END)

// ------------------------------------------------------------------------
// SDCH
// ------------------------------------------------------------------------

// This event is created when some problem occurs during sdch-encoded resource
// handling. It contains the following parameters:
//   {
//     "sdch_problem_code": <SDCH problem code>,
//     "net_error": <Always ERR_FAILED, present just to indicate this is a
//                   failure>,
//   }
EVENT_TYPE(SDCH_DECODING_ERROR)

// This event is created when SdchFilter initialization fails due to the
// response corruption. It contains the following parameters:
//   {
//     "cause": <Response corruption detection cause>,
//     "cached": <True if response was read from cache>,
//   }
EVENT_TYPE(SDCH_RESPONSE_CORRUPTION_DETECTION)

// This event is created when some problem occurs during sdch dictionary fetch.
// It contains the following parameters:
//   {
//     "dictionary_url": <Dictionary url>,
//     "sdch_problem_code": <SDCH problem code>,
//     "net_error": <Only present on unexpected errors. Always ERR_FAILED when
//                   present. Used to indicate this is a real failure>,
//   }
EVENT_TYPE(SDCH_DICTIONARY_ERROR)

// This event is created when SdchDictionaryFetcher starts fetch.  It contains
// no parameters.
EVENT_TYPE(SDCH_DICTIONARY_FETCH)

// This event is created if the SdchDictionaryFetcher URLRequest returns
// no error, but signals an error through bytes_read < 0.
// It contains the following parameters:
//   {
//     "net_error": <error created>
//   }
EVENT_TYPE(SDCH_DICTIONARY_FETCH_IMPLIED_ERROR)

// -----------------------------------------------------------------------------
// Data Reduction Proxy events.
// -----------------------------------------------------------------------------

// This event is created when the data reduction proxy has been turned on or
// off. It always contains the parameter:
//  {
//    "enabled": <true if the proxy is enabled>
//  }
//
// If it is enabled, it contains additional parameters:
//  {
//    "primary_restricted": <Whether the primary proxy is restricted or not>,
//    "fallback_restricted": <Whether the fallback proxy is restricted or not>,
//    "primary_origin": <The primary proxy origin address>,
//    "fallback_origin": <The fallback proxy origin address>,
//    "ssl_origin": <The SSL proxy origin address>,
//  }
EVENT_TYPE(DATA_REDUCTION_PROXY_ENABLED)

// The start/end of a canary request is sent to the data reduction proxy.
//
// The BEGIN phase contains the following parameters:
//  {
//    "url": <The URL of the canary endpoint>,
//  }
//
// The END phase contains the following parameters:
//  {
//    "net_error": <The net_error of the completion of the canary request>,
//    "http_response_code": <The HTTP response code of the canary request>,
//    "check_succeeded": <Whether a secure Data Reduction Proxy can be used or
//                        not>
//  }
EVENT_TYPE(DATA_REDUCTION_PROXY_CANARY_REQUEST)

// This event is created when a response to the canary request has been
// received with the following parameters:
//  {
//    "headers": <The list of header:value pairs>,
//  }
EVENT_TYPE(DATA_REDUCTION_PROXY_CANARY_RESPONSE_RECEIVED)

// This event is created when a bypass event takes place with the following
// parameters:
//  {
//    "action": <For DRP proxy sourced bypasses in the chrome-proxy header,
//               the bypass type>,
//    "bypass_type": <For non-DRP proxy sourced bypasses, the bypass type>,
//    "url": <The origin URL of the remote endpoint which resulted in the
//            bypass>,
//    "bypass_duration_seconds": <The length of time to be in a bypass state>,
//  }
EVENT_TYPE(DATA_REDUCTION_PROXY_BYPASS_REQUESTED)

// This event is created when the data reduction proxy configuration changes
// (i.e. a switch between primary and fallback) with the following parameters:
//  {
//    "proxy_server": <The URL of the proxy server no longer being used>,
//    "net_error": <The net_error encountered when using the proxy server; this
//                  can be 0 if the proxy server is explicitly skipped>,
//  }
EVENT_TYPE(DATA_REDUCTION_PROXY_FALLBACK)

// The start/end of a config request is sent to the Data Saver Config API
// service.
//
// The BEGIN phase contains the following parameters:
//  {
//    "url": <The URL of the service endpoint>,
//  }
//
// The END phase contains the following parameters:
//  {
//    "net_error": <The net_error of the completion of the config request>,
//    "http_response_code": <The HTTP response code of the config request>,
//    "failure_count": <The number of consecutive config request failures>,
//    "retry_delay_seconds": <The length of time after which another config
//                            request will be made>,
//  }
EVENT_TYPE(DATA_REDUCTION_PROXY_CONFIG_REQUEST)

// -----------------------------------------------------------------------------
// Safe Browsing related events
// -----------------------------------------------------------------------------

// The start/end of an async URL check by Safe Browsing. Will only show up if
// it can't be classified as "safe" synchronously.
//
// The BEGIN phase contains the following parameters:
//  {
//    "url": <The URL being checked>,
//  }
//
// The END phase contains the following parameters:
//  {
//    "result": <"safe", "unsafe", or "request_canceled">
//  }
EVENT_TYPE(SAFE_BROWSING_CHECKING_URL)

// The start/end of some portion of the SAFE_BROWSING_CHECKING_URL during which
// the request is delayed due to that check.
//
// The BEGIN phase contains the following parameters:
//  {
//    "url": <The URL being checked>,
//    "defer_reason" : < "at_start", "at_response", "redirect",
//                       "resumed_redirect", "unchecked_redirect">
//  }
EVENT_TYPE(SAFE_BROWSING_DEFERRED)

// The start/end of a Safe Browsing ping being sent.
//
// The BEGIN phase contains the following parameters:
//  {
//    "url": <The URL the ping is going to, which identifies the type of ping
//            that is being sent (eg: ThreatReport, SafeBrowsingHit)>
//    "data": <The base64 encoding of the payload sent with the ping>
//
// The END phase contains the following parameters:
//  {
//    "status": <The integer status of the report transmission. Corresponds to
//               URLRequestStatus::Status>
//    "error": <The error code returned by the server, 0 indicating success>
EVENT_TYPE(SAFE_BROWSING_PING)

// Marks start of UploadDataStream that is logged on initialization.
// The END phase contains the following parameters:
// {
//   "net_error": <Result of the initialization step>,
//   "total_size": <Shows total content length>,
//   "is_chunked": <Shows whether data is chunked or not>
// }
EVENT_TYPE(UPLOAD_DATA_STREAM_INIT)

// The start/end of UploadDataStream::Read method.
//
// The BEGIN phase contains the following information:
// {
//   "current_position": <Shows current read position>,
// }
//
// The END phase contains the following information:
// {
//   "result": <Result of reading. Result > 0 is bytes read. Result == 0 means
//              the end of file. Result < 0 means an error.>
// }
EVENT_TYPE(UPLOAD_DATA_STREAM_READ)

// -----------------------------------------------------------------------------
// ResourceScheduler related events
// -----------------------------------------------------------------------------

// The ResourceScheduler has started a previously blocked request.  Parameters:
// {
//   "trigger": <Trigger for evaluation that caused request start>
// }
EVENT_TYPE(RESOURCE_SCHEDULER_REQUEST_STARTED)
