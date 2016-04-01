// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TOOLS_QUIC_TEST_TOOLS_SIMPLE_CLIENT_H_
#define NET_TOOLS_QUIC_TEST_TOOLS_SIMPLE_CLIENT_H_

#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

#include "net/base/ip_address.h"
#include "net/base/ip_endpoint.h"
#include "net/tools/balsa/balsa_frame.h"

namespace net {
namespace test {

class HTTPMessage;

class SimpleClient {
 public:
  virtual ~SimpleClient() {}

  // Clears any outstanding state and sends 'size' bytes from 'buffer' to the
  // server, possibly with multiple send operations.  Returns 'size' on success
  // and -1 on error.  Callers should assume that any return value other than
  // 'size' indicates failure.
  virtual ssize_t Send(const void* buffer, size_t size) = 0;

  // Serialize and send an HTTP request.
  virtual ssize_t SendMessage(const HTTPMessage& message) = 0;

  // Clears any outstanding state, sends 'size' bytes from 'buffer' and waits
  // for a response or an error.
  virtual ssize_t SendAndWaitForResponse(const void* buffer, size_t size) = 0;

  // Clears any outstanding state and sends a simple GET of 'uri' to the
  // server.
  virtual ssize_t SendRequest(const std::string& uri) = 0;

  // The response body is returned as a string.
  virtual std::string SendCustomSynchronousRequest(
      const HTTPMessage& message) = 0;
  virtual std::string SendSynchronousRequest(const std::string& url) = 0;

  // Returns once a complete response or a connection close has been received
  // from the server.
  virtual void WaitForResponse();

  // Waits for some data or response from the server.
  virtual void WaitForInitialResponse();

  // Returns once a complete response or a connection close has been received
  // from the server, or once the timeout expires. -1 for no timeout.
  virtual void WaitForResponseForMs(int timeout_ms) = 0;

  // Waits for some data or response from the server, or once the timeout
  // expires. -1 for no timeout.
  virtual void WaitForInitialResponseForMs(int timeout_ms) = 0;

  // Clears any outstanding state from the last request.
  virtual void ClearPerRequestState() = 0;

  // Closes and reopens the connection to the server.
  virtual void ResetConnection() = 0;

  // Closes the connection to the server.
  virtual void Disconnect() = 0;

  // Both will return 0 on success, -1 otherwise.
  // Sends out RST packet to peer.
  // TODO(yongfa): Probably should be an interface too. LOG(FATAL) here
  // to prevent accidental invocation.
  virtual int ResetSocket();

  virtual int HalfClose();

  // Connects to the server.  This should be done implicitly by Send*
  // functions, but can be done explicitly as well.
  virtual void Connect() = 0;

  // Bind to the specified address.  If set_bind_to_address() is called, this
  // is called automatically on connect, but can be done explicitly to make
  // LocalIPEndPoint() meaningful before actually connecting.
  // Sets *local_address to the actual address bound to, which can be different
  // if the given address has port 0.
  virtual void Bind(IPEndPoint* local_address) = 0;

  virtual void MigrateSocket(const IPAddress& new_host) = 0;

  // Returns the local socket address of the client fd. Call only when
  // connected.
  // To get the local IPAdress, use local_address().host().
  // To get the local port, use local_address.port().
  virtual IPEndPoint local_address() const = 0;

  // Returns the serialized message that would be sent by any of the HTTPMessage
  // functions above.
  virtual std::string SerializeMessage(const HTTPMessage& message) = 0;

  // Sets the IP address to bind to on future Connect()s in case Bind() is not
  // called in advance. If it's set to uninitialized IPAddress, default loopback
  // address will be used.
  virtual IPAddress bind_to_address() const = 0;
  virtual void set_bind_to_address(const IPAddress& address) = 0;

  // Returns true if the headers have been processed and are available.
  virtual bool response_headers_complete() const = 0;

  // Returns the response headers, if a response was completely framed.
  // Undefined behavior otherwise.
  virtual const BalsaHeaders* response_headers() const = 0;

  // Returns true iff response has been fully received.
  virtual bool response_complete() const = 0;

  // Returns the number of bytes read from the server during this request.
  virtual int64_t response_size() const = 0;

  // Returns the number of header bytes received during this request, if
  // meaningful for the protocol.
  virtual int response_header_size() const;

  // Returns the number of body bytes received during this request, if
  // meaningful for the protocol.
  virtual int64_t response_body_size() const;

  // Returns the response body, if there was one. If there was no response, or
  // if buffer_body() is false, returns an empty string.
  virtual const std::string& response_body() = 0;

  // The address the client is connected to.
  virtual const IPEndPoint& address() const = 0;

  // Returns true if the client is connected, false otherwise.
  virtual bool connected() const = 0;

  // Returns true if the server has informed the client that it is
  // in "lame duck" mode, indicating intent to shut down and
  // requesting that no further connections be established.
  virtual bool ServerInLameDuckMode() const = 0;

  // Return the number of bytes read off the wire by this client.
  virtual size_t bytes_read() const = 0;

  // Returns the number of bytes written to the wire by this client.
  virtual size_t bytes_written() const = 0;

  // Return the number of requests sent.
  virtual size_t requests_sent() const = 0;

  // Instructs the client to populate response_body().
  virtual bool buffer_body() const = 0;
  virtual void set_buffer_body(bool buffer_body) = 0;
};

}  // namespace test
}  // namespace net

#endif  // NET_TOOLS_QUIC_TEST_TOOLS_SIMPLE_CLIENT_H_
