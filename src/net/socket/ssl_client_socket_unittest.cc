// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/socket/ssl_client_socket.h"

#include <errno.h>
#include <string.h>

#include <utility>

#include "base/callback_helpers.h"
#include "base/files/file_util.h"
#include "base/location.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/message_loop/message_loop.h"
#include "base/run_loop.h"
#include "base/single_thread_task_runner.h"
#include "base/test/scoped_task_scheduler.h"
#include "base/threading/thread_task_runner_handle.h"
#include "base/time/time.h"
#include "base/values.h"
#include "net/base/address_list.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/cert/asn1_util.h"
#include "net/cert/ct_policy_enforcer.h"
#include "net/cert/ct_policy_status.h"
#include "net/cert/ct_verifier.h"
#include "net/cert/do_nothing_ct_verifier.h"
#include "net/cert/mock_cert_verifier.h"
#include "net/cert/signed_certificate_timestamp_and_status.h"
#include "net/cert/test_root_certs.h"
#include "net/der/input.h"
#include "net/der/parser.h"
#include "net/der/tag.h"
#include "net/dns/host_resolver.h"
#include "net/http/transport_security_state.h"
#include "net/log/net_log_event_type.h"
#include "net/log/net_log_source.h"
#include "net/log/test_net_log.h"
#include "net/log/test_net_log_entry.h"
#include "net/log/test_net_log_util.h"
#include "net/socket/client_socket_factory.h"
#include "net/socket/client_socket_handle.h"
#include "net/socket/socket_test_util.h"
#include "net/socket/stream_socket.h"
#include "net/socket/tcp_client_socket.h"
#include "net/ssl/channel_id_service.h"
#include "net/ssl/default_channel_id_store.h"
#include "net/ssl/ssl_cert_request_info.h"
#include "net/ssl/ssl_config_service.h"
#include "net/ssl/ssl_connection_status_flags.h"
#include "net/ssl/ssl_info.h"
#include "net/ssl/test_ssl_private_key.h"
#include "net/test/cert_test_util.h"
#include "net/test/gtest_util.h"
#include "net/test/spawned_test_server/spawned_test_server.h"
#include "net/test/test_data_directory.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "testing/platform_test.h"
#include "third_party/boringssl/src/include/openssl/bio.h"
#include "third_party/boringssl/src/include/openssl/evp.h"
#include "third_party/boringssl/src/include/openssl/pem.h"

using net::test::IsError;
using net::test::IsOk;

using testing::_;
using testing::Return;
using testing::Truly;

namespace net {

class NetLogWithSource;

namespace {

// WrappedStreamSocket is a base class that wraps an existing StreamSocket,
// forwarding the Socket and StreamSocket interfaces to the underlying
// transport.
// This is to provide a common base class for subclasses to override specific
// StreamSocket methods for testing, while still communicating with a 'real'
// StreamSocket.
class WrappedStreamSocket : public StreamSocket {
 public:
  explicit WrappedStreamSocket(std::unique_ptr<StreamSocket> transport)
      : transport_(std::move(transport)) {}
  ~WrappedStreamSocket() override {}

  // StreamSocket implementation:
  int Connect(const CompletionCallback& callback) override {
    return transport_->Connect(callback);
  }
  void Disconnect() override { transport_->Disconnect(); }
  bool IsConnected() const override { return transport_->IsConnected(); }
  bool IsConnectedAndIdle() const override {
    return transport_->IsConnectedAndIdle();
  }
  int GetPeerAddress(IPEndPoint* address) const override {
    return transport_->GetPeerAddress(address);
  }
  int GetLocalAddress(IPEndPoint* address) const override {
    return transport_->GetLocalAddress(address);
  }
  const NetLogWithSource& NetLog() const override {
    return transport_->NetLog();
  }
  void SetSubresourceSpeculation() override {
    transport_->SetSubresourceSpeculation();
  }
  void SetOmniboxSpeculation() override { transport_->SetOmniboxSpeculation(); }
  bool WasEverUsed() const override { return transport_->WasEverUsed(); }
  bool WasAlpnNegotiated() const override {
    return transport_->WasAlpnNegotiated();
  }
  NextProto GetNegotiatedProtocol() const override {
    return transport_->GetNegotiatedProtocol();
  }
  bool GetSSLInfo(SSLInfo* ssl_info) override {
    return transport_->GetSSLInfo(ssl_info);
  }
  void GetConnectionAttempts(ConnectionAttempts* out) const override {
    transport_->GetConnectionAttempts(out);
  }
  void ClearConnectionAttempts() override {
    transport_->ClearConnectionAttempts();
  }
  void AddConnectionAttempts(const ConnectionAttempts& attempts) override {
    transport_->AddConnectionAttempts(attempts);
  }
  int64_t GetTotalReceivedBytes() const override {
    return transport_->GetTotalReceivedBytes();
  }

  // Socket implementation:
  int Read(IOBuffer* buf,
           int buf_len,
           const CompletionCallback& callback) override {
    return transport_->Read(buf, buf_len, callback);
  }
  int Write(IOBuffer* buf,
            int buf_len,
            const CompletionCallback& callback) override {
    return transport_->Write(buf, buf_len, callback);
  }
  int SetReceiveBufferSize(int32_t size) override {
    return transport_->SetReceiveBufferSize(size);
  }
  int SetSendBufferSize(int32_t size) override {
    return transport_->SetSendBufferSize(size);
  }

 protected:
  std::unique_ptr<StreamSocket> transport_;
};

// ReadBufferingStreamSocket is a wrapper for an existing StreamSocket that
// will ensure a certain amount of data is internally buffered before
// satisfying a Read() request. It exists to mimic OS-level internal
// buffering, but in a way to guarantee that X number of bytes will be
// returned to callers of Read(), regardless of how quickly the OS receives
// them from the TestServer.
class ReadBufferingStreamSocket : public WrappedStreamSocket {
 public:
  explicit ReadBufferingStreamSocket(std::unique_ptr<StreamSocket> transport);
  ~ReadBufferingStreamSocket() override {}

  // Socket implementation:
  int Read(IOBuffer* buf,
           int buf_len,
           const CompletionCallback& callback) override;

  // Sets the internal buffer to |size|. This must not be greater than
  // the largest value supplied to Read() - that is, it does not handle
  // having "leftovers" at the end of Read().
  // Each call to Read() will be prevented from completion until at least
  // |size| data has been read.
  // Set to 0 to turn off buffering, causing Read() to transparently
  // read via the underlying transport.
  void SetBufferSize(int size);

 private:
  enum State {
    STATE_NONE,
    STATE_READ,
    STATE_READ_COMPLETE,
  };

  int DoLoop(int result);
  int DoRead();
  int DoReadComplete(int result);
  void OnReadCompleted(int result);

  State state_;
  scoped_refptr<GrowableIOBuffer> read_buffer_;
  int buffer_size_;

  scoped_refptr<IOBuffer> user_read_buf_;
  CompletionCallback user_read_callback_;
};

ReadBufferingStreamSocket::ReadBufferingStreamSocket(
    std::unique_ptr<StreamSocket> transport)
    : WrappedStreamSocket(std::move(transport)),
      read_buffer_(new GrowableIOBuffer()),
      buffer_size_(0) {}

void ReadBufferingStreamSocket::SetBufferSize(int size) {
  DCHECK(!user_read_buf_.get());
  buffer_size_ = size;
  read_buffer_->SetCapacity(size);
}

int ReadBufferingStreamSocket::Read(IOBuffer* buf,
                                    int buf_len,
                                    const CompletionCallback& callback) {
  if (buffer_size_ == 0)
    return transport_->Read(buf, buf_len, callback);

  if (buf_len < buffer_size_)
    return ERR_UNEXPECTED;

  state_ = STATE_READ;
  user_read_buf_ = buf;
  int result = DoLoop(OK);
  if (result == ERR_IO_PENDING)
    user_read_callback_ = callback;
  else
    user_read_buf_ = NULL;
  return result;
}

int ReadBufferingStreamSocket::DoLoop(int result) {
  int rv = result;
  do {
    State current_state = state_;
    state_ = STATE_NONE;
    switch (current_state) {
      case STATE_READ:
        rv = DoRead();
        break;
      case STATE_READ_COMPLETE:
        rv = DoReadComplete(rv);
        break;
      case STATE_NONE:
      default:
        NOTREACHED() << "Unexpected state: " << current_state;
        rv = ERR_UNEXPECTED;
        break;
    }
  } while (rv != ERR_IO_PENDING && state_ != STATE_NONE);
  return rv;
}

int ReadBufferingStreamSocket::DoRead() {
  state_ = STATE_READ_COMPLETE;
  int rv =
      transport_->Read(read_buffer_.get(),
                       read_buffer_->RemainingCapacity(),
                       base::Bind(&ReadBufferingStreamSocket::OnReadCompleted,
                                  base::Unretained(this)));
  return rv;
}

int ReadBufferingStreamSocket::DoReadComplete(int result) {
  state_ = STATE_NONE;
  if (result <= 0)
    return result;

  read_buffer_->set_offset(read_buffer_->offset() + result);
  if (read_buffer_->RemainingCapacity() > 0) {
    state_ = STATE_READ;
    return OK;
  }

  memcpy(user_read_buf_->data(),
         read_buffer_->StartOfBuffer(),
         read_buffer_->capacity());
  read_buffer_->set_offset(0);
  return read_buffer_->capacity();
}

void ReadBufferingStreamSocket::OnReadCompleted(int result) {
  result = DoLoop(result);
  if (result == ERR_IO_PENDING)
    return;

  user_read_buf_ = NULL;
  base::ResetAndReturn(&user_read_callback_).Run(result);
}

// Simulates synchronously receiving an error during Read() or Write()
class SynchronousErrorStreamSocket : public WrappedStreamSocket {
 public:
  explicit SynchronousErrorStreamSocket(std::unique_ptr<StreamSocket> transport)
      : WrappedStreamSocket(std::move(transport)) {}
  ~SynchronousErrorStreamSocket() override {}

  // Socket implementation:
  int Read(IOBuffer* buf,
           int buf_len,
           const CompletionCallback& callback) override;
  int Write(IOBuffer* buf,
            int buf_len,
            const CompletionCallback& callback) override;

  // Sets the next Read() call and all future calls to return |error|.
  // If there is already a pending asynchronous read, the configured error
  // will not be returned until that asynchronous read has completed and Read()
  // is called again.
  void SetNextReadError(int error) {
    DCHECK_GE(0, error);
    have_read_error_ = true;
    pending_read_error_ = error;
  }

  // Sets the next Write() call and all future calls to return |error|.
  // If there is already a pending asynchronous write, the configured error
  // will not be returned until that asynchronous write has completed and
  // Write() is called again.
  void SetNextWriteError(int error) {
    DCHECK_GE(0, error);
    have_write_error_ = true;
    pending_write_error_ = error;
  }

 private:
  bool have_read_error_ = false;
  int pending_read_error_ = OK;

  bool have_write_error_ = false;
  int pending_write_error_ = OK;

  DISALLOW_COPY_AND_ASSIGN(SynchronousErrorStreamSocket);
};

int SynchronousErrorStreamSocket::Read(IOBuffer* buf,
                                       int buf_len,
                                       const CompletionCallback& callback) {
  if (have_read_error_)
    return pending_read_error_;
  return transport_->Read(buf, buf_len, callback);
}

int SynchronousErrorStreamSocket::Write(IOBuffer* buf,
                                        int buf_len,
                                        const CompletionCallback& callback) {
  if (have_write_error_)
    return pending_write_error_;
  return transport_->Write(buf, buf_len, callback);
}

// FakeBlockingStreamSocket wraps an existing StreamSocket and simulates the
// underlying transport needing to complete things asynchronously in a
// deterministic manner (e.g.: independent of the TestServer and the OS's
// semantics).
class FakeBlockingStreamSocket : public WrappedStreamSocket {
 public:
  explicit FakeBlockingStreamSocket(std::unique_ptr<StreamSocket> transport)
      : WrappedStreamSocket(std::move(transport)) {}
  ~FakeBlockingStreamSocket() override {}

  // Socket implementation:
  int Read(IOBuffer* buf,
           int buf_len,
           const CompletionCallback& callback) override;
  int Write(IOBuffer* buf,
            int buf_len,
            const CompletionCallback& callback) override;

  int pending_read_result() const { return pending_read_result_; }
  IOBuffer* pending_read_buf() const { return pending_read_buf_.get(); }

  // Blocks read results on the socket. Reads will not complete until
  // UnblockReadResult() has been called and a result is ready from the
  // underlying transport. Note: if BlockReadResult() is called while there is a
  // hanging asynchronous Read(), that Read is blocked.
  void BlockReadResult();
  void UnblockReadResult();

  // Replaces the pending read with |data|. Returns true on success or false if
  // the caller's reads were too small.
  bool ReplaceReadResult(const std::string& data);

  // Waits for the blocked Read() call to be complete at the underlying
  // transport.
  void WaitForReadResult();

  // Causes the next call to Write() to return ERR_IO_PENDING, not beginning the
  // underlying transport until UnblockWrite() has been called. Note: if there
  // is a pending asynchronous write, it is NOT blocked. For purposes of
  // blocking writes, data is considered to have reached the underlying
  // transport as soon as Write() is called.
  void BlockWrite();
  void UnblockWrite();

  // Waits for the blocked Write() call to be scheduled.
  void WaitForWrite();

 private:
  // Handles completion from the underlying transport read.
  void OnReadCompleted(int result);

  // Finishes the current read.
  void ReturnReadResult();

  // True if read callbacks are blocked.
  bool should_block_read_ = false;

  // The buffer for the pending read, or NULL if not consumed.
  scoped_refptr<IOBuffer> pending_read_buf_;

  // The size of the pending read buffer, or -1 if not set.
  int pending_read_buf_len_ = -1;

  // The user callback for the pending read call.
  CompletionCallback pending_read_callback_;

  // The result for the blocked read callback, or ERR_IO_PENDING if not
  // completed.
  int pending_read_result_ = ERR_IO_PENDING;

  // WaitForReadResult() wait loop.
  std::unique_ptr<base::RunLoop> read_loop_;

  // True if write calls are blocked.
  bool should_block_write_ = false;

  // The buffer for the pending write, or NULL if not scheduled.
  scoped_refptr<IOBuffer> pending_write_buf_;

  // The callback for the pending write call.
  CompletionCallback pending_write_callback_;

  // The length for the pending write, or -1 if not scheduled.
  int pending_write_len_ = -1;

  // WaitForWrite() wait loop.
  std::unique_ptr<base::RunLoop> write_loop_;
};

int FakeBlockingStreamSocket::Read(IOBuffer* buf,
                                   int len,
                                   const CompletionCallback& callback) {
  DCHECK(!pending_read_buf_);
  DCHECK(pending_read_callback_.is_null());
  DCHECK_EQ(ERR_IO_PENDING, pending_read_result_);
  DCHECK(!callback.is_null());

  int rv = transport_->Read(buf, len, base::Bind(
      &FakeBlockingStreamSocket::OnReadCompleted, base::Unretained(this)));
  if (rv == ERR_IO_PENDING || should_block_read_) {
    // Save the callback to be called later.
    pending_read_buf_ = buf;
    pending_read_buf_len_ = len;
    pending_read_callback_ = callback;
    // Save the read result.
    if (rv != ERR_IO_PENDING) {
      OnReadCompleted(rv);
      rv = ERR_IO_PENDING;
    }
  }
  return rv;
}

int FakeBlockingStreamSocket::Write(IOBuffer* buf,
                                    int len,
                                    const CompletionCallback& callback) {
  DCHECK(buf);
  DCHECK_LE(0, len);

  if (!should_block_write_)
    return transport_->Write(buf, len, callback);

  // Schedule the write, but do nothing.
  DCHECK(!pending_write_buf_.get());
  DCHECK_EQ(-1, pending_write_len_);
  DCHECK(pending_write_callback_.is_null());
  DCHECK(!callback.is_null());
  pending_write_buf_ = buf;
  pending_write_len_ = len;
  pending_write_callback_ = callback;

  // Stop the write loop, if any.
  if (write_loop_)
    write_loop_->Quit();
  return ERR_IO_PENDING;
}

void FakeBlockingStreamSocket::BlockReadResult() {
  DCHECK(!should_block_read_);
  should_block_read_ = true;
}

void FakeBlockingStreamSocket::UnblockReadResult() {
  DCHECK(should_block_read_);
  should_block_read_ = false;

  // If the operation has since completed, return the result to the caller.
  if (pending_read_result_ != ERR_IO_PENDING)
    ReturnReadResult();
}

bool FakeBlockingStreamSocket::ReplaceReadResult(const std::string& data) {
  DCHECK(should_block_read_);
  DCHECK_NE(ERR_IO_PENDING, pending_read_result_);
  DCHECK(pending_read_buf_);
  DCHECK_NE(-1, pending_read_buf_len_);

  if (static_cast<size_t>(pending_read_buf_len_) < data.size())
    return false;

  memcpy(pending_read_buf_->data(), data.data(), data.size());
  pending_read_result_ = data.size();
  return true;
}

void FakeBlockingStreamSocket::WaitForReadResult() {
  DCHECK(should_block_read_);
  DCHECK(!read_loop_);

  if (pending_read_result_ != ERR_IO_PENDING)
    return;
  read_loop_.reset(new base::RunLoop);
  read_loop_->Run();
  read_loop_.reset();
  DCHECK_NE(ERR_IO_PENDING, pending_read_result_);
}

void FakeBlockingStreamSocket::BlockWrite() {
  DCHECK(!should_block_write_);
  should_block_write_ = true;
}

void FakeBlockingStreamSocket::UnblockWrite() {
  DCHECK(should_block_write_);
  should_block_write_ = false;

  // Do nothing if UnblockWrite() was called after BlockWrite(),
  // without a Write() in between.
  if (!pending_write_buf_.get())
    return;

  int rv = transport_->Write(
      pending_write_buf_.get(), pending_write_len_, pending_write_callback_);
  pending_write_buf_ = NULL;
  pending_write_len_ = -1;
  if (rv == ERR_IO_PENDING) {
    pending_write_callback_.Reset();
  } else {
    base::ResetAndReturn(&pending_write_callback_).Run(rv);
  }
}

void FakeBlockingStreamSocket::WaitForWrite() {
  DCHECK(should_block_write_);
  DCHECK(!write_loop_);

  if (pending_write_buf_.get())
    return;
  write_loop_.reset(new base::RunLoop);
  write_loop_->Run();
  write_loop_.reset();
  DCHECK(pending_write_buf_.get());
}

void FakeBlockingStreamSocket::OnReadCompleted(int result) {
  DCHECK_EQ(ERR_IO_PENDING, pending_read_result_);
  DCHECK(!pending_read_callback_.is_null());

  pending_read_result_ = result;

  if (should_block_read_) {
    // Defer the result until UnblockReadResult is called.
    if (read_loop_)
      read_loop_->Quit();
    return;
  }

  ReturnReadResult();
}

void FakeBlockingStreamSocket::ReturnReadResult() {
  int result = pending_read_result_;
  pending_read_result_ = ERR_IO_PENDING;
  pending_read_buf_ = nullptr;
  pending_read_buf_len_ = -1;
  base::ResetAndReturn(&pending_read_callback_).Run(result);
}

// CountingStreamSocket wraps an existing StreamSocket and maintains a count of
// reads and writes on the socket.
class CountingStreamSocket : public WrappedStreamSocket {
 public:
  explicit CountingStreamSocket(std::unique_ptr<StreamSocket> transport)
      : WrappedStreamSocket(std::move(transport)),
        read_count_(0),
        write_count_(0) {}
  ~CountingStreamSocket() override {}

  // Socket implementation:
  int Read(IOBuffer* buf,
           int buf_len,
           const CompletionCallback& callback) override {
    read_count_++;
    return transport_->Read(buf, buf_len, callback);
  }
  int Write(IOBuffer* buf,
            int buf_len,
            const CompletionCallback& callback) override {
    write_count_++;
    return transport_->Write(buf, buf_len, callback);
  }

  int read_count() const { return read_count_; }
  int write_count() const { return write_count_; }

 private:
  int read_count_;
  int write_count_;
};

// CompletionCallback that will delete the associated StreamSocket when
// the callback is invoked.
class DeleteSocketCallback : public TestCompletionCallbackBase {
 public:
  explicit DeleteSocketCallback(StreamSocket* socket)
      : socket_(socket),
        callback_(base::Bind(&DeleteSocketCallback::OnComplete,
                             base::Unretained(this))) {}
  ~DeleteSocketCallback() override {}

  const CompletionCallback& callback() const { return callback_; }

 private:
  void OnComplete(int result) {
    if (socket_) {
      delete socket_;
      socket_ = NULL;
    } else {
      ADD_FAILURE() << "Deleting socket twice";
    }
    SetResult(result);
  }

  StreamSocket* socket_;
  CompletionCallback callback_;

  DISALLOW_COPY_AND_ASSIGN(DeleteSocketCallback);
};

// A ChannelIDStore that always returns an error when asked for a
// channel id.
class FailingChannelIDStore : public ChannelIDStore {
  int GetChannelID(const std::string& server_identifier,
                   std::unique_ptr<crypto::ECPrivateKey>* key_result,
                   const GetChannelIDCallback& callback) override {
    return ERR_UNEXPECTED;
  }
  void SetChannelID(std::unique_ptr<ChannelID> channel_id) override {}
  void DeleteChannelID(const std::string& server_identifier,
                       const base::Closure& completion_callback) override {}
  void DeleteForDomainsCreatedBetween(
      const base::Callback<bool(const std::string&)>& domain_predicate,
      base::Time delete_begin,
      base::Time delete_end,
      const base::Closure& completion_callback) override {}
  void DeleteAll(const base::Closure& completion_callback) override {}
  void GetAllChannelIDs(const GetChannelIDListCallback& callback) override {}
  int GetChannelIDCount() override { return 0; }
  void SetForceKeepSessionState() override {}
  bool IsEphemeral() override { return true; }
};

// A ChannelIDStore that asynchronously returns an error when asked for a
// channel id.
class AsyncFailingChannelIDStore : public ChannelIDStore {
  int GetChannelID(const std::string& server_identifier,
                   std::unique_ptr<crypto::ECPrivateKey>* key_result,
                   const GetChannelIDCallback& callback) override {
    base::ThreadTaskRunnerHandle::Get()->PostTask(
        FROM_HERE,
        base::Bind(callback, ERR_UNEXPECTED, server_identifier, nullptr));
    return ERR_IO_PENDING;
  }
  void SetChannelID(std::unique_ptr<ChannelID> channel_id) override {}
  void DeleteChannelID(const std::string& server_identifier,
                       const base::Closure& completion_callback) override {}
  void DeleteForDomainsCreatedBetween(
      const base::Callback<bool(const std::string&)>& domain_predicate,
      base::Time delete_begin,
      base::Time delete_end,
      const base::Closure& completion_callback) override {}
  void DeleteAll(const base::Closure& completion_callback) override {}
  void GetAllChannelIDs(const GetChannelIDListCallback& callback) override {}
  int GetChannelIDCount() override { return 0; }
  void SetForceKeepSessionState() override {}
  bool IsEphemeral() override { return true; }
};

// A mock CTVerifier that records every call to Verify but doesn't verify
// anything.
class MockCTVerifier : public CTVerifier {
 public:
  MOCK_METHOD5(Verify,
               void(X509Certificate*,
                    base::StringPiece,
                    base::StringPiece,
                    SignedCertificateTimestampAndStatusList*,
                    const NetLogWithSource&));
  MOCK_METHOD1(SetObserver, void(CTVerifier::Observer*));
};

// A mock CTPolicyEnforcer that returns a custom verification result.
class MockCTPolicyEnforcer : public CTPolicyEnforcer {
 public:
  MOCK_METHOD3(DoesConformToCertPolicy,
               ct::CertPolicyCompliance(X509Certificate* cert,
                                        const ct::SCTList&,
                                        const NetLogWithSource&));
  MOCK_METHOD4(DoesConformToCTEVPolicy,
               ct::EVPolicyCompliance(X509Certificate* cert,
                                      const ct::EVCertsWhitelist*,
                                      const ct::SCTList&,
                                      const NetLogWithSource&));
};

class MockRequireCTDelegate : public TransportSecurityState::RequireCTDelegate {
 public:
  MOCK_METHOD1(IsCTRequiredForHost,
               CTRequirementLevel(const std::string& host));
};

class SSLClientSocketTest : public PlatformTest {
 public:
  SSLClientSocketTest()
      : socket_factory_(ClientSocketFactory::GetDefaultFactory()),
        cert_verifier_(new MockCertVerifier),
        transport_security_state_(new TransportSecurityState),
        ct_verifier_(new DoNothingCTVerifier),
        ct_policy_enforcer_(new MockCTPolicyEnforcer) {
    cert_verifier_->set_default_result(OK);
    context_.cert_verifier = cert_verifier_.get();
    context_.transport_security_state = transport_security_state_.get();
    context_.cert_transparency_verifier = ct_verifier_.get();
    context_.ct_policy_enforcer = ct_policy_enforcer_.get();

    EXPECT_CALL(*ct_policy_enforcer_, DoesConformToCertPolicy(_, _, _))
        .WillRepeatedly(
            Return(ct::CertPolicyCompliance::CERT_POLICY_COMPLIES_VIA_SCTS));
    EXPECT_CALL(*ct_policy_enforcer_, DoesConformToCTEVPolicy(_, _, _, _))
        .WillRepeatedly(
            Return(ct::EVPolicyCompliance::EV_POLICY_COMPLIES_VIA_SCTS));
  }

 protected:
  // The address of the spawned test server, after calling StartTestServer().
  const AddressList& addr() const { return addr_; }

  // The SpawnedTestServer object, after calling StartTestServer().
  const SpawnedTestServer* spawned_test_server() const {
    return spawned_test_server_.get();
  }

  void SetCTVerifier(CTVerifier* ct_verifier) {
    context_.cert_transparency_verifier = ct_verifier;
  }

  void SetCTPolicyEnforcer(CTPolicyEnforcer* policy_enforcer) {
    context_.ct_policy_enforcer = policy_enforcer;
  }

  // Starts the test server with SSL configuration |ssl_options|. Returns true
  // on success.
  bool StartTestServer(const SpawnedTestServer::SSLOptions& ssl_options) {
    spawned_test_server_.reset(new SpawnedTestServer(
        SpawnedTestServer::TYPE_HTTPS, ssl_options, base::FilePath()));
    if (!spawned_test_server_->Start()) {
      LOG(ERROR) << "Could not start SpawnedTestServer";
      return false;
    }

    if (!spawned_test_server_->GetAddressList(&addr_)) {
      LOG(ERROR) << "Could not get SpawnedTestServer address list";
      return false;
    }
    return true;
  }

  std::unique_ptr<SSLClientSocket> CreateSSLClientSocket(
      std::unique_ptr<StreamSocket> transport_socket,
      const HostPortPair& host_and_port,
      const SSLConfig& ssl_config) {
    std::unique_ptr<ClientSocketHandle> connection(new ClientSocketHandle);
    connection->SetSocket(std::move(transport_socket));
    return socket_factory_->CreateSSLClientSocket(
        std::move(connection), host_and_port, ssl_config, context_);
  }

  // Create an SSLClientSocket object and use it to connect to a test
  // server, then wait for connection results. This must be called after
  // a successful StartTestServer() call.
  // |ssl_config| the SSL configuration to use.
  // |result| will retrieve the ::Connect() result value.
  // Returns true on success, false otherwise. Success means that the SSL socket
  // could be created and its Connect() was called, not that the connection
  // itself was a success.
  bool CreateAndConnectSSLClientSocket(const SSLConfig& ssl_config,
                                       int* result) {
    std::unique_ptr<StreamSocket> transport(
        new TCPClientSocket(addr_, NULL, &log_, NetLogSource()));
    int rv = callback_.GetResult(transport->Connect(callback_.callback()));
    if (rv != OK) {
      LOG(ERROR) << "Could not connect to SpawnedTestServer";
      return false;
    }

    sock_ = CreateSSLClientSocket(std::move(transport),
                                  spawned_test_server_->host_port_pair(),
                                  ssl_config);
    EXPECT_FALSE(sock_->IsConnected());

    *result = callback_.GetResult(sock_->Connect(callback_.callback()));
    return true;
  }

  // Adds the server certificate with provided cert status.
  // Must be called after StartTestServer has been called.
  void AddServerCertStatusToSSLConfig(CertStatus status,
                                      SSLConfig* ssl_config) {
    ASSERT_TRUE(spawned_test_server());
    // Find out the certificate the server is using.
    scoped_refptr<X509Certificate> server_cert =
        spawned_test_server()->GetCertificate();
    // Get the MockCertVerifier to verify it as an EV cert.
    CertVerifyResult verify_result;
    verify_result.cert_status = status;
    verify_result.verified_cert = server_cert;
    cert_verifier_->AddResultForCert(server_cert.get(), verify_result, OK);
  }

  ClientSocketFactory* socket_factory_;
  std::unique_ptr<MockCertVerifier> cert_verifier_;
  std::unique_ptr<TransportSecurityState> transport_security_state_;
  std::unique_ptr<DoNothingCTVerifier> ct_verifier_;
  std::unique_ptr<MockCTPolicyEnforcer> ct_policy_enforcer_;
  SSLClientSocketContext context_;
  std::unique_ptr<SSLClientSocket> sock_;
  TestNetLog log_;

 private:
  std::unique_ptr<SpawnedTestServer> spawned_test_server_;
  TestCompletionCallback callback_;
  AddressList addr_;
};

// Verifies the correctness of GetSSLCertRequestInfo.
class SSLClientSocketCertRequestInfoTest : public SSLClientSocketTest {
 protected:
  // Creates a test server with the given SSLOptions, connects to it and returns
  // the SSLCertRequestInfo reported by the socket.
  scoped_refptr<SSLCertRequestInfo> GetCertRequest(
      SpawnedTestServer::SSLOptions ssl_options) {
    SpawnedTestServer spawned_test_server(SpawnedTestServer::TYPE_HTTPS,
                                          ssl_options, base::FilePath());
    if (!spawned_test_server.Start())
      return NULL;

    AddressList addr;
    if (!spawned_test_server.GetAddressList(&addr))
      return NULL;

    TestCompletionCallback callback;
    TestNetLog log;
    std::unique_ptr<StreamSocket> transport(
        new TCPClientSocket(addr, NULL, &log, NetLogSource()));
    int rv = callback.GetResult(transport->Connect(callback.callback()));
    EXPECT_THAT(rv, IsOk());

    std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
        std::move(transport), spawned_test_server.host_port_pair(),
        SSLConfig()));
    EXPECT_FALSE(sock->IsConnected());

    rv = callback.GetResult(sock->Connect(callback.callback()));
    EXPECT_THAT(rv, IsError(ERR_SSL_CLIENT_AUTH_CERT_NEEDED));

    scoped_refptr<SSLCertRequestInfo> request_info = new SSLCertRequestInfo();
    sock->GetSSLCertRequestInfo(request_info.get());
    sock->Disconnect();
    EXPECT_FALSE(sock->IsConnected());
    EXPECT_TRUE(spawned_test_server.host_port_pair().Equals(
        request_info->host_and_port));

    return request_info;
  }
};

class SSLClientSocketFalseStartTest : public SSLClientSocketTest {
 protected:
  // Creates an SSLClientSocket with |client_config| attached to a
  // FakeBlockingStreamSocket, returning both in |*out_raw_transport| and
  // |*out_sock|. The FakeBlockingStreamSocket is owned by the SSLClientSocket,
  // so |*out_raw_transport| is a raw pointer.
  //
  // The client socket will begin a connect using |callback| but stop before the
  // server's finished message is received. The finished message will be blocked
  // in |*out_raw_transport|. To complete the handshake and successfully read
  // data, the caller must unblock reads on |*out_raw_transport|. (Note that, if
  // the client successfully false started, |callback.WaitForResult()| will
  // return OK without unblocking transport reads. But Read() will still block.)
  //
  // Must be called after StartTestServer is called.
  void CreateAndConnectUntilServerFinishedReceived(
      const SSLConfig& client_config,
      TestCompletionCallback* callback,
      FakeBlockingStreamSocket** out_raw_transport,
      std::unique_ptr<SSLClientSocket>* out_sock) {
    CHECK(spawned_test_server());

    std::unique_ptr<StreamSocket> real_transport(
        new TCPClientSocket(addr(), NULL, NULL, NetLogSource()));
    std::unique_ptr<FakeBlockingStreamSocket> transport(
        new FakeBlockingStreamSocket(std::move(real_transport)));
    int rv = callback->GetResult(transport->Connect(callback->callback()));
    EXPECT_THAT(rv, IsOk());

    FakeBlockingStreamSocket* raw_transport = transport.get();
    std::unique_ptr<SSLClientSocket> sock = CreateSSLClientSocket(
        std::move(transport), spawned_test_server()->host_port_pair(),
        client_config);

    // Connect. Stop before the client processes the first server leg
    // (ServerHello, etc.)
    raw_transport->BlockReadResult();
    rv = sock->Connect(callback->callback());
    EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
    raw_transport->WaitForReadResult();

    // Release the ServerHello and wait for the client to write
    // ClientKeyExchange, etc. (A proxy for waiting for the entirety of the
    // server's leg to complete, since it may span multiple reads.)
    EXPECT_FALSE(callback->have_result());
    raw_transport->BlockWrite();
    raw_transport->UnblockReadResult();
    raw_transport->WaitForWrite();

    // And, finally, release that and block the next server leg
    // (ChangeCipherSpec, Finished).
    raw_transport->BlockReadResult();
    raw_transport->UnblockWrite();

    *out_raw_transport = raw_transport;
    *out_sock = std::move(sock);
  }

  void TestFalseStart(const SpawnedTestServer::SSLOptions& server_options,
                      const SSLConfig& client_config,
                      bool expect_false_start) {
    ASSERT_TRUE(StartTestServer(server_options));

    TestCompletionCallback callback;
    FakeBlockingStreamSocket* raw_transport = NULL;
    std::unique_ptr<SSLClientSocket> sock;
    ASSERT_NO_FATAL_FAILURE(CreateAndConnectUntilServerFinishedReceived(
        client_config, &callback, &raw_transport, &sock));

    if (expect_false_start) {
      // When False Starting, the handshake should complete before receiving the
      // Change Cipher Spec and Finished messages.
      //
      // Note: callback.have_result() may not be true without waiting. The NSS
      // state machine sometimes lives on a separate thread, so this thread may
      // not yet have processed the signal that the handshake has completed.
      int rv = callback.WaitForResult();
      EXPECT_THAT(rv, IsOk());
      EXPECT_TRUE(sock->IsConnected());

      const char request_text[] = "GET / HTTP/1.0\r\n\r\n";
      static const int kRequestTextSize =
          static_cast<int>(arraysize(request_text) - 1);
      scoped_refptr<IOBuffer> request_buffer(new IOBuffer(kRequestTextSize));
      memcpy(request_buffer->data(), request_text, kRequestTextSize);

      // Write the request.
      rv = callback.GetResult(sock->Write(request_buffer.get(),
                                          kRequestTextSize,
                                          callback.callback()));
      EXPECT_EQ(kRequestTextSize, rv);

      // The read will hang; it's waiting for the peer to complete the
      // handshake, and the handshake is still blocked.
      scoped_refptr<IOBuffer> buf(new IOBuffer(4096));
      rv = sock->Read(buf.get(), 4096, callback.callback());

      // After releasing reads, the connection proceeds.
      raw_transport->UnblockReadResult();
      rv = callback.GetResult(rv);
      EXPECT_LT(0, rv);
    } else {
      // False Start is not enabled, so the handshake will not complete because
      // the server second leg is blocked.
      base::RunLoop().RunUntilIdle();
      EXPECT_FALSE(callback.have_result());
    }
  }
};

class SSLClientSocketChannelIDTest : public SSLClientSocketTest {
 protected:
  SSLClientSocketChannelIDTest()
      : scoped_task_scheduler_(base::MessageLoop::current()) {}

  void EnableChannelID() {
    channel_id_service_.reset(
        new ChannelIDService(new DefaultChannelIDStore(NULL)));
    context_.channel_id_service = channel_id_service_.get();
  }

  void EnableFailingChannelID() {
    channel_id_service_.reset(
        new ChannelIDService(new FailingChannelIDStore()));
    context_.channel_id_service = channel_id_service_.get();
  }

  void EnableAsyncFailingChannelID() {
    channel_id_service_.reset(
        new ChannelIDService(new AsyncFailingChannelIDStore()));
    context_.channel_id_service = channel_id_service_.get();
  }

 private:
  base::test::ScopedTaskScheduler scoped_task_scheduler_;
  std::unique_ptr<ChannelIDService> channel_id_service_;
};

// Returns a serialized unencrypted TLS 1.2 alert record for the given alert
// value.
std::string FormatTLS12Alert(uint8_t alert) {
  std::string ret;
  // ContentType.alert
  ret.push_back(21);
  // Record-layer version. Assume TLS 1.2.
  ret.push_back(0x03);
  ret.push_back(0x03);
  // Record length.
  ret.push_back(0);
  ret.push_back(2);
  // AlertLevel.fatal.
  ret.push_back(2);
  // The alert itself.
  ret.push_back(alert);
  return ret;
}

}  // namespace

TEST_F(SSLClientSocketTest, Connect) {
  ASSERT_TRUE(StartTestServer(SpawnedTestServer::SSLOptions()));

  TestCompletionCallback callback;
  TestNetLog log;
  std::unique_ptr<StreamSocket> transport(
      new TCPClientSocket(addr(), NULL, &log, NetLogSource()));
  int rv = callback.GetResult(transport->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());

  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(transport), spawned_test_server()->host_port_pair(),
      SSLConfig()));

  EXPECT_FALSE(sock->IsConnected());

  rv = sock->Connect(callback.callback());

  TestNetLogEntry::List entries;
  log.GetEntries(&entries);
  EXPECT_TRUE(LogContainsBeginEvent(entries, 5, NetLogEventType::SSL_CONNECT));
  if (rv == ERR_IO_PENDING)
    rv = callback.WaitForResult();
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock->IsConnected());
  log.GetEntries(&entries);
  EXPECT_TRUE(LogContainsEndEvent(entries, -1, NetLogEventType::SSL_CONNECT));

  sock->Disconnect();
  EXPECT_FALSE(sock->IsConnected());
}

TEST_F(SSLClientSocketTest, ConnectExpired) {
  SpawnedTestServer::SSLOptions ssl_options(
      SpawnedTestServer::SSLOptions::CERT_EXPIRED);
  ASSERT_TRUE(StartTestServer(ssl_options));

  cert_verifier_->set_default_result(ERR_CERT_DATE_INVALID);

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsError(ERR_CERT_DATE_INVALID));

  // Rather than testing whether or not the underlying socket is connected,
  // test that the handshake has finished. This is because it may be
  // desirable to disconnect the socket before showing a user prompt, since
  // the user may take indefinitely long to respond.
  TestNetLogEntry::List entries;
  log_.GetEntries(&entries);
  EXPECT_TRUE(LogContainsEndEvent(entries, -1, NetLogEventType::SSL_CONNECT));
}

TEST_F(SSLClientSocketTest, ConnectMismatched) {
  SpawnedTestServer::SSLOptions ssl_options(
      SpawnedTestServer::SSLOptions::CERT_MISMATCHED_NAME);
  ASSERT_TRUE(StartTestServer(ssl_options));

  cert_verifier_->set_default_result(ERR_CERT_COMMON_NAME_INVALID);

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsError(ERR_CERT_COMMON_NAME_INVALID));

  // Rather than testing whether or not the underlying socket is connected,
  // test that the handshake has finished. This is because it may be
  // desirable to disconnect the socket before showing a user prompt, since
  // the user may take indefinitely long to respond.
  TestNetLogEntry::List entries;
  log_.GetEntries(&entries);
  EXPECT_TRUE(LogContainsEndEvent(entries, -1, NetLogEventType::SSL_CONNECT));
}

#if defined(OS_WIN)
// Tests that certificates parsable by SSLClientSocket's internal SSL
// implementation, but not X509Certificate are treated as fatal non-certificate
// errors. This is regression test for https://crbug.com/91341.
TEST_F(SSLClientSocketTest, ConnectBadValidity) {
  SpawnedTestServer::SSLOptions ssl_options(
      SpawnedTestServer::SSLOptions::CERT_BAD_VALIDITY);
  ASSERT_TRUE(StartTestServer(ssl_options));
  SSLConfig ssl_config;
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));

  EXPECT_THAT(rv, IsError(ERR_SSL_SERVER_CERT_BAD_FORMAT));
  EXPECT_FALSE(IsCertificateError(rv));

  SSLInfo ssl_info;
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_FALSE(ssl_info.cert);
}
#endif  // defined(OS_WIN)

// Attempt to connect to a page which requests a client certificate. It should
// return an error code on connect.
TEST_F(SSLClientSocketTest, ConnectClientAuthCertRequested) {
  SpawnedTestServer::SSLOptions ssl_options;
  ssl_options.request_client_certificate = true;
  ASSERT_TRUE(StartTestServer(ssl_options));

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsError(ERR_SSL_CLIENT_AUTH_CERT_NEEDED));

  TestNetLogEntry::List entries;
  log_.GetEntries(&entries);
  EXPECT_TRUE(LogContainsEndEvent(entries, -1, NetLogEventType::SSL_CONNECT));
  EXPECT_FALSE(sock_->IsConnected());
}

// Connect to a server requesting optional client authentication. Send it a
// null certificate. It should allow the connection.
//
// TODO(davidben): Also test providing an actual certificate.
TEST_F(SSLClientSocketTest, ConnectClientAuthSendNullCert) {
  SpawnedTestServer::SSLOptions ssl_options;
  ssl_options.request_client_certificate = true;
  ASSERT_TRUE(StartTestServer(ssl_options));

  // Our test server accepts certificate-less connections.
  // TODO(davidben): Add a test which requires them and verify the error.
  SSLConfig ssl_config;
  ssl_config.send_client_cert = true;
  ssl_config.client_cert = NULL;

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  EXPECT_THAT(rv, IsOk());

  // We responded to the server's certificate request with a Certificate
  // message with no client certificate in it.  ssl_info.client_cert_sent
  // should be false in this case.
  SSLInfo ssl_info;
  sock_->GetSSLInfo(&ssl_info);
  EXPECT_FALSE(ssl_info.client_cert_sent);

  sock_->Disconnect();
  EXPECT_FALSE(sock_->IsConnected());
}

// TODO(wtc): Add unit tests for IsConnectedAndIdle:
//   - Server closes an SSL connection (with a close_notify alert message).
//   - Server closes the underlying TCP connection directly.
//   - Server sends data unexpectedly.

// Tests that the socket can be read from successfully. Also test that a peer's
// close_notify alert is successfully processed without error.
TEST_F(SSLClientSocketTest, Read) {
  ASSERT_TRUE(StartTestServer(SpawnedTestServer::SSLOptions()));

  TestCompletionCallback callback;
  std::unique_ptr<StreamSocket> transport(
      new TCPClientSocket(addr(), NULL, NULL, NetLogSource()));
  EXPECT_EQ(0, transport->GetTotalReceivedBytes());

  int rv = callback.GetResult(transport->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());

  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(transport), spawned_test_server()->host_port_pair(),
      SSLConfig()));
  EXPECT_EQ(0, sock->GetTotalReceivedBytes());

  rv = callback.GetResult(sock->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());

  // Number of network bytes received should increase because of SSL socket
  // establishment.
  EXPECT_GT(sock->GetTotalReceivedBytes(), 0);

  const char request_text[] = "GET / HTTP/1.0\r\n\r\n";
  scoped_refptr<IOBuffer> request_buffer(
      new IOBuffer(arraysize(request_text) - 1));
  memcpy(request_buffer->data(), request_text, arraysize(request_text) - 1);

  rv = callback.GetResult(sock->Write(
      request_buffer.get(), arraysize(request_text) - 1, callback.callback()));
  EXPECT_EQ(static_cast<int>(arraysize(request_text) - 1), rv);

  scoped_refptr<IOBuffer> buf(new IOBuffer(4096));
  int64_t unencrypted_bytes_read = 0;
  int64_t network_bytes_read_during_handshake = sock->GetTotalReceivedBytes();
  do {
    rv = callback.GetResult(sock->Read(buf.get(), 4096, callback.callback()));
    EXPECT_GE(rv, 0);
    if (rv >= 0) {
      unencrypted_bytes_read += rv;
    }
  } while (rv > 0);
  EXPECT_GT(unencrypted_bytes_read, 0);
  // Reading the payload should increase the number of bytes on network layer.
  EXPECT_GT(sock->GetTotalReceivedBytes(), network_bytes_read_during_handshake);
  // Number of bytes received on the network after the handshake should be
  // higher than the number of encrypted bytes read.
  EXPECT_GE(sock->GetTotalReceivedBytes() - network_bytes_read_during_handshake,
            unencrypted_bytes_read);

  // The peer should have cleanly closed the connection with a close_notify.
  EXPECT_EQ(0, rv);
}

// Tests that SSLClientSocket properly handles when the underlying transport
// synchronously fails a transport write in during the handshake.
TEST_F(SSLClientSocketTest, Connect_WithSynchronousError) {
  ASSERT_TRUE(StartTestServer(SpawnedTestServer::SSLOptions()));

  TestCompletionCallback callback;
  std::unique_ptr<StreamSocket> real_transport(
      new TCPClientSocket(addr(), NULL, NULL, NetLogSource()));
  std::unique_ptr<SynchronousErrorStreamSocket> transport(
      new SynchronousErrorStreamSocket(std::move(real_transport)));
  int rv = callback.GetResult(transport->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());

  // Disable TLS False Start to avoid handshake non-determinism.
  SSLConfig ssl_config;
  ssl_config.false_start_enabled = false;

  SynchronousErrorStreamSocket* raw_transport = transport.get();
  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(transport), spawned_test_server()->host_port_pair(),
      ssl_config));

  raw_transport->SetNextWriteError(ERR_CONNECTION_RESET);

  rv = callback.GetResult(sock->Connect(callback.callback()));
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));
  EXPECT_FALSE(sock->IsConnected());
}

// Tests that the SSLClientSocket properly handles when the underlying transport
// synchronously returns an error code - such as if an intermediary terminates
// the socket connection uncleanly.
// This is a regression test for http://crbug.com/238536
TEST_F(SSLClientSocketTest, Read_WithSynchronousError) {
  ASSERT_TRUE(StartTestServer(SpawnedTestServer::SSLOptions()));

  TestCompletionCallback callback;
  std::unique_ptr<StreamSocket> real_transport(
      new TCPClientSocket(addr(), NULL, NULL, NetLogSource()));
  std::unique_ptr<SynchronousErrorStreamSocket> transport(
      new SynchronousErrorStreamSocket(std::move(real_transport)));
  int rv = callback.GetResult(transport->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());

  // Disable TLS False Start to avoid handshake non-determinism.
  SSLConfig ssl_config;
  ssl_config.false_start_enabled = false;

  SynchronousErrorStreamSocket* raw_transport = transport.get();
  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(transport), spawned_test_server()->host_port_pair(),
      ssl_config));

  rv = callback.GetResult(sock->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock->IsConnected());

  const char request_text[] = "GET / HTTP/1.0\r\n\r\n";
  static const int kRequestTextSize =
      static_cast<int>(arraysize(request_text) - 1);
  scoped_refptr<IOBuffer> request_buffer(new IOBuffer(kRequestTextSize));
  memcpy(request_buffer->data(), request_text, kRequestTextSize);

  rv = callback.GetResult(
      sock->Write(request_buffer.get(), kRequestTextSize, callback.callback()));
  EXPECT_EQ(kRequestTextSize, rv);

  // Simulate an unclean/forcible shutdown.
  raw_transport->SetNextReadError(ERR_CONNECTION_RESET);

  scoped_refptr<IOBuffer> buf(new IOBuffer(4096));

  // Note: This test will hang if this bug has regressed. Simply checking that
  // rv != ERR_IO_PENDING is insufficient, as ERR_IO_PENDING is a legitimate
  // result when using a dedicated task runner for NSS.
  rv = callback.GetResult(sock->Read(buf.get(), 4096, callback.callback()));
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));
}

// Tests that the SSLClientSocket properly handles when the underlying transport
// asynchronously returns an error code while writing data - such as if an
// intermediary terminates the socket connection uncleanly.
// This is a regression test for http://crbug.com/249848
TEST_F(SSLClientSocketTest, Write_WithSynchronousError) {
  ASSERT_TRUE(StartTestServer(SpawnedTestServer::SSLOptions()));

  TestCompletionCallback callback;
  std::unique_ptr<StreamSocket> real_transport(
      new TCPClientSocket(addr(), NULL, NULL, NetLogSource()));
  // Note: |error_socket|'s ownership is handed to |transport|, but a pointer
  // is retained in order to configure additional errors.
  std::unique_ptr<SynchronousErrorStreamSocket> error_socket(
      new SynchronousErrorStreamSocket(std::move(real_transport)));
  SynchronousErrorStreamSocket* raw_error_socket = error_socket.get();
  std::unique_ptr<FakeBlockingStreamSocket> transport(
      new FakeBlockingStreamSocket(std::move(error_socket)));
  FakeBlockingStreamSocket* raw_transport = transport.get();
  int rv = callback.GetResult(transport->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());

  // Disable TLS False Start to avoid handshake non-determinism.
  SSLConfig ssl_config;
  ssl_config.false_start_enabled = false;

  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(transport), spawned_test_server()->host_port_pair(),
      ssl_config));

  rv = callback.GetResult(sock->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock->IsConnected());

  const char request_text[] = "GET / HTTP/1.0\r\n\r\n";
  static const int kRequestTextSize =
      static_cast<int>(arraysize(request_text) - 1);
  scoped_refptr<IOBuffer> request_buffer(new IOBuffer(kRequestTextSize));
  memcpy(request_buffer->data(), request_text, kRequestTextSize);

  // Simulate an unclean/forcible shutdown on the underlying socket.
  // However, simulate this error asynchronously.
  raw_error_socket->SetNextWriteError(ERR_CONNECTION_RESET);
  raw_transport->BlockWrite();

  // This write should complete synchronously, because the TLS ciphertext
  // can be created and placed into the outgoing buffers independent of the
  // underlying transport.
  rv = callback.GetResult(
      sock->Write(request_buffer.get(), kRequestTextSize, callback.callback()));
  EXPECT_EQ(kRequestTextSize, rv);

  scoped_refptr<IOBuffer> buf(new IOBuffer(4096));

  rv = sock->Read(buf.get(), 4096, callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Now unblock the outgoing request, having it fail with the connection
  // being reset.
  raw_transport->UnblockWrite();

  // Note: This will cause an inifite loop if this bug has regressed. Simply
  // checking that rv != ERR_IO_PENDING is insufficient, as ERR_IO_PENDING
  // is a legitimate result when using a dedicated task runner for NSS.
  rv = callback.GetResult(rv);
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));
}

// If there is a Write failure at the transport with no follow-up Read, although
// the write error will not be returned to the client until a future Read or
// Write operation, SSLClientSocket should not spin attempting to re-write on
// the socket. This is a regression test for part of https://crbug.com/381160.
TEST_F(SSLClientSocketTest, Write_WithSynchronousErrorNoRead) {
  ASSERT_TRUE(StartTestServer(SpawnedTestServer::SSLOptions()));

  TestCompletionCallback callback;
  std::unique_ptr<StreamSocket> real_transport(
      new TCPClientSocket(addr(), NULL, NULL, NetLogSource()));
  // Note: intermediate sockets' ownership are handed to |sock|, but a pointer
  // is retained in order to query them.
  std::unique_ptr<SynchronousErrorStreamSocket> error_socket(
      new SynchronousErrorStreamSocket(std::move(real_transport)));
  SynchronousErrorStreamSocket* raw_error_socket = error_socket.get();
  std::unique_ptr<CountingStreamSocket> counting_socket(
      new CountingStreamSocket(std::move(error_socket)));
  CountingStreamSocket* raw_counting_socket = counting_socket.get();
  int rv = callback.GetResult(counting_socket->Connect(callback.callback()));
  ASSERT_THAT(rv, IsOk());

  // Disable TLS False Start to avoid handshake non-determinism.
  SSLConfig ssl_config;
  ssl_config.false_start_enabled = false;

  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(counting_socket), spawned_test_server()->host_port_pair(),
      ssl_config));

  rv = callback.GetResult(sock->Connect(callback.callback()));
  ASSERT_THAT(rv, IsOk());
  ASSERT_TRUE(sock->IsConnected());

  // Simulate an unclean/forcible shutdown on the underlying socket.
  raw_error_socket->SetNextWriteError(ERR_CONNECTION_RESET);

  const char request_text[] = "GET / HTTP/1.0\r\n\r\n";
  static const int kRequestTextSize =
      static_cast<int>(arraysize(request_text) - 1);
  scoped_refptr<IOBuffer> request_buffer(new IOBuffer(kRequestTextSize));
  memcpy(request_buffer->data(), request_text, kRequestTextSize);

  // This write should complete synchronously, because the TLS ciphertext
  // can be created and placed into the outgoing buffers independent of the
  // underlying transport.
  rv = callback.GetResult(
      sock->Write(request_buffer.get(), kRequestTextSize, callback.callback()));
  ASSERT_EQ(kRequestTextSize, rv);

  // Let the event loop spin for a little bit of time. Even on platforms where
  // pumping the state machine involve thread hops, there should be no further
  // writes on the transport socket.
  //
  // TODO(davidben): Avoid the arbitrary timeout?
  int old_write_count = raw_counting_socket->write_count();
  base::RunLoop loop;
  base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
      FROM_HERE, loop.QuitClosure(), base::TimeDelta::FromMilliseconds(100));
  loop.Run();
  EXPECT_EQ(old_write_count, raw_counting_socket->write_count());
}

// Test the full duplex mode, with Read and Write pending at the same time.
// This test also serves as a regression test for http://crbug.com/29815.
TEST_F(SSLClientSocketTest, Read_FullDuplex) {
  ASSERT_TRUE(StartTestServer(SpawnedTestServer::SSLOptions()));

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsOk());

  // Issue a "hanging" Read first.
  TestCompletionCallback callback;
  scoped_refptr<IOBuffer> buf(new IOBuffer(4096));
  rv = sock_->Read(buf.get(), 4096, callback.callback());
  // We haven't written the request, so there should be no response yet.
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));

  // Write the request.
  // The request is padded with a User-Agent header to a size that causes the
  // memio circular buffer (4k bytes) in SSLClientSocketNSS to wrap around.
  // This tests the fix for http://crbug.com/29815.
  std::string request_text = "GET / HTTP/1.1\r\nUser-Agent: long browser name ";
  for (int i = 0; i < 3770; ++i)
    request_text.push_back('*');
  request_text.append("\r\n\r\n");
  scoped_refptr<IOBuffer> request_buffer(new StringIOBuffer(request_text));

  TestCompletionCallback callback2;  // Used for Write only.
  rv = callback2.GetResult(sock_->Write(
      request_buffer.get(), request_text.size(), callback2.callback()));
  EXPECT_EQ(static_cast<int>(request_text.size()), rv);

  // Now get the Read result.
  rv = callback.WaitForResult();
  EXPECT_GT(rv, 0);
}

// Attempts to Read() and Write() from an SSLClientSocketNSS in full duplex
// mode when the underlying transport is blocked on sending data. When the
// underlying transport completes due to an error, it should invoke both the
// Read() and Write() callbacks. If the socket is deleted by the Read()
// callback, the Write() callback should not be invoked.
// Regression test for http://crbug.com/232633
TEST_F(SSLClientSocketTest, Read_DeleteWhilePendingFullDuplex) {
  ASSERT_TRUE(StartTestServer(SpawnedTestServer::SSLOptions()));

  TestCompletionCallback callback;
  std::unique_ptr<StreamSocket> real_transport(
      new TCPClientSocket(addr(), NULL, NULL, NetLogSource()));
  // Note: |error_socket|'s ownership is handed to |transport|, but a pointer
  // is retained in order to configure additional errors.
  std::unique_ptr<SynchronousErrorStreamSocket> error_socket(
      new SynchronousErrorStreamSocket(std::move(real_transport)));
  SynchronousErrorStreamSocket* raw_error_socket = error_socket.get();
  std::unique_ptr<FakeBlockingStreamSocket> transport(
      new FakeBlockingStreamSocket(std::move(error_socket)));
  FakeBlockingStreamSocket* raw_transport = transport.get();

  int rv = callback.GetResult(transport->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());

  // Disable TLS False Start to avoid handshake non-determinism.
  SSLConfig ssl_config;
  ssl_config.false_start_enabled = false;

  std::unique_ptr<SSLClientSocket> sock = CreateSSLClientSocket(
      std::move(transport), spawned_test_server()->host_port_pair(),
      ssl_config);

  rv = callback.GetResult(sock->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock->IsConnected());

  std::string request_text = "GET / HTTP/1.1\r\nUser-Agent: long browser name ";
  request_text.append(20 * 1024, '*');
  request_text.append("\r\n\r\n");
  scoped_refptr<DrainableIOBuffer> request_buffer(new DrainableIOBuffer(
      new StringIOBuffer(request_text), request_text.size()));

  // Simulate errors being returned from the underlying Read() and Write() ...
  raw_error_socket->SetNextReadError(ERR_CONNECTION_RESET);
  raw_error_socket->SetNextWriteError(ERR_CONNECTION_RESET);
  // ... but have those errors returned asynchronously. Because the Write() will
  // return first, this will trigger the error.
  raw_transport->BlockReadResult();
  raw_transport->BlockWrite();

  // Enqueue a Read() before calling Write(), which should "hang" due to
  // the ERR_IO_PENDING caused by SetReadShouldBlock() and thus return.
  SSLClientSocket* raw_sock = sock.get();
  DeleteSocketCallback read_callback(sock.release());
  scoped_refptr<IOBuffer> read_buf(new IOBuffer(4096));
  rv = raw_sock->Read(read_buf.get(), 4096, read_callback.callback());

  // Ensure things didn't complete synchronously, otherwise |sock| is invalid.
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  ASSERT_FALSE(read_callback.have_result());

  // Attempt to write the remaining data. OpenSSL will return that its blocked
  // because the underlying transport is blocked.
  rv = raw_sock->Write(request_buffer.get(),
                       request_buffer->BytesRemaining(),
                       callback.callback());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  ASSERT_FALSE(callback.have_result());

  // Now unblock Write(), which will invoke OnSendComplete and (eventually)
  // call the Read() callback, deleting the socket and thus aborting calling
  // the Write() callback.
  raw_transport->UnblockWrite();

  rv = read_callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));

  // The Write callback should not have been called.
  EXPECT_FALSE(callback.have_result());
}

// Tests that the SSLClientSocket does not crash if data is received on the
// transport socket after a failing write. This can occur if we have a Write
// error in a SPDY socket.
// Regression test for http://crbug.com/335557
TEST_F(SSLClientSocketTest, Read_WithWriteError) {
  ASSERT_TRUE(StartTestServer(SpawnedTestServer::SSLOptions()));

  TestCompletionCallback callback;
  std::unique_ptr<StreamSocket> real_transport(
      new TCPClientSocket(addr(), NULL, NULL, NetLogSource()));
  // Note: |error_socket|'s ownership is handed to |transport|, but a pointer
  // is retained in order to configure additional errors.
  std::unique_ptr<SynchronousErrorStreamSocket> error_socket(
      new SynchronousErrorStreamSocket(std::move(real_transport)));
  SynchronousErrorStreamSocket* raw_error_socket = error_socket.get();
  std::unique_ptr<FakeBlockingStreamSocket> transport(
      new FakeBlockingStreamSocket(std::move(error_socket)));
  FakeBlockingStreamSocket* raw_transport = transport.get();

  int rv = callback.GetResult(transport->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());

  // Disable TLS False Start to avoid handshake non-determinism.
  SSLConfig ssl_config;
  ssl_config.false_start_enabled = false;

  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(transport), spawned_test_server()->host_port_pair(),
      ssl_config));

  rv = callback.GetResult(sock->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock->IsConnected());

  // Send a request so there is something to read from the socket.
  const char request_text[] = "GET / HTTP/1.0\r\n\r\n";
  static const int kRequestTextSize =
      static_cast<int>(arraysize(request_text) - 1);
  scoped_refptr<IOBuffer> request_buffer(new IOBuffer(kRequestTextSize));
  memcpy(request_buffer->data(), request_text, kRequestTextSize);

  rv = callback.GetResult(
      sock->Write(request_buffer.get(), kRequestTextSize, callback.callback()));
  EXPECT_EQ(kRequestTextSize, rv);

  // Start a hanging read.
  TestCompletionCallback read_callback;
  raw_transport->BlockReadResult();
  scoped_refptr<IOBuffer> buf(new IOBuffer(4096));
  rv = sock->Read(buf.get(), 4096, read_callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  // Perform another write, but have it fail. Write a request larger than the
  // internal socket buffers so that the request hits the underlying transport
  // socket and detects the error.
  std::string long_request_text =
      "GET / HTTP/1.1\r\nUser-Agent: long browser name ";
  long_request_text.append(20 * 1024, '*');
  long_request_text.append("\r\n\r\n");
  scoped_refptr<DrainableIOBuffer> long_request_buffer(new DrainableIOBuffer(
      new StringIOBuffer(long_request_text), long_request_text.size()));

  raw_error_socket->SetNextWriteError(ERR_CONNECTION_RESET);

  // Write as much data as possible until hitting an error.
  do {
    rv = callback.GetResult(sock->Write(long_request_buffer.get(),
                                        long_request_buffer->BytesRemaining(),
                                        callback.callback()));
    if (rv > 0) {
      long_request_buffer->DidConsume(rv);
      // Abort if the entire input is ever consumed. The input is larger than
      // the SSLClientSocket's write buffers.
      ASSERT_LT(0, long_request_buffer->BytesRemaining());
    }
  } while (rv > 0);

  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));

  // At this point the Read result is available. Transport write errors are
  // surfaced through Writes. See https://crbug.com/249848.
  rv = read_callback.WaitForResult();
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_RESET));

  // Release the read. This does not cause a crash.
  raw_transport->UnblockReadResult();
  base::RunLoop().RunUntilIdle();
}

// Tests that SSLClientSocket fails the handshake if the underlying
// transport is cleanly closed.
TEST_F(SSLClientSocketTest, Connect_WithZeroReturn) {
  ASSERT_TRUE(StartTestServer(SpawnedTestServer::SSLOptions()));

  TestCompletionCallback callback;
  std::unique_ptr<StreamSocket> real_transport(
      new TCPClientSocket(addr(), NULL, NULL, NetLogSource()));
  std::unique_ptr<SynchronousErrorStreamSocket> transport(
      new SynchronousErrorStreamSocket(std::move(real_transport)));
  int rv = callback.GetResult(transport->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());

  SynchronousErrorStreamSocket* raw_transport = transport.get();
  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(transport), spawned_test_server()->host_port_pair(),
      SSLConfig()));

  raw_transport->SetNextReadError(0);

  rv = callback.GetResult(sock->Connect(callback.callback()));
  EXPECT_THAT(rv, IsError(ERR_CONNECTION_CLOSED));
  EXPECT_FALSE(sock->IsConnected());
}

// Tests that SSLClientSocket returns a Read of size 0 if the underlying socket
// is cleanly closed, but the peer does not send close_notify.
// This is a regression test for https://crbug.com/422246
TEST_F(SSLClientSocketTest, Read_WithZeroReturn) {
  ASSERT_TRUE(StartTestServer(SpawnedTestServer::SSLOptions()));

  TestCompletionCallback callback;
  std::unique_ptr<StreamSocket> real_transport(
      new TCPClientSocket(addr(), NULL, NULL, NetLogSource()));
  std::unique_ptr<SynchronousErrorStreamSocket> transport(
      new SynchronousErrorStreamSocket(std::move(real_transport)));
  int rv = callback.GetResult(transport->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());

  // Disable TLS False Start to ensure the handshake has completed.
  SSLConfig ssl_config;
  ssl_config.false_start_enabled = false;

  SynchronousErrorStreamSocket* raw_transport = transport.get();
  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(transport), spawned_test_server()->host_port_pair(),
      ssl_config));

  rv = callback.GetResult(sock->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock->IsConnected());

  raw_transport->SetNextReadError(0);
  scoped_refptr<IOBuffer> buf(new IOBuffer(4096));
  rv = callback.GetResult(sock->Read(buf.get(), 4096, callback.callback()));
  EXPECT_EQ(0, rv);
}

// Tests that SSLClientSocket cleanly returns a Read of size 0 if the
// underlying socket is cleanly closed asynchronously.
// This is a regression test for https://crbug.com/422246
TEST_F(SSLClientSocketTest, Read_WithAsyncZeroReturn) {
  ASSERT_TRUE(StartTestServer(SpawnedTestServer::SSLOptions()));

  TestCompletionCallback callback;
  std::unique_ptr<StreamSocket> real_transport(
      new TCPClientSocket(addr(), NULL, NULL, NetLogSource()));
  std::unique_ptr<SynchronousErrorStreamSocket> error_socket(
      new SynchronousErrorStreamSocket(std::move(real_transport)));
  SynchronousErrorStreamSocket* raw_error_socket = error_socket.get();
  std::unique_ptr<FakeBlockingStreamSocket> transport(
      new FakeBlockingStreamSocket(std::move(error_socket)));
  FakeBlockingStreamSocket* raw_transport = transport.get();
  int rv = callback.GetResult(transport->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());

  // Disable TLS False Start to ensure the handshake has completed.
  SSLConfig ssl_config;
  ssl_config.false_start_enabled = false;

  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(transport), spawned_test_server()->host_port_pair(),
      ssl_config));

  rv = callback.GetResult(sock->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock->IsConnected());

  raw_error_socket->SetNextReadError(0);
  raw_transport->BlockReadResult();
  scoped_refptr<IOBuffer> buf(new IOBuffer(4096));
  rv = sock->Read(buf.get(), 4096, callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));

  raw_transport->UnblockReadResult();
  rv = callback.GetResult(rv);
  EXPECT_EQ(0, rv);
}

// Tests that fatal alerts from the peer are processed. This is a regression
// test for https://crbug.com/466303.
TEST_F(SSLClientSocketTest, Read_WithFatalAlert) {
  SpawnedTestServer::SSLOptions ssl_options;
  ssl_options.alert_after_handshake = true;
  ASSERT_TRUE(StartTestServer(ssl_options));

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsOk());

  // Receive the fatal alert.
  TestCompletionCallback callback;
  scoped_refptr<IOBuffer> buf(new IOBuffer(4096));
  EXPECT_EQ(ERR_SSL_PROTOCOL_ERROR, callback.GetResult(sock_->Read(
                                        buf.get(), 4096, callback.callback())));
}

TEST_F(SSLClientSocketTest, Read_SmallChunks) {
  ASSERT_TRUE(StartTestServer(SpawnedTestServer::SSLOptions()));

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsOk());

  const char request_text[] = "GET / HTTP/1.0\r\n\r\n";
  scoped_refptr<IOBuffer> request_buffer(
      new IOBuffer(arraysize(request_text) - 1));
  memcpy(request_buffer->data(), request_text, arraysize(request_text) - 1);

  TestCompletionCallback callback;
  rv = callback.GetResult(sock_->Write(
      request_buffer.get(), arraysize(request_text) - 1, callback.callback()));
  EXPECT_EQ(static_cast<int>(arraysize(request_text) - 1), rv);

  scoped_refptr<IOBuffer> buf(new IOBuffer(1));
  do {
    rv = callback.GetResult(sock_->Read(buf.get(), 1, callback.callback()));
    EXPECT_GE(rv, 0);
  } while (rv > 0);
}

TEST_F(SSLClientSocketTest, Read_ManySmallRecords) {
  ASSERT_TRUE(StartTestServer(SpawnedTestServer::SSLOptions()));

  TestCompletionCallback callback;

  std::unique_ptr<StreamSocket> real_transport(
      new TCPClientSocket(addr(), NULL, NULL, NetLogSource()));
  std::unique_ptr<ReadBufferingStreamSocket> transport(
      new ReadBufferingStreamSocket(std::move(real_transport)));
  ReadBufferingStreamSocket* raw_transport = transport.get();
  int rv = callback.GetResult(transport->Connect(callback.callback()));
  ASSERT_THAT(rv, IsOk());

  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(transport), spawned_test_server()->host_port_pair(),
      SSLConfig()));

  rv = callback.GetResult(sock->Connect(callback.callback()));
  ASSERT_THAT(rv, IsOk());
  ASSERT_TRUE(sock->IsConnected());

  const char request_text[] = "GET /ssl-many-small-records HTTP/1.0\r\n\r\n";
  scoped_refptr<IOBuffer> request_buffer(
      new IOBuffer(arraysize(request_text) - 1));
  memcpy(request_buffer->data(), request_text, arraysize(request_text) - 1);

  rv = callback.GetResult(sock->Write(
      request_buffer.get(), arraysize(request_text) - 1, callback.callback()));
  ASSERT_GT(rv, 0);
  ASSERT_EQ(static_cast<int>(arraysize(request_text) - 1), rv);

  // Note: This relies on SSLClientSocketNSS attempting to read up to 17K of
  // data (the max SSL record size) at a time. Ensure that at least 15K worth
  // of SSL data is buffered first. The 15K of buffered data is made up of
  // many smaller SSL records (the TestServer writes along 1350 byte
  // plaintext boundaries), although there may also be a few records that are
  // smaller or larger, due to timing and SSL False Start.
  // 15K was chosen because 15K is smaller than the 17K (max) read issued by
  // the SSLClientSocket implementation, and larger than the minimum amount
  // of ciphertext necessary to contain the 8K of plaintext requested below.
  raw_transport->SetBufferSize(15000);

  scoped_refptr<IOBuffer> buffer(new IOBuffer(8192));
  rv = callback.GetResult(sock->Read(buffer.get(), 8192, callback.callback()));
  ASSERT_EQ(rv, 8192);
}

TEST_F(SSLClientSocketTest, Read_Interrupted) {
  ASSERT_TRUE(StartTestServer(SpawnedTestServer::SSLOptions()));

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsOk());

  const char request_text[] = "GET / HTTP/1.0\r\n\r\n";
  scoped_refptr<IOBuffer> request_buffer(
      new IOBuffer(arraysize(request_text) - 1));
  memcpy(request_buffer->data(), request_text, arraysize(request_text) - 1);

  TestCompletionCallback callback;
  rv = callback.GetResult(sock_->Write(
      request_buffer.get(), arraysize(request_text) - 1, callback.callback()));
  EXPECT_EQ(static_cast<int>(arraysize(request_text) - 1), rv);

  // Do a partial read and then exit.  This test should not crash!
  scoped_refptr<IOBuffer> buf(new IOBuffer(512));
  rv = callback.GetResult(sock_->Read(buf.get(), 512, callback.callback()));
  EXPECT_GT(rv, 0);
}

TEST_F(SSLClientSocketTest, Read_FullLogging) {
  ASSERT_TRUE(StartTestServer(SpawnedTestServer::SSLOptions()));

  TestCompletionCallback callback;
  TestNetLog log;
  log.SetCaptureMode(NetLogCaptureMode::IncludeSocketBytes());
  std::unique_ptr<StreamSocket> transport(
      new TCPClientSocket(addr(), NULL, &log, NetLogSource()));
  int rv = callback.GetResult(transport->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());

  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(transport), spawned_test_server()->host_port_pair(),
      SSLConfig()));

  rv = callback.GetResult(sock->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock->IsConnected());

  const char request_text[] = "GET / HTTP/1.0\r\n\r\n";
  scoped_refptr<IOBuffer> request_buffer(
      new IOBuffer(arraysize(request_text) - 1));
  memcpy(request_buffer->data(), request_text, arraysize(request_text) - 1);

  rv = callback.GetResult(sock->Write(
      request_buffer.get(), arraysize(request_text) - 1, callback.callback()));
  EXPECT_EQ(static_cast<int>(arraysize(request_text) - 1), rv);

  TestNetLogEntry::List entries;
  log.GetEntries(&entries);
  size_t last_index = ExpectLogContainsSomewhereAfter(
      entries, 5, NetLogEventType::SSL_SOCKET_BYTES_SENT,
      NetLogEventPhase::NONE);

  scoped_refptr<IOBuffer> buf(new IOBuffer(4096));
  for (;;) {
    rv = callback.GetResult(sock->Read(buf.get(), 4096, callback.callback()));
    EXPECT_GE(rv, 0);
    if (rv <= 0)
      break;

    log.GetEntries(&entries);
    last_index = ExpectLogContainsSomewhereAfter(
        entries, last_index + 1, NetLogEventType::SSL_SOCKET_BYTES_RECEIVED,
        NetLogEventPhase::NONE);
  }
}

// Regression test for http://crbug.com/42538
TEST_F(SSLClientSocketTest, PrematureApplicationData) {
  ASSERT_TRUE(StartTestServer(SpawnedTestServer::SSLOptions()));

  static const unsigned char application_data[] = {
      0x17, 0x03, 0x01, 0x00, 0x4a, 0x02, 0x00, 0x00, 0x46, 0x03, 0x01, 0x4b,
      0xc2, 0xf8, 0xb2, 0xc1, 0x56, 0x42, 0xb9, 0x57, 0x7f, 0xde, 0x87, 0x46,
      0xf7, 0xa3, 0x52, 0x42, 0x21, 0xf0, 0x13, 0x1c, 0x9c, 0x83, 0x88, 0xd6,
      0x93, 0x0c, 0xf6, 0x36, 0x30, 0x05, 0x7e, 0x20, 0xb5, 0xb5, 0x73, 0x36,
      0x53, 0x83, 0x0a, 0xfc, 0x17, 0x63, 0xbf, 0xa0, 0xe4, 0x42, 0x90, 0x0d,
      0x2f, 0x18, 0x6d, 0x20, 0xd8, 0x36, 0x3f, 0xfc, 0xe6, 0x01, 0xfa, 0x0f,
      0xa5, 0x75, 0x7f, 0x09, 0x00, 0x04, 0x00, 0x16, 0x03, 0x01, 0x11, 0x57,
      0x0b, 0x00, 0x11, 0x53, 0x00, 0x11, 0x50, 0x00, 0x06, 0x22, 0x30, 0x82,
      0x06, 0x1e, 0x30, 0x82, 0x05, 0x06, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02,
      0x0a};

  // All reads and writes complete synchronously (async=false).
  MockRead data_reads[] = {
      MockRead(SYNCHRONOUS,
               reinterpret_cast<const char*>(application_data),
               arraysize(application_data)),
      MockRead(SYNCHRONOUS, OK), };

  StaticSocketDataProvider data(data_reads, arraysize(data_reads), NULL, 0);

  TestCompletionCallback callback;
  std::unique_ptr<StreamSocket> transport(
      new MockTCPClientSocket(addr(), NULL, &data));
  int rv = callback.GetResult(transport->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());

  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(transport), spawned_test_server()->host_port_pair(),
      SSLConfig()));

  rv = callback.GetResult(sock->Connect(callback.callback()));
  EXPECT_THAT(rv, IsError(ERR_SSL_PROTOCOL_ERROR));
}

TEST_F(SSLClientSocketTest, CipherSuiteDisables) {
  // Rather than exhaustively disabling every AES_128_CBC ciphersuite defined at
  // http://www.iana.org/assignments/tls-parameters/tls-parameters.xml, only
  // disabling those cipher suites that the test server actually implements.
  const uint16_t kCiphersToDisable[] = {
      0x002f,  // TLS_RSA_WITH_AES_128_CBC_SHA
      0x0033,  // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
      0xc013,  // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
  };

  SpawnedTestServer::SSLOptions ssl_options;
  // Enable only AES_128_CBC on the test server.
  ssl_options.bulk_ciphers = SpawnedTestServer::SSLOptions::BULK_CIPHER_AES128;
  ASSERT_TRUE(StartTestServer(ssl_options));

  SSLConfig ssl_config;
  for (size_t i = 0; i < arraysize(kCiphersToDisable); ++i)
    ssl_config.disabled_cipher_suites.push_back(kCiphersToDisable[i]);

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  EXPECT_THAT(rv, IsError(ERR_SSL_VERSION_OR_CIPHER_MISMATCH));
}

// When creating an SSLClientSocket, it is allowed to pass in a
// ClientSocketHandle that is not obtained from a client socket pool.
// Here we verify that such a simple ClientSocketHandle, not associated with any
// client socket pool, can be destroyed safely.
TEST_F(SSLClientSocketTest, ClientSocketHandleNotFromPool) {
  ASSERT_TRUE(StartTestServer(SpawnedTestServer::SSLOptions()));

  TestCompletionCallback callback;
  std::unique_ptr<StreamSocket> transport(
      new TCPClientSocket(addr(), NULL, NULL, NetLogSource()));
  int rv = callback.GetResult(transport->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());

  std::unique_ptr<ClientSocketHandle> socket_handle(new ClientSocketHandle());
  socket_handle->SetSocket(std::move(transport));

  std::unique_ptr<SSLClientSocket> sock(socket_factory_->CreateSSLClientSocket(
      std::move(socket_handle), spawned_test_server()->host_port_pair(),
      SSLConfig(), context_));

  EXPECT_FALSE(sock->IsConnected());
  rv = callback.GetResult(sock->Connect(callback.callback()));
  EXPECT_THAT(rv, IsOk());
}

// Verifies that SSLClientSocket::ExportKeyingMaterial return a success
// code and different keying label results in different keying material.
TEST_F(SSLClientSocketTest, ExportKeyingMaterial) {
  ASSERT_TRUE(StartTestServer(SpawnedTestServer::SSLOptions()));

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock_->IsConnected());

  const int kKeyingMaterialSize = 32;
  const char kKeyingLabel1[] = "client-socket-test-1";
  const char kKeyingContext1[] = "";
  unsigned char client_out1[kKeyingMaterialSize];
  memset(client_out1, 0, sizeof(client_out1));
  rv = sock_->ExportKeyingMaterial(kKeyingLabel1, false, kKeyingContext1,
                                   client_out1, sizeof(client_out1));
  EXPECT_EQ(rv, OK);

  const char kKeyingLabel2[] = "client-socket-test-2";
  unsigned char client_out2[kKeyingMaterialSize];
  memset(client_out2, 0, sizeof(client_out2));
  rv = sock_->ExportKeyingMaterial(kKeyingLabel2, false, kKeyingContext1,
                                   client_out2, sizeof(client_out2));
  EXPECT_EQ(rv, OK);
  EXPECT_NE(memcmp(client_out1, client_out2, kKeyingMaterialSize), 0);

  const char kKeyingContext2[] = "context";
  rv = sock_->ExportKeyingMaterial(kKeyingLabel1, true, kKeyingContext2,
                                   client_out2, sizeof(client_out2));
  EXPECT_EQ(rv, OK);
  EXPECT_NE(memcmp(client_out1, client_out2, kKeyingMaterialSize), 0);

  // Using an empty context should give different key material from not using a
  // context at all.
  memset(client_out2, 0, sizeof(client_out2));
  rv = sock_->ExportKeyingMaterial(kKeyingLabel1, true, kKeyingContext1,
                                   client_out2, sizeof(client_out2));
  EXPECT_EQ(rv, OK);
  EXPECT_NE(memcmp(client_out1, client_out2, kKeyingMaterialSize), 0);
}

// Verifies that SSLClientSocket::ClearSessionCache can be called without
// explicit NSS initialization.
TEST(SSLClientSocket, ClearSessionCache) {
  SSLClientSocket::ClearSessionCache();
}

TEST(SSLClientSocket, SerializeNextProtos) {
  NextProtoVector next_protos;
  next_protos.push_back(kProtoHTTP11);
  next_protos.push_back(kProtoHTTP2);
  static std::vector<uint8_t> serialized =
      SSLClientSocket::SerializeNextProtos(next_protos);
  ASSERT_EQ(12u, serialized.size());
  EXPECT_EQ(8, serialized[0]);  // length("http/1.1")
  EXPECT_EQ('h', serialized[1]);
  EXPECT_EQ('t', serialized[2]);
  EXPECT_EQ('t', serialized[3]);
  EXPECT_EQ('p', serialized[4]);
  EXPECT_EQ('/', serialized[5]);
  EXPECT_EQ('1', serialized[6]);
  EXPECT_EQ('.', serialized[7]);
  EXPECT_EQ('1', serialized[8]);
  EXPECT_EQ(2, serialized[9]);  // length("h2")
  EXPECT_EQ('h', serialized[10]);
  EXPECT_EQ('2', serialized[11]);
}

// Test that the server certificates are properly retrieved from the underlying
// SSL stack.
TEST_F(SSLClientSocketTest, VerifyServerChainProperlyOrdered) {
  // The connection does not have to be successful.
  cert_verifier_->set_default_result(ERR_CERT_INVALID);

  // Set up a test server with CERT_CHAIN_WRONG_ROOT.
  // This makes the server present redundant-server-chain.pem, which contains
  // intermediate certificates.
  SpawnedTestServer::SSLOptions ssl_options(
      SpawnedTestServer::SSLOptions::CERT_CHAIN_WRONG_ROOT);
  ASSERT_TRUE(StartTestServer(ssl_options));

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsError(ERR_CERT_INVALID));
  EXPECT_TRUE(sock_->IsConnected());

  // When given option CERT_CHAIN_WRONG_ROOT, SpawnedTestServer will present
  // certs from redundant-server-chain.pem.
  CertificateList server_certs =
      CreateCertificateListFromFile(GetTestCertsDirectory(),
                                    "redundant-server-chain.pem",
                                    X509Certificate::FORMAT_AUTO);

  // Get the server certificate as received client side.
  SSLInfo ssl_info;
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  scoped_refptr<X509Certificate> server_certificate = ssl_info.unverified_cert;

  // Get the intermediates as received  client side.
  const X509Certificate::OSCertHandles& server_intermediates =
      server_certificate->GetIntermediateCertificates();

  // Check that the unverified server certificate chain is properly retrieved
  // from the underlying ssl stack.
  ASSERT_EQ(4U, server_certs.size());

  EXPECT_TRUE(X509Certificate::IsSameOSCert(
      server_certificate->os_cert_handle(), server_certs[0]->os_cert_handle()));

  ASSERT_EQ(3U, server_intermediates.size());

  EXPECT_TRUE(X509Certificate::IsSameOSCert(server_intermediates[0],
                                            server_certs[1]->os_cert_handle()));
  EXPECT_TRUE(X509Certificate::IsSameOSCert(server_intermediates[1],
                                            server_certs[2]->os_cert_handle()));
  EXPECT_TRUE(X509Certificate::IsSameOSCert(server_intermediates[2],
                                            server_certs[3]->os_cert_handle()));

  sock_->Disconnect();
  EXPECT_FALSE(sock_->IsConnected());
}

// This tests that SSLInfo contains a properly re-constructed certificate
// chain. That, in turn, verifies that GetSSLInfo is giving us the chain as
// verified, not the chain as served by the server. (They may be different.)
//
// CERT_CHAIN_WRONG_ROOT is redundant-server-chain.pem. It contains A
// (end-entity) -> B -> C, and C is signed by D. redundant-validated-chain.pem
// contains a chain of A -> B -> C2, where C2 is the same public key as C, but
// a self-signed root. Such a situation can occur when a new root (C2) is
// cross-certified by an old root (D) and has two different versions of its
// floating around. Servers may supply C2 as an intermediate, but the
// SSLClientSocket should return the chain that was verified, from
// verify_result, instead.
TEST_F(SSLClientSocketTest, VerifyReturnChainProperlyOrdered) {
  // By default, cause the CertVerifier to treat all certificates as
  // expired.
  cert_verifier_->set_default_result(ERR_CERT_DATE_INVALID);

  CertificateList unverified_certs = CreateCertificateListFromFile(
      GetTestCertsDirectory(), "redundant-server-chain.pem",
      X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(4u, unverified_certs.size());

  // We will expect SSLInfo to ultimately contain this chain.
  CertificateList certs =
      CreateCertificateListFromFile(GetTestCertsDirectory(),
                                    "redundant-validated-chain.pem",
                                    X509Certificate::FORMAT_AUTO);
  ASSERT_EQ(3U, certs.size());

  ASSERT_TRUE(certs[0]->Equals(unverified_certs[0].get()));

  X509Certificate::OSCertHandles temp_intermediates;
  temp_intermediates.push_back(certs[1]->os_cert_handle());
  temp_intermediates.push_back(certs[2]->os_cert_handle());

  CertVerifyResult verify_result;
  verify_result.verified_cert = X509Certificate::CreateFromHandle(
      certs[0]->os_cert_handle(), temp_intermediates);

  // Add a rule that maps the server cert (A) to the chain of A->B->C2
  // rather than A->B->C.
  cert_verifier_->AddResultForCert(certs[0].get(), verify_result, OK);

  // Load and install the root for the validated chain.
  scoped_refptr<X509Certificate> root_cert = ImportCertFromFile(
      GetTestCertsDirectory(), "redundant-validated-chain-root.pem");
  ASSERT_NE(static_cast<X509Certificate*>(NULL), root_cert.get());
  ScopedTestRoot scoped_root(root_cert.get());

  // Set up a test server with CERT_CHAIN_WRONG_ROOT.
  SpawnedTestServer::SSLOptions ssl_options(
      SpawnedTestServer::SSLOptions::CERT_CHAIN_WRONG_ROOT);
  ASSERT_TRUE(StartTestServer(ssl_options));

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock_->IsConnected());

  TestNetLogEntry::List entries;
  log_.GetEntries(&entries);
  EXPECT_TRUE(LogContainsEndEvent(entries, -1, NetLogEventType::SSL_CONNECT));

  SSLInfo ssl_info;
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));

  // Verify that SSLInfo contains the corrected re-constructed chain A -> B
  // -> C2.
  ASSERT_TRUE(ssl_info.cert);
  const X509Certificate::OSCertHandles& intermediates =
      ssl_info.cert->GetIntermediateCertificates();
  ASSERT_EQ(2U, intermediates.size());
  EXPECT_TRUE(X509Certificate::IsSameOSCert(ssl_info.cert->os_cert_handle(),
                                            certs[0]->os_cert_handle()));
  EXPECT_TRUE(X509Certificate::IsSameOSCert(intermediates[0],
                                            certs[1]->os_cert_handle()));
  EXPECT_TRUE(X509Certificate::IsSameOSCert(intermediates[1],
                                            certs[2]->os_cert_handle()));

  // Verify that SSLInfo also contains the chain as received from the server.
  ASSERT_TRUE(ssl_info.unverified_cert);
  const X509Certificate::OSCertHandles& served_intermediates =
      ssl_info.unverified_cert->GetIntermediateCertificates();
  ASSERT_EQ(3U, served_intermediates.size());
  EXPECT_TRUE(X509Certificate::IsSameOSCert(
      ssl_info.cert->os_cert_handle(), unverified_certs[0]->os_cert_handle()));
  EXPECT_TRUE(X509Certificate::IsSameOSCert(
      served_intermediates[0], unverified_certs[1]->os_cert_handle()));
  EXPECT_TRUE(X509Certificate::IsSameOSCert(
      served_intermediates[1], unverified_certs[2]->os_cert_handle()));
  EXPECT_TRUE(X509Certificate::IsSameOSCert(
      served_intermediates[2], unverified_certs[3]->os_cert_handle()));

  sock_->Disconnect();
  EXPECT_FALSE(sock_->IsConnected());
}

TEST_F(SSLClientSocketCertRequestInfoTest, NoAuthorities) {
  SpawnedTestServer::SSLOptions ssl_options;
  ssl_options.request_client_certificate = true;
  scoped_refptr<SSLCertRequestInfo> request_info = GetCertRequest(ssl_options);
  ASSERT_TRUE(request_info.get());
  EXPECT_EQ(0u, request_info->cert_authorities.size());
}

TEST_F(SSLClientSocketCertRequestInfoTest, TwoAuthorities) {
  const base::FilePath::CharType kThawteFile[] =
      FILE_PATH_LITERAL("thawte.single.pem");
  const unsigned char kThawteDN[] = {
      0x30, 0x4c, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
      0x02, 0x5a, 0x41, 0x31, 0x25, 0x30, 0x23, 0x06, 0x03, 0x55, 0x04, 0x0a,
      0x13, 0x1c, 0x54, 0x68, 0x61, 0x77, 0x74, 0x65, 0x20, 0x43, 0x6f, 0x6e,
      0x73, 0x75, 0x6c, 0x74, 0x69, 0x6e, 0x67, 0x20, 0x28, 0x50, 0x74, 0x79,
      0x29, 0x20, 0x4c, 0x74, 0x64, 0x2e, 0x31, 0x16, 0x30, 0x14, 0x06, 0x03,
      0x55, 0x04, 0x03, 0x13, 0x0d, 0x54, 0x68, 0x61, 0x77, 0x74, 0x65, 0x20,
      0x53, 0x47, 0x43, 0x20, 0x43, 0x41};
  const size_t kThawteLen = sizeof(kThawteDN);

  const base::FilePath::CharType kDiginotarFile[] =
      FILE_PATH_LITERAL("diginotar_root_ca.pem");
  const unsigned char kDiginotarDN[] = {
      0x30, 0x5f, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
      0x02, 0x4e, 0x4c, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a,
      0x13, 0x09, 0x44, 0x69, 0x67, 0x69, 0x4e, 0x6f, 0x74, 0x61, 0x72, 0x31,
      0x1a, 0x30, 0x18, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x11, 0x44, 0x69,
      0x67, 0x69, 0x4e, 0x6f, 0x74, 0x61, 0x72, 0x20, 0x52, 0x6f, 0x6f, 0x74,
      0x20, 0x43, 0x41, 0x31, 0x20, 0x30, 0x1e, 0x06, 0x09, 0x2a, 0x86, 0x48,
      0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x16, 0x11, 0x69, 0x6e, 0x66, 0x6f,
      0x40, 0x64, 0x69, 0x67, 0x69, 0x6e, 0x6f, 0x74, 0x61, 0x72, 0x2e, 0x6e,
      0x6c};
  const size_t kDiginotarLen = sizeof(kDiginotarDN);

  SpawnedTestServer::SSLOptions ssl_options;
  ssl_options.request_client_certificate = true;
  ssl_options.client_authorities.push_back(
      GetTestClientCertsDirectory().Append(kThawteFile));
  ssl_options.client_authorities.push_back(
      GetTestClientCertsDirectory().Append(kDiginotarFile));
  scoped_refptr<SSLCertRequestInfo> request_info = GetCertRequest(ssl_options);
  ASSERT_TRUE(request_info.get());
  ASSERT_EQ(2u, request_info->cert_authorities.size());
  EXPECT_EQ(std::string(reinterpret_cast<const char*>(kThawteDN), kThawteLen),
            request_info->cert_authorities[0]);
  EXPECT_EQ(
      std::string(reinterpret_cast<const char*>(kDiginotarDN), kDiginotarLen),
      request_info->cert_authorities[1]);
}

TEST_F(SSLClientSocketCertRequestInfoTest, CertKeyTypes) {
  SpawnedTestServer::SSLOptions ssl_options;
  ssl_options.request_client_certificate = true;
  ssl_options.client_cert_types.push_back(CLIENT_CERT_RSA_SIGN);
  ssl_options.client_cert_types.push_back(CLIENT_CERT_ECDSA_SIGN);
  scoped_refptr<SSLCertRequestInfo> request_info = GetCertRequest(ssl_options);
  ASSERT_TRUE(request_info.get());
  ASSERT_EQ(2u, request_info->cert_key_types.size());
  EXPECT_EQ(CLIENT_CERT_RSA_SIGN, request_info->cert_key_types[0]);
  EXPECT_EQ(CLIENT_CERT_ECDSA_SIGN, request_info->cert_key_types[1]);
}

TEST_F(SSLClientSocketTest, ConnectSignedCertTimestampsEnabledTLSExtension) {
  // Encoding of SCT List containing 'test'.
  base::StringPiece sct_ext("\x00\x06\x00\x04test", 8);

  SpawnedTestServer::SSLOptions ssl_options;
  ssl_options.signed_cert_timestamps_tls_ext = sct_ext.as_string();
  ASSERT_TRUE(StartTestServer(ssl_options));

  SSLConfig ssl_config;
  ssl_config.signed_cert_timestamps_enabled = true;

  MockCTVerifier ct_verifier;
  SetCTVerifier(&ct_verifier);

  // Check that the SCT list is extracted from the TLS extension as expected,
  // while also simulating that it was an unparsable response.
  SignedCertificateTimestampAndStatusList sct_list;
  EXPECT_CALL(ct_verifier, Verify(_, _, sct_ext, _, _))
      .WillOnce(testing::SetArgPointee<3>(sct_list));

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  EXPECT_THAT(rv, IsOk());

  EXPECT_TRUE(sock_->signed_cert_timestamps_received_);
}

// Test that when a CT verifier and a CTPolicyEnforcer are defined, and
// the EV certificate used conforms to the CT/EV policy, its EV status
// is maintained.
TEST_F(SSLClientSocketTest, EVCertStatusMaintainedForCompliantCert) {
  SpawnedTestServer::SSLOptions ssl_options;
  ASSERT_TRUE(StartTestServer(ssl_options));

  SSLConfig ssl_config;
  AddServerCertStatusToSSLConfig(CERT_STATUS_IS_EV, &ssl_config);

  // Emulate compliance of the certificate to the policy.
  MockCTPolicyEnforcer policy_enforcer;
  SetCTPolicyEnforcer(&policy_enforcer);
  EXPECT_CALL(policy_enforcer, DoesConformToCertPolicy(_, _, _))
      .WillRepeatedly(
          Return(ct::CertPolicyCompliance::CERT_POLICY_COMPLIES_VIA_SCTS));
  EXPECT_CALL(policy_enforcer, DoesConformToCTEVPolicy(_, _, _, _))
      .WillRepeatedly(
          Return(ct::EVPolicyCompliance::EV_POLICY_COMPLIES_VIA_SCTS));

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  EXPECT_THAT(rv, IsOk());

  SSLInfo result;
  ASSERT_TRUE(sock_->GetSSLInfo(&result));

  EXPECT_TRUE(result.cert_status & CERT_STATUS_IS_EV);
}

// Test that when a CT verifier and a CTPolicyEnforcer are defined, but
// the EV certificate used does not conform to the CT/EV policy, its EV status
// is removed.
TEST_F(SSLClientSocketTest, EVCertStatusRemovedForNonCompliantCert) {
  SpawnedTestServer::SSLOptions ssl_options;
  ASSERT_TRUE(StartTestServer(ssl_options));

  SSLConfig ssl_config;
  AddServerCertStatusToSSLConfig(CERT_STATUS_IS_EV, &ssl_config);

  // Emulate non-compliance of the certificate to the policy.
  MockCTPolicyEnforcer policy_enforcer;
  SetCTPolicyEnforcer(&policy_enforcer);
  EXPECT_CALL(policy_enforcer, DoesConformToCertPolicy(_, _, _))
      .WillRepeatedly(
          Return(ct::CertPolicyCompliance::CERT_POLICY_NOT_ENOUGH_SCTS));
  EXPECT_CALL(policy_enforcer, DoesConformToCTEVPolicy(_, _, _, _))
      .WillRepeatedly(
          Return(ct::EVPolicyCompliance::EV_POLICY_NOT_ENOUGH_SCTS));

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  EXPECT_THAT(rv, IsOk());

  SSLInfo result;
  ASSERT_TRUE(sock_->GetSSLInfo(&result));

  EXPECT_FALSE(result.cert_status & CERT_STATUS_IS_EV);
  EXPECT_TRUE(result.cert_status & CERT_STATUS_CT_COMPLIANCE_FAILED);
}

// Test that enabling Signed Certificate Timestamps enables OCSP stapling.
TEST_F(SSLClientSocketTest, ConnectSignedCertTimestampsEnabledOCSP) {
  SpawnedTestServer::SSLOptions ssl_options;
  ssl_options.staple_ocsp_response = true;
  // The test server currently only knows how to generate OCSP responses
  // for a freshly minted certificate.
  ssl_options.server_certificate = SpawnedTestServer::SSLOptions::CERT_AUTO;

  ASSERT_TRUE(StartTestServer(ssl_options));

  SSLConfig ssl_config;
  // Enabling Signed Cert Timestamps ensures we request OCSP stapling for
  // Certificate Transparency verification regardless of whether the platform
  // is able to process the OCSP status itself.
  ssl_config.signed_cert_timestamps_enabled = true;

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  EXPECT_THAT(rv, IsOk());

  EXPECT_TRUE(sock_->stapled_ocsp_response_received_);
}

TEST_F(SSLClientSocketTest, ConnectSignedCertTimestampsDisabled) {
  SpawnedTestServer::SSLOptions ssl_options;
  ssl_options.signed_cert_timestamps_tls_ext = "test";

  ASSERT_TRUE(StartTestServer(ssl_options));

  SSLConfig ssl_config;
  ssl_config.signed_cert_timestamps_enabled = false;

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  EXPECT_THAT(rv, IsOk());

  EXPECT_FALSE(sock_->signed_cert_timestamps_received_);
}

// Tests that IsConnectedAndIdle and WasEverUsed behave as expected.
TEST_F(SSLClientSocketTest, ReuseStates) {
  ASSERT_TRUE(StartTestServer(SpawnedTestServer::SSLOptions()));

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));

  // The socket was just connected. It should be idle because it is speaking
  // HTTP. Although the transport has been used for the handshake, WasEverUsed()
  // returns false.
  EXPECT_TRUE(sock_->IsConnected());
  EXPECT_TRUE(sock_->IsConnectedAndIdle());
  EXPECT_FALSE(sock_->WasEverUsed());

  const char kRequestText[] = "GET / HTTP/1.0\r\n\r\n";
  const size_t kRequestLen = arraysize(kRequestText) - 1;
  scoped_refptr<IOBuffer> request_buffer(new IOBuffer(kRequestLen));
  memcpy(request_buffer->data(), kRequestText, kRequestLen);

  TestCompletionCallback callback;
  rv = callback.GetResult(
      sock_->Write(request_buffer.get(), kRequestLen, callback.callback()));
  EXPECT_EQ(static_cast<int>(kRequestLen), rv);

  // The socket has now been used.
  EXPECT_TRUE(sock_->WasEverUsed());

  // TODO(davidben): Read one byte to ensure the test server has responded and
  // then assert IsConnectedAndIdle is false. This currently doesn't work
  // because SSLClientSocketImpl doesn't check the implementation's internal
  // buffer. Call SSL_pending.
}

// Tests that IsConnectedAndIdle treats a socket as idle even if a Write hasn't
// been flushed completely out of SSLClientSocket's internal buffers. This is a
// regression test for https://crbug.com/466147.
TEST_F(SSLClientSocketTest, ReusableAfterWrite) {
  ASSERT_TRUE(StartTestServer(SpawnedTestServer::SSLOptions()));

  TestCompletionCallback callback;
  std::unique_ptr<StreamSocket> real_transport(
      new TCPClientSocket(addr(), NULL, NULL, NetLogSource()));
  std::unique_ptr<FakeBlockingStreamSocket> transport(
      new FakeBlockingStreamSocket(std::move(real_transport)));
  FakeBlockingStreamSocket* raw_transport = transport.get();
  ASSERT_THAT(callback.GetResult(transport->Connect(callback.callback())),
              IsOk());

  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(transport), spawned_test_server()->host_port_pair(),
      SSLConfig()));
  ASSERT_THAT(callback.GetResult(sock->Connect(callback.callback())), IsOk());

  // Block any application data from reaching the network.
  raw_transport->BlockWrite();

  // Write a partial HTTP request.
  const char kRequestText[] = "GET / HTTP/1.0";
  const size_t kRequestLen = arraysize(kRequestText) - 1;
  scoped_refptr<IOBuffer> request_buffer(new IOBuffer(kRequestLen));
  memcpy(request_buffer->data(), kRequestText, kRequestLen);

  // Although transport writes are blocked, SSLClientSocketImpl completes the
  // outer Write operation.
  EXPECT_EQ(static_cast<int>(kRequestLen),
            callback.GetResult(sock->Write(request_buffer.get(), kRequestLen,
                                           callback.callback())));

  // The Write operation is complete, so the socket should be treated as
  // reusable, in case the server returns an HTTP response before completely
  // consuming the request body. In this case, we assume the server will
  // properly drain the request body before trying to read the next request.
  EXPECT_TRUE(sock->IsConnectedAndIdle());
}

// Tests that basic session resumption works.
TEST_F(SSLClientSocketTest, SessionResumption) {
  SpawnedTestServer::SSLOptions ssl_options;
  ASSERT_TRUE(StartTestServer(ssl_options));

  // First, perform a full handshake.
  SSLConfig ssl_config;
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  ASSERT_THAT(rv, IsOk());
  SSLInfo ssl_info;
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, ssl_info.handshake_type);

  // The next connection should resume.
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  ASSERT_THAT(rv, IsOk());
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_RESUME, ssl_info.handshake_type);
  sock_.reset();

  // Using a different HostPortPair uses a different session cache key.
  std::unique_ptr<StreamSocket> transport(
      new TCPClientSocket(addr(), NULL, &log_, NetLogSource()));
  TestCompletionCallback callback;
  ASSERT_THAT(callback.GetResult(transport->Connect(callback.callback())),
              IsOk());
  std::unique_ptr<SSLClientSocket> sock = CreateSSLClientSocket(
      std::move(transport), HostPortPair("example.com", 443), ssl_config);
  ASSERT_THAT(callback.GetResult(sock->Connect(callback.callback())), IsOk());
  ASSERT_TRUE(sock->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, ssl_info.handshake_type);
  sock.reset();

  SSLClientSocket::ClearSessionCache();

  // After clearing the session cache, the next handshake doesn't resume.
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  ASSERT_THAT(rv, IsOk());
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, ssl_info.handshake_type);
}

// Tests that ALPN works with session resumption.
TEST_F(SSLClientSocketTest, SessionResumptionAlpn) {
  SpawnedTestServer::SSLOptions ssl_options;
  ssl_options.alpn_protocols.push_back("h2");
  ssl_options.alpn_protocols.push_back("http/1.1");
  ASSERT_TRUE(StartTestServer(ssl_options));

  // First, perform a full handshake.
  SSLConfig ssl_config;
  // Disable TLS False Start to ensure the handshake has completed.
  ssl_config.false_start_enabled = false;
  ssl_config.alpn_protos.push_back(kProtoHTTP2);
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  ASSERT_THAT(rv, IsOk());
  SSLInfo ssl_info;
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, ssl_info.handshake_type);
  EXPECT_EQ(kProtoHTTP2, sock_->GetNegotiatedProtocol());

  // The next connection should resume; ALPN should be renegotiated.
  ssl_config.alpn_protos.clear();
  ssl_config.alpn_protos.push_back(kProtoHTTP11);
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  ASSERT_THAT(rv, IsOk());
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_RESUME, ssl_info.handshake_type);
  EXPECT_EQ(kProtoHTTP11, sock_->GetNegotiatedProtocol());
}

// Tests that connections with certificate errors do not add entries to the
// session cache.
TEST_F(SSLClientSocketTest, CertificateErrorNoResume) {
  SpawnedTestServer::SSLOptions ssl_options;
  ASSERT_TRUE(StartTestServer(ssl_options));

  cert_verifier_->set_default_result(ERR_CERT_COMMON_NAME_INVALID);

  SSLConfig ssl_config;
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  ASSERT_THAT(rv, IsError(ERR_CERT_COMMON_NAME_INVALID));

  cert_verifier_->set_default_result(OK);

  // The next connection should perform a full handshake.
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  ASSERT_THAT(rv, IsOk());
  SSLInfo ssl_info;
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, ssl_info.handshake_type);
}

// Test that DHE is removed.
TEST_F(SSLClientSocketTest, NoDHE) {
  SpawnedTestServer::SSLOptions ssl_options;
  ssl_options.key_exchanges =
      SpawnedTestServer::SSLOptions::KEY_EXCHANGE_DHE_RSA;
  ASSERT_TRUE(StartTestServer(ssl_options));

  SSLConfig ssl_config;
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  EXPECT_THAT(rv, IsError(ERR_SSL_VERSION_OR_CIPHER_MISMATCH));
}

// Tests that enabling deprecated ciphers shards the session cache.
TEST_F(SSLClientSocketTest, DeprecatedShardSessionCache) {
  ASSERT_TRUE(StartTestServer(SpawnedTestServer::SSLOptions()));

  // Prepare a normal and deprecated SSL config.
  SSLConfig ssl_config;
  SSLConfig deprecated_ssl_config;
  deprecated_ssl_config.deprecated_cipher_suites_enabled = true;

  // Connect with deprecated ciphers enabled to warm the session cache cache.
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(deprecated_ssl_config, &rv));
  EXPECT_THAT(rv, IsOk());
  SSLInfo ssl_info;
  EXPECT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, ssl_info.handshake_type);

  // Test that re-connecting with deprecated ciphers enabled still resumes.
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(deprecated_ssl_config, &rv));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_RESUME, ssl_info.handshake_type);

  // However, a normal connection needs a full handshake.
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, ssl_info.handshake_type);

  // Clear the session cache for the inverse test.
  SSLClientSocket::ClearSessionCache();

  // Now make a normal connection to prime the session cache.
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, ssl_info.handshake_type);

  // A normal connection should be able to resume.
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_RESUME, ssl_info.handshake_type);

  // However, enabling deprecated ciphers connects fresh.
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(deprecated_ssl_config, &rv));
  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, ssl_info.handshake_type);
}

TEST_F(SSLClientSocketTest, RequireECDHE) {
  // Run test server without ECDHE.
  SpawnedTestServer::SSLOptions ssl_options;
  ssl_options.key_exchanges = SpawnedTestServer::SSLOptions::KEY_EXCHANGE_RSA;
  ASSERT_TRUE(StartTestServer(ssl_options));

  SSLConfig config;
  config.require_ecdhe = true;
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(config, &rv));
  EXPECT_THAT(rv, IsError(ERR_SSL_VERSION_OR_CIPHER_MISMATCH));
}

TEST_F(SSLClientSocketTest, TokenBindingEnabled) {
  SpawnedTestServer::SSLOptions ssl_options;
  ssl_options.supported_token_binding_params.push_back(TB_PARAM_ECDSAP256);
  ASSERT_TRUE(StartTestServer(ssl_options));

  SSLConfig ssl_config;
  ssl_config.token_binding_params.push_back(TB_PARAM_ECDSAP256);

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  EXPECT_THAT(rv, IsOk());
  SSLInfo info;
  EXPECT_TRUE(sock_->GetSSLInfo(&info));
  EXPECT_TRUE(info.token_binding_negotiated);
  EXPECT_EQ(TB_PARAM_ECDSAP256, info.token_binding_key_param);
}

TEST_F(SSLClientSocketTest, TokenBindingFailsWithEmsDisabled) {
  SpawnedTestServer::SSLOptions ssl_options;
  ssl_options.supported_token_binding_params.push_back(TB_PARAM_ECDSAP256);
  ssl_options.disable_extended_master_secret = true;
  ASSERT_TRUE(StartTestServer(ssl_options));

  SSLConfig ssl_config;
  ssl_config.token_binding_params.push_back(TB_PARAM_ECDSAP256);

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  EXPECT_THAT(rv, IsError(ERR_SSL_PROTOCOL_ERROR));
}

TEST_F(SSLClientSocketTest, TokenBindingEnabledWithoutServerSupport) {
  SpawnedTestServer::SSLOptions ssl_options;
  ASSERT_TRUE(StartTestServer(ssl_options));

  SSLConfig ssl_config;
  ssl_config.token_binding_params.push_back(TB_PARAM_ECDSAP256);

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  EXPECT_THAT(rv, IsOk());
  SSLInfo info;
  EXPECT_TRUE(sock_->GetSSLInfo(&info));
  EXPECT_FALSE(info.token_binding_negotiated);
}

TEST_F(SSLClientSocketFalseStartTest, FalseStartEnabled) {
  // False Start requires ALPN, ECDHE, and an AEAD.
  SpawnedTestServer::SSLOptions server_options;
  server_options.key_exchanges =
      SpawnedTestServer::SSLOptions::KEY_EXCHANGE_ECDHE_RSA;
  server_options.bulk_ciphers =
      SpawnedTestServer::SSLOptions::BULK_CIPHER_AES128GCM;
  server_options.alpn_protocols.push_back("http/1.1");
  SSLConfig client_config;
  client_config.alpn_protos.push_back(kProtoHTTP11);
  ASSERT_NO_FATAL_FAILURE(TestFalseStart(server_options, client_config, true));
}

// Test that False Start is disabled without ALPN.
TEST_F(SSLClientSocketFalseStartTest, NoAlpn) {
  SpawnedTestServer::SSLOptions server_options;
  server_options.key_exchanges =
      SpawnedTestServer::SSLOptions::KEY_EXCHANGE_ECDHE_RSA;
  server_options.bulk_ciphers =
      SpawnedTestServer::SSLOptions::BULK_CIPHER_AES128GCM;
  SSLConfig client_config;
  client_config.alpn_protos.clear();
  ASSERT_NO_FATAL_FAILURE(
      TestFalseStart(server_options, client_config, false));
}

// Test that False Start is disabled with plain RSA ciphers.
TEST_F(SSLClientSocketFalseStartTest, RSA) {
  SpawnedTestServer::SSLOptions server_options;
  server_options.key_exchanges =
      SpawnedTestServer::SSLOptions::KEY_EXCHANGE_RSA;
  server_options.bulk_ciphers =
      SpawnedTestServer::SSLOptions::BULK_CIPHER_AES128GCM;
  server_options.alpn_protocols.push_back("http/1.1");
  SSLConfig client_config;
  client_config.alpn_protos.push_back(kProtoHTTP11);
  ASSERT_NO_FATAL_FAILURE(
      TestFalseStart(server_options, client_config, false));
}

// Test that False Start is disabled without an AEAD.
TEST_F(SSLClientSocketFalseStartTest, NoAEAD) {
  SpawnedTestServer::SSLOptions server_options;
  server_options.key_exchanges =
      SpawnedTestServer::SSLOptions::KEY_EXCHANGE_ECDHE_RSA;
  server_options.bulk_ciphers =
      SpawnedTestServer::SSLOptions::BULK_CIPHER_AES128;
  server_options.alpn_protocols.push_back("http/1.1");
  SSLConfig client_config;
  client_config.alpn_protos.push_back(kProtoHTTP11);
  ASSERT_NO_FATAL_FAILURE(TestFalseStart(server_options, client_config, false));
}

// Test that sessions are resumable after receiving the server Finished message.
TEST_F(SSLClientSocketFalseStartTest, SessionResumption) {
  // Start a server.
  SpawnedTestServer::SSLOptions server_options;
  server_options.key_exchanges =
      SpawnedTestServer::SSLOptions::KEY_EXCHANGE_ECDHE_RSA;
  server_options.bulk_ciphers =
      SpawnedTestServer::SSLOptions::BULK_CIPHER_AES128GCM;
  server_options.alpn_protocols.push_back("http/1.1");
  SSLConfig client_config;
  client_config.alpn_protos.push_back(kProtoHTTP11);

  // Let a full handshake complete with False Start.
  ASSERT_NO_FATAL_FAILURE(
      TestFalseStart(server_options, client_config, true));

  // Make a second connection.
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(client_config, &rv));
  EXPECT_THAT(rv, IsOk());

  // It should resume the session.
  SSLInfo ssl_info;
  EXPECT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_RESUME, ssl_info.handshake_type);
}

// Test that False Started sessions are not resumable before receiving the
// server Finished message.
TEST_F(SSLClientSocketFalseStartTest, NoSessionResumptionBeforeFinished) {
  // Start a server.
  SpawnedTestServer::SSLOptions server_options;
  server_options.key_exchanges =
      SpawnedTestServer::SSLOptions::KEY_EXCHANGE_ECDHE_RSA;
  server_options.bulk_ciphers =
      SpawnedTestServer::SSLOptions::BULK_CIPHER_AES128GCM;
  server_options.alpn_protocols.push_back("http/1.1");
  ASSERT_TRUE(StartTestServer(server_options));

  SSLConfig client_config;
  client_config.alpn_protos.push_back(kProtoHTTP11);

  // Start a handshake up to the server Finished message.
  TestCompletionCallback callback;
  FakeBlockingStreamSocket* raw_transport1 = NULL;
  std::unique_ptr<SSLClientSocket> sock1;
  ASSERT_NO_FATAL_FAILURE(CreateAndConnectUntilServerFinishedReceived(
      client_config, &callback, &raw_transport1, &sock1));
  // Although raw_transport1 has the server Finished blocked, the handshake
  // still completes.
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  // Continue to block the client (|sock1|) from processing the Finished
  // message, but allow it to arrive on the socket. This ensures that, from the
  // server's point of view, it has completed the handshake and added the
  // session to its session cache.
  //
  // The actual read on |sock1| will not complete until the Finished message is
  // processed; however, pump the underlying transport so that it is read from
  // the socket. NOTE: This may flakily pass if the server's final flight
  // doesn't come in one Read.
  scoped_refptr<IOBuffer> buf(new IOBuffer(4096));
  int rv = sock1->Read(buf.get(), 4096, callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  raw_transport1->WaitForReadResult();

  // Drop the old socket. This is needed because the Python test server can't
  // service two sockets in parallel.
  sock1.reset();

  // Start a second connection.
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(client_config, &rv));
  EXPECT_THAT(rv, IsOk());

  // No session resumption because the first connection never received a server
  // Finished message.
  SSLInfo ssl_info;
  EXPECT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, ssl_info.handshake_type);
}

// Test that False Started sessions are not resumable if the server Finished
// message was bad.
TEST_F(SSLClientSocketFalseStartTest, NoSessionResumptionBadFinished) {
  // Start a server.
  SpawnedTestServer::SSLOptions server_options;
  server_options.key_exchanges =
      SpawnedTestServer::SSLOptions::KEY_EXCHANGE_ECDHE_RSA;
  server_options.bulk_ciphers =
      SpawnedTestServer::SSLOptions::BULK_CIPHER_AES128GCM;
  server_options.alpn_protocols.push_back("http/1.1");
  ASSERT_TRUE(StartTestServer(server_options));

  SSLConfig client_config;
  client_config.alpn_protos.push_back(kProtoHTTP11);

  // Start a handshake up to the server Finished message.
  TestCompletionCallback callback;
  FakeBlockingStreamSocket* raw_transport1 = NULL;
  std::unique_ptr<SSLClientSocket> sock1;
  ASSERT_NO_FATAL_FAILURE(CreateAndConnectUntilServerFinishedReceived(
      client_config, &callback, &raw_transport1, &sock1));
  // Although raw_transport1 has the server Finished blocked, the handshake
  // still completes.
  EXPECT_THAT(callback.WaitForResult(), IsOk());

  // Continue to block the client (|sock1|) from processing the Finished
  // message, but allow it to arrive on the socket. This ensures that, from the
  // server's point of view, it has completed the handshake and added the
  // session to its session cache.
  //
  // The actual read on |sock1| will not complete until the Finished message is
  // processed; however, pump the underlying transport so that it is read from
  // the socket.
  scoped_refptr<IOBuffer> buf(new IOBuffer(4096));
  int rv = sock1->Read(buf.get(), 4096, callback.callback());
  EXPECT_THAT(rv, IsError(ERR_IO_PENDING));
  raw_transport1->WaitForReadResult();

  // The server's second leg, or part of it, is now received but not yet sent to
  // |sock1|. Before doing so, break the server's second leg.
  int bytes_read = raw_transport1->pending_read_result();
  ASSERT_LT(0, bytes_read);
  raw_transport1->pending_read_buf()->data()[bytes_read - 1]++;

  // Unblock the Finished message. |sock1->Read| should now fail.
  raw_transport1->UnblockReadResult();
  EXPECT_THAT(callback.GetResult(rv), IsError(ERR_SSL_PROTOCOL_ERROR));

  // Drop the old socket. This is needed because the Python test server can't
  // service two sockets in parallel.
  sock1.reset();

  // Start a second connection.
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(client_config, &rv));
  EXPECT_THAT(rv, IsOk());

  // No session resumption because the first connection never received a server
  // Finished message.
  SSLInfo ssl_info;
  EXPECT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, ssl_info.handshake_type);
}

// Connect to a server using channel id. It should allow the connection.
TEST_F(SSLClientSocketChannelIDTest, SendChannelID) {
  SpawnedTestServer::SSLOptions ssl_options;

  ASSERT_TRUE(StartTestServer(ssl_options));

  EnableChannelID();
  SSLConfig ssl_config;
  ssl_config.channel_id_enabled = true;

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));

  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock_->IsConnected());
  SSLInfo ssl_info;
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_TRUE(ssl_info.channel_id_sent);

  sock_->Disconnect();
  EXPECT_FALSE(sock_->IsConnected());
}

// Connect to a server using Channel ID but failing to look up the Channel
// ID. It should fail.
TEST_F(SSLClientSocketChannelIDTest, FailingChannelID) {
  SpawnedTestServer::SSLOptions ssl_options;

  ASSERT_TRUE(StartTestServer(ssl_options));

  EnableFailingChannelID();
  SSLConfig ssl_config;
  ssl_config.channel_id_enabled = true;

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));

  // TODO(haavardm@opera.com): Due to differences in threading, Linux returns
  // ERR_UNEXPECTED while Mac and Windows return ERR_PROTOCOL_ERROR. Accept all
  // error codes for now.
  // http://crbug.com/373670
  EXPECT_NE(OK, rv);
  EXPECT_FALSE(sock_->IsConnected());
}

// Connect to a server using Channel ID but asynchronously failing to look up
// the Channel ID. It should fail.
TEST_F(SSLClientSocketChannelIDTest, FailingChannelIDAsync) {
  SpawnedTestServer::SSLOptions ssl_options;

  ASSERT_TRUE(StartTestServer(ssl_options));

  EnableAsyncFailingChannelID();
  SSLConfig ssl_config;
  ssl_config.channel_id_enabled = true;

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));

  EXPECT_THAT(rv, IsError(ERR_UNEXPECTED));
  EXPECT_FALSE(sock_->IsConnected());
}

// Tests that session caches are sharded by whether Channel ID is enabled.
TEST_F(SSLClientSocketChannelIDTest, ChannelIDShardSessionCache) {
  SpawnedTestServer::SSLOptions ssl_options;
  ASSERT_TRUE(StartTestServer(ssl_options));

  EnableChannelID();

  // Connect without Channel ID.
  SSLConfig ssl_config;
  ssl_config.channel_id_enabled = false;
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  SSLInfo ssl_info;
  EXPECT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, ssl_info.handshake_type);
  EXPECT_FALSE(ssl_info.channel_id_sent);

  // Enable Channel ID and connect again. This needs a full handshake to assert
  // Channel ID.
  ssl_config.channel_id_enabled = true;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  EXPECT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_EQ(SSLInfo::HANDSHAKE_FULL, ssl_info.handshake_type);
  EXPECT_TRUE(ssl_info.channel_id_sent);
}

// Server preference should win in ALPN.
TEST_F(SSLClientSocketTest, Alpn) {
  SpawnedTestServer::SSLOptions server_options;
  server_options.alpn_protocols.push_back("h2");
  server_options.alpn_protocols.push_back("http/1.1");
  ASSERT_TRUE(StartTestServer(server_options));

  SSLConfig client_config;
  client_config.alpn_protos.push_back(kProtoHTTP11);
  client_config.alpn_protos.push_back(kProtoHTTP2);

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(client_config, &rv));
  EXPECT_THAT(rv, IsOk());

  EXPECT_EQ(kProtoHTTP2, sock_->GetNegotiatedProtocol());
}

// If the server supports ALPN but the client does not, then ALPN is not used.
TEST_F(SSLClientSocketTest, AlpnClientDisabled) {
  SpawnedTestServer::SSLOptions server_options;
  server_options.alpn_protocols.push_back("foo");
  ASSERT_TRUE(StartTestServer(server_options));

  SSLConfig client_config;

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(client_config, &rv));
  EXPECT_THAT(rv, IsOk());

  EXPECT_EQ(kProtoUnknown, sock_->GetNegotiatedProtocol());
}

namespace {

// Loads a PEM-encoded private key file into a SSLPrivateKey object.
// |filepath| is the private key file path.
// Returns the new SSLPrivateKey.
scoped_refptr<SSLPrivateKey> LoadPrivateKeyOpenSSL(
    const base::FilePath& filepath) {
  std::string data;
  if (!base::ReadFileToString(filepath, &data)) {
    LOG(ERROR) << "Could not read private key file: " << filepath.value();
    return nullptr;
  }
  bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(const_cast<char*>(data.data()),
                                           static_cast<int>(data.size())));
  if (!bio) {
    LOG(ERROR) << "Could not allocate BIO for buffer?";
    return nullptr;
  }
  bssl::UniquePtr<EVP_PKEY> result(
      PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
  if (!result) {
    LOG(ERROR) << "Could not decode private key file: " << filepath.value();
    return nullptr;
  }
  return WrapOpenSSLPrivateKey(std::move(result));
}

}  // namespace

// Connect to a server requesting client authentication, do not send
// any client certificates. It should refuse the connection.
TEST_F(SSLClientSocketTest, NoCert) {
  SpawnedTestServer::SSLOptions ssl_options;
  ssl_options.request_client_certificate = true;
  ASSERT_TRUE(StartTestServer(ssl_options));

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));

  EXPECT_THAT(rv, IsError(ERR_SSL_CLIENT_AUTH_CERT_NEEDED));
  EXPECT_FALSE(sock_->IsConnected());
}

// Connect to a server requesting client authentication, and send it
// an empty certificate.
TEST_F(SSLClientSocketTest, SendEmptyCert) {
  SpawnedTestServer::SSLOptions ssl_options;
  ssl_options.request_client_certificate = true;
  ssl_options.client_authorities.push_back(
      GetTestClientCertsDirectory().AppendASCII("client_1_ca.pem"));

  ASSERT_TRUE(StartTestServer(ssl_options));

  SSLConfig ssl_config;
  ssl_config.send_client_cert = true;
  ssl_config.client_cert = nullptr;
  ssl_config.client_private_key = nullptr;

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));

  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock_->IsConnected());

  SSLInfo ssl_info;
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_FALSE(ssl_info.client_cert_sent);
}

// Connect to a server requesting client authentication. Send it a
// matching certificate. It should allow the connection.
TEST_F(SSLClientSocketTest, SendGoodCert) {
  SpawnedTestServer::SSLOptions ssl_options;
  ssl_options.request_client_certificate = true;
  ssl_options.client_authorities.push_back(
      GetTestClientCertsDirectory().AppendASCII("client_1_ca.pem"));

  ASSERT_TRUE(StartTestServer(ssl_options));

  base::FilePath certs_dir = GetTestCertsDirectory();
  SSLConfig ssl_config;
  ssl_config.send_client_cert = true;
  ssl_config.client_cert = ImportCertFromFile(certs_dir, "client_1.pem");
  ssl_config.client_private_key =
      LoadPrivateKeyOpenSSL(certs_dir.AppendASCII("client_1.key"));

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));

  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock_->IsConnected());

  SSLInfo ssl_info;
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));
  EXPECT_TRUE(ssl_info.client_cert_sent);

  sock_->Disconnect();
  EXPECT_FALSE(sock_->IsConnected());
}

HashValueVector MakeHashValueVector(uint8_t value) {
  HashValueVector out;
  HashValue hash(HASH_VALUE_SHA256);
  memset(hash.data(), value, hash.size());
  out.push_back(hash);
  return out;
}

// Test that |ssl_info.pkp_bypassed| is set when a local trust anchor causes
// pinning to be bypassed.
TEST_F(SSLClientSocketTest, PKPBypassedSet) {
  SpawnedTestServer::SSLOptions ssl_options;
  ASSERT_TRUE(StartTestServer(ssl_options));
  scoped_refptr<X509Certificate> server_cert =
      spawned_test_server()->GetCertificate();

  // The certificate needs to be trusted, but chain to a local root with
  // different public key hashes than specified in the pin.
  CertVerifyResult verify_result;
  verify_result.is_issued_by_known_root = false;
  verify_result.verified_cert = server_cert;
  verify_result.public_key_hashes = MakeHashValueVector(0);
  cert_verifier_->AddResultForCert(server_cert.get(), verify_result, OK);

  // Set up HPKP
  HashValueVector expected_hashes = MakeHashValueVector(1);
  context_.transport_security_state->AddHPKP(
      spawned_test_server()->host_port_pair().host(),
      base::Time::Now() + base::TimeDelta::FromSeconds(10000), true,
      expected_hashes, GURL());

  SSLConfig ssl_config;
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  SSLInfo ssl_info;
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));

  EXPECT_THAT(rv, IsOk());
  EXPECT_TRUE(sock_->IsConnected());

  EXPECT_TRUE(ssl_info.pkp_bypassed);
  EXPECT_FALSE(ssl_info.cert_status & CERT_STATUS_PINNED_KEY_MISSING);
}

TEST_F(SSLClientSocketTest, PKPEnforced) {
  SpawnedTestServer::SSLOptions ssl_options;
  ASSERT_TRUE(StartTestServer(ssl_options));
  scoped_refptr<X509Certificate> server_cert =
      spawned_test_server()->GetCertificate();

  // Certificate is trusted, but chains to a public root that doesn't match the
  // pin hashes.
  CertVerifyResult verify_result;
  verify_result.is_issued_by_known_root = true;
  verify_result.verified_cert = server_cert;
  verify_result.public_key_hashes = MakeHashValueVector(0);
  cert_verifier_->AddResultForCert(server_cert.get(), verify_result, OK);

  // Set up HPKP
  HashValueVector expected_hashes = MakeHashValueVector(1);
  context_.transport_security_state->AddHPKP(
      spawned_test_server()->host_port_pair().host(),
      base::Time::Now() + base::TimeDelta::FromSeconds(10000), true,
      expected_hashes, GURL());

  SSLConfig ssl_config;
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  SSLInfo ssl_info;
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));

  EXPECT_THAT(rv, IsError(ERR_SSL_PINNED_KEY_NOT_IN_CERT_CHAIN));
  EXPECT_TRUE(ssl_info.cert_status & CERT_STATUS_PINNED_KEY_MISSING);
  EXPECT_TRUE(sock_->IsConnected());

  EXPECT_FALSE(ssl_info.pkp_bypassed);
}

// Test that when CT is required (in this case, by the delegate), the
// absence of CT information is a socket error.
TEST_F(SSLClientSocketTest, CTIsRequired) {
  SpawnedTestServer::SSLOptions ssl_options;
  ASSERT_TRUE(StartTestServer(ssl_options));
  scoped_refptr<X509Certificate> server_cert =
      spawned_test_server()->GetCertificate();

  // Certificate is trusted and chains to a public root.
  CertVerifyResult verify_result;
  verify_result.is_issued_by_known_root = true;
  verify_result.verified_cert = server_cert;
  verify_result.public_key_hashes = MakeHashValueVector(0);
  cert_verifier_->AddResultForCert(server_cert.get(), verify_result, OK);

  // Set up CT
  MockRequireCTDelegate require_ct_delegate;
  transport_security_state_->SetRequireCTDelegate(&require_ct_delegate);
  EXPECT_CALL(require_ct_delegate, IsCTRequiredForHost(_))
      .WillRepeatedly(Return(TransportSecurityState::RequireCTDelegate::
                                 CTRequirementLevel::NOT_REQUIRED));
  EXPECT_CALL(
      require_ct_delegate,
      IsCTRequiredForHost(spawned_test_server()->host_port_pair().host()))
      .WillRepeatedly(Return(TransportSecurityState::RequireCTDelegate::
                                 CTRequirementLevel::REQUIRED));
  EXPECT_CALL(*ct_policy_enforcer_,
              DoesConformToCertPolicy(server_cert.get(), _, _))
      .WillRepeatedly(
          Return(ct::CertPolicyCompliance::CERT_POLICY_NOT_ENOUGH_SCTS));

  SSLConfig ssl_config;
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  SSLInfo ssl_info;
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));

  EXPECT_THAT(rv, IsError(ERR_CERTIFICATE_TRANSPARENCY_REQUIRED));
  EXPECT_TRUE(ssl_info.cert_status &
              CERT_STATUS_CERTIFICATE_TRANSPARENCY_REQUIRED);
  EXPECT_TRUE(sock_->IsConnected());
}

// When both HPKP and CT are required for a host, and both fail, the more
// serious error is that the HPKP pin validation failed.
TEST_F(SSLClientSocketTest, PKPMoreImportantThanCT) {
  SpawnedTestServer::SSLOptions ssl_options;
  ASSERT_TRUE(StartTestServer(ssl_options));
  scoped_refptr<X509Certificate> server_cert =
      spawned_test_server()->GetCertificate();

  // Certificate is trusted, but chains to a public root that doesn't match the
  // pin hashes.
  CertVerifyResult verify_result;
  verify_result.is_issued_by_known_root = true;
  verify_result.verified_cert = server_cert;
  verify_result.public_key_hashes = MakeHashValueVector(0);
  cert_verifier_->AddResultForCert(server_cert.get(), verify_result, OK);

  // Set up HPKP.
  HashValueVector expected_hashes = MakeHashValueVector(1);
  context_.transport_security_state->AddHPKP(
      spawned_test_server()->host_port_pair().host(),
      base::Time::Now() + base::TimeDelta::FromSeconds(10000), true,
      expected_hashes, GURL());

  // Set up CT.
  MockRequireCTDelegate require_ct_delegate;
  transport_security_state_->SetRequireCTDelegate(&require_ct_delegate);
  EXPECT_CALL(require_ct_delegate, IsCTRequiredForHost(_))
      .WillRepeatedly(Return(TransportSecurityState::RequireCTDelegate::
                                 CTRequirementLevel::NOT_REQUIRED));
  EXPECT_CALL(
      require_ct_delegate,
      IsCTRequiredForHost(spawned_test_server()->host_port_pair().host()))
      .WillRepeatedly(Return(TransportSecurityState::RequireCTDelegate::
                                 CTRequirementLevel::REQUIRED));
  EXPECT_CALL(*ct_policy_enforcer_,
              DoesConformToCertPolicy(server_cert.get(), _, _))
      .WillRepeatedly(
          Return(ct::CertPolicyCompliance::CERT_POLICY_NOT_ENOUGH_SCTS));

  SSLConfig ssl_config;
  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(ssl_config, &rv));
  SSLInfo ssl_info;
  ASSERT_TRUE(sock_->GetSSLInfo(&ssl_info));

  EXPECT_THAT(rv, IsError(ERR_SSL_PINNED_KEY_NOT_IN_CERT_CHAIN));
  EXPECT_TRUE(ssl_info.cert_status & CERT_STATUS_PINNED_KEY_MISSING);
  EXPECT_TRUE(ssl_info.cert_status &
              CERT_STATUS_CERTIFICATE_TRANSPARENCY_REQUIRED);
  EXPECT_TRUE(sock_->IsConnected());
}

// Test that handshake_failure alerts at the ServerHello are mapped to
// ERR_SSL_VERSION_OR_CIPHER_MISMATCH.
TEST_F(SSLClientSocketTest, HandshakeFailureServerHello) {
  ASSERT_TRUE(StartTestServer(SpawnedTestServer::SSLOptions()));

  TestCompletionCallback callback;
  std::unique_ptr<StreamSocket> real_transport(
      new TCPClientSocket(addr(), NULL, NULL, NetLogSource()));
  std::unique_ptr<FakeBlockingStreamSocket> transport(
      new FakeBlockingStreamSocket(std::move(real_transport)));
  FakeBlockingStreamSocket* raw_transport = transport.get();
  int rv = callback.GetResult(transport->Connect(callback.callback()));
  ASSERT_THAT(rv, IsOk());

  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(transport), spawned_test_server()->host_port_pair(),
      SSLConfig()));

  // Connect. Stop before the client processes ServerHello.
  raw_transport->BlockReadResult();
  rv = sock->Connect(callback.callback());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  raw_transport->WaitForReadResult();

  // Replace it with an alert.
  raw_transport->ReplaceReadResult(
      FormatTLS12Alert(40 /* AlertDescription.handshake_failure */));
  raw_transport->UnblockReadResult();

  rv = callback.GetResult(rv);
  EXPECT_THAT(rv, IsError(ERR_SSL_VERSION_OR_CIPHER_MISMATCH));
}

// Test that handshake_failure alerts after the ServerHello but without a
// CertificateRequest are mapped to ERR_SSL_PROTOCOL_ERROR.
TEST_F(SSLClientSocketTest, HandshakeFailureNoClientCerts) {
  ASSERT_TRUE(StartTestServer(SpawnedTestServer::SSLOptions()));

  TestCompletionCallback callback;
  std::unique_ptr<StreamSocket> real_transport(
      new TCPClientSocket(addr(), NULL, NULL, NetLogSource()));
  std::unique_ptr<FakeBlockingStreamSocket> transport(
      new FakeBlockingStreamSocket(std::move(real_transport)));
  FakeBlockingStreamSocket* raw_transport = transport.get();
  int rv = callback.GetResult(transport->Connect(callback.callback()));
  ASSERT_THAT(rv, IsOk());

  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(transport), spawned_test_server()->host_port_pair(),
      SSLConfig()));

  // Connect. Stop before the client processes ServerHello.
  raw_transport->BlockReadResult();
  rv = sock->Connect(callback.callback());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  raw_transport->WaitForReadResult();

  // Release the ServerHello and wait for the client to write its second flight.
  raw_transport->BlockWrite();
  raw_transport->UnblockReadResult();
  raw_transport->WaitForWrite();

  // Wait for the server's final flight.
  raw_transport->BlockReadResult();
  raw_transport->UnblockWrite();
  raw_transport->WaitForReadResult();

  // Replace it with an alert.
  raw_transport->ReplaceReadResult(
      FormatTLS12Alert(40 /* AlertDescription.handshake_failure */));
  raw_transport->UnblockReadResult();

  rv = callback.GetResult(rv);
  EXPECT_THAT(rv, IsError(ERR_SSL_PROTOCOL_ERROR));
}

// Test that handshake_failure alerts after the ServerHello map to
// ERR_BAD_SSL_CLIENT_AUTH_CERT if a client certificate was requested but not
// supplied. TLS does not have an alert for this case, so handshake_failure is
// common. See https://crbug.com/646567.
TEST_F(SSLClientSocketTest, LateHandshakeFailureMissingClientCerts) {
  // Request a client certificate.
  SpawnedTestServer::SSLOptions ssl_options;
  ssl_options.request_client_certificate = true;
  ASSERT_TRUE(StartTestServer(ssl_options));

  TestCompletionCallback callback;
  std::unique_ptr<StreamSocket> real_transport(
      new TCPClientSocket(addr(), NULL, NULL, NetLogSource()));
  std::unique_ptr<FakeBlockingStreamSocket> transport(
      new FakeBlockingStreamSocket(std::move(real_transport)));
  FakeBlockingStreamSocket* raw_transport = transport.get();
  int rv = callback.GetResult(transport->Connect(callback.callback()));
  ASSERT_THAT(rv, IsOk());

  // Send no client certificate.
  SSLConfig config;
  config.send_client_cert = true;
  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(transport), spawned_test_server()->host_port_pair(), config));

  // Connect. Stop before the client processes ServerHello.
  raw_transport->BlockReadResult();
  rv = sock->Connect(callback.callback());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  raw_transport->WaitForReadResult();

  // Release the ServerHello and wait for the client to write its second flight.
  raw_transport->BlockWrite();
  raw_transport->UnblockReadResult();
  raw_transport->WaitForWrite();

  // Wait for the server's final flight.
  raw_transport->BlockReadResult();
  raw_transport->UnblockWrite();
  raw_transport->WaitForReadResult();

  // Replace it with an alert.
  raw_transport->ReplaceReadResult(
      FormatTLS12Alert(40 /* AlertDescription.handshake_failure */));
  raw_transport->UnblockReadResult();

  rv = callback.GetResult(rv);
  EXPECT_THAT(rv, IsError(ERR_BAD_SSL_CLIENT_AUTH_CERT));
}

// Test that handshake_failure alerts after the ServerHello map to
// ERR_SSL_PROTOCOL_ERROR if received after sending a client certificate. It is
// assumed servers will send a more appropriate alert in this case.
TEST_F(SSLClientSocketTest, LateHandshakeFailureSendClientCerts) {
  // Request a client certificate.
  SpawnedTestServer::SSLOptions ssl_options;
  ssl_options.request_client_certificate = true;
  ASSERT_TRUE(StartTestServer(ssl_options));

  TestCompletionCallback callback;
  std::unique_ptr<StreamSocket> real_transport(
      new TCPClientSocket(addr(), NULL, NULL, NetLogSource()));
  std::unique_ptr<FakeBlockingStreamSocket> transport(
      new FakeBlockingStreamSocket(std::move(real_transport)));
  FakeBlockingStreamSocket* raw_transport = transport.get();
  int rv = callback.GetResult(transport->Connect(callback.callback()));
  ASSERT_THAT(rv, IsOk());

  // Send a client certificate.
  base::FilePath certs_dir = GetTestCertsDirectory();
  SSLConfig config;
  config.send_client_cert = true;
  config.client_cert = ImportCertFromFile(certs_dir, "client_1.pem");
  config.client_private_key =
      LoadPrivateKeyOpenSSL(certs_dir.AppendASCII("client_1.key"));
  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(transport), spawned_test_server()->host_port_pair(), config));

  // Connect. Stop before the client processes ServerHello.
  raw_transport->BlockReadResult();
  rv = sock->Connect(callback.callback());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  raw_transport->WaitForReadResult();

  // Release the ServerHello and wait for the client to write its second flight.
  raw_transport->BlockWrite();
  raw_transport->UnblockReadResult();
  raw_transport->WaitForWrite();

  // Wait for the server's final flight.
  raw_transport->BlockReadResult();
  raw_transport->UnblockWrite();
  raw_transport->WaitForReadResult();

  // Replace it with an alert.
  raw_transport->ReplaceReadResult(
      FormatTLS12Alert(40 /* AlertDescription.handshake_failure */));
  raw_transport->UnblockReadResult();

  rv = callback.GetResult(rv);
  EXPECT_THAT(rv, IsError(ERR_SSL_PROTOCOL_ERROR));
}

// Test that access_denied alerts are mapped to ERR_SSL_PROTOCOL_ERROR if
// received on a connection not requesting client certificates. This is an
// incorrect use of the alert but is common. See https://crbug.com/630883.
TEST_F(SSLClientSocketTest, AccessDeniedNoClientCerts) {
  ASSERT_TRUE(StartTestServer(SpawnedTestServer::SSLOptions()));

  TestCompletionCallback callback;
  std::unique_ptr<StreamSocket> real_transport(
      new TCPClientSocket(addr(), NULL, NULL, NetLogSource()));
  std::unique_ptr<FakeBlockingStreamSocket> transport(
      new FakeBlockingStreamSocket(std::move(real_transport)));
  FakeBlockingStreamSocket* raw_transport = transport.get();
  int rv = callback.GetResult(transport->Connect(callback.callback()));
  ASSERT_THAT(rv, IsOk());

  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(transport), spawned_test_server()->host_port_pair(),
      SSLConfig()));

  // Connect. Stop before the client processes ServerHello.
  raw_transport->BlockReadResult();
  rv = sock->Connect(callback.callback());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  raw_transport->WaitForReadResult();

  // Release the ServerHello and wait for the client to write its second flight.
  raw_transport->BlockWrite();
  raw_transport->UnblockReadResult();
  raw_transport->WaitForWrite();

  // Wait for the server's final flight.
  raw_transport->BlockReadResult();
  raw_transport->UnblockWrite();
  raw_transport->WaitForReadResult();

  // Replace it with an alert.
  raw_transport->ReplaceReadResult(
      FormatTLS12Alert(49 /* AlertDescription.access_denied */));
  raw_transport->UnblockReadResult();

  rv = callback.GetResult(rv);
  EXPECT_THAT(rv, IsError(ERR_SSL_PROTOCOL_ERROR));
}

// Test that access_denied alerts are mapped to ERR_BAD_SSL_CLIENT_AUTH_CERT if
// received on a connection requesting client certificates.
TEST_F(SSLClientSocketTest, AccessDeniedClientCerts) {
  // Request a client certificate.
  SpawnedTestServer::SSLOptions ssl_options;
  ssl_options.request_client_certificate = true;
  ASSERT_TRUE(StartTestServer(ssl_options));

  TestCompletionCallback callback;
  std::unique_ptr<StreamSocket> real_transport(
      new TCPClientSocket(addr(), NULL, NULL, NetLogSource()));
  std::unique_ptr<FakeBlockingStreamSocket> transport(
      new FakeBlockingStreamSocket(std::move(real_transport)));
  FakeBlockingStreamSocket* raw_transport = transport.get();
  int rv = callback.GetResult(transport->Connect(callback.callback()));
  ASSERT_THAT(rv, IsOk());

  // Send a client certificate.
  base::FilePath certs_dir = GetTestCertsDirectory();
  SSLConfig config;
  config.send_client_cert = true;
  config.client_cert = ImportCertFromFile(certs_dir, "client_1.pem");
  config.client_private_key =
      LoadPrivateKeyOpenSSL(certs_dir.AppendASCII("client_1.key"));
  std::unique_ptr<SSLClientSocket> sock(CreateSSLClientSocket(
      std::move(transport), spawned_test_server()->host_port_pair(), config));

  // Connect. Stop before the client processes ServerHello.
  raw_transport->BlockReadResult();
  rv = sock->Connect(callback.callback());
  ASSERT_THAT(rv, IsError(ERR_IO_PENDING));
  raw_transport->WaitForReadResult();

  // Release the ServerHello and wait for the client to write its second flight.
  raw_transport->BlockWrite();
  raw_transport->UnblockReadResult();
  raw_transport->WaitForWrite();

  // Wait for the server's final flight.
  raw_transport->BlockReadResult();
  raw_transport->UnblockWrite();
  raw_transport->WaitForReadResult();

  // Replace it with an alert.
  raw_transport->ReplaceReadResult(
      FormatTLS12Alert(49 /* AlertDescription.access_denied */));
  raw_transport->UnblockReadResult();

  rv = callback.GetResult(rv);
  EXPECT_THAT(rv, IsError(ERR_BAD_SSL_CLIENT_AUTH_CERT));
}

// Basic test for dumping memory stats.
TEST_F(SSLClientSocketTest, DumpMemoryStats) {
  ASSERT_TRUE(StartTestServer(SpawnedTestServer::SSLOptions()));

  int rv;
  ASSERT_TRUE(CreateAndConnectSSLClientSocket(SSLConfig(), &rv));
  EXPECT_THAT(rv, IsOk());
  StreamSocket::SocketMemoryStats stats;
  sock_->DumpMemoryStats(&stats);
  EXPECT_EQ(0u, stats.buffer_size);
  EXPECT_EQ(1u, stats.cert_count);
  EXPECT_LT(0u, stats.cert_size);
  EXPECT_EQ(stats.cert_size, stats.total_size);

  // Read the response without writing a request, so the read will be pending.
  TestCompletionCallback read_callback;
  scoped_refptr<IOBuffer> buf(new IOBuffer(4096));
  rv = sock_->Read(buf.get(), 4096, read_callback.callback());
  EXPECT_EQ(ERR_IO_PENDING, rv);

  // Dump memory again and check that |buffer_size| contain the read buffer.
  StreamSocket::SocketMemoryStats stats2;
  sock_->DumpMemoryStats(&stats2);
  EXPECT_EQ(17 * 1024u, stats2.buffer_size);
  EXPECT_EQ(1u, stats2.cert_count);
  EXPECT_LT(0u, stats2.cert_size);
  EXPECT_LT(17 * 1024u, stats2.total_size);
}

}  // namespace net
