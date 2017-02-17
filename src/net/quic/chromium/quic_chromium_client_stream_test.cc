// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/chromium/quic_chromium_client_stream.h"

#include <string>

#include "base/memory/ptr_util.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "net/base/io_buffer.h"
#include "net/base/net_errors.h"
#include "net/base/test_completion_callback.h"
#include "net/quic/chromium/quic_chromium_client_session.h"
#include "net/quic/core/quic_client_session_base.h"
#include "net/quic/core/quic_utils.h"
#include "net/quic/core/spdy_utils.h"
#include "net/quic/test_tools/crypto_test_utils.h"
#include "net/quic/test_tools/quic_test_utils.h"
#include "net/test/gtest_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gmock_mutant.h"

using testing::AnyNumber;
using testing::CreateFunctor;
using testing::Invoke;
using testing::Return;
using testing::StrEq;
using testing::_;

namespace net {
namespace test {
namespace {

const QuicStreamId kTestStreamId = 5u;

class MockDelegate : public QuicChromiumClientStream::Delegate {
 public:
  MockDelegate() {}

  MOCK_METHOD0(OnSendData, int());
  MOCK_METHOD2(OnSendDataComplete, int(int, bool*));
  void OnHeadersAvailable(const SpdyHeaderBlock& headers,
                          size_t frame_len) override {
    headers_ = headers.Clone();
    OnHeadersAvailableMock(headers, frame_len);
  }
  MOCK_METHOD2(OnHeadersAvailableMock,
               void(const SpdyHeaderBlock& headers, size_t frame_len));
  MOCK_METHOD2(OnDataReceived, int(const char*, int));
  MOCK_METHOD0(OnDataAvailable, void());
  MOCK_METHOD0(OnClose, void());
  MOCK_METHOD1(OnError, void(int));
  MOCK_METHOD0(HasSendHeadersComplete, bool());

  SpdyHeaderBlock headers_;

 private:
  DISALLOW_COPY_AND_ASSIGN(MockDelegate);
};

class MockQuicClientSessionBase : public QuicClientSessionBase {
 public:
  explicit MockQuicClientSessionBase(QuicConnection* connection,
                                     QuicClientPushPromiseIndex* index);
  ~MockQuicClientSessionBase() override;

  QuicCryptoStream* GetCryptoStream() override { return crypto_stream_.get(); }

  // From QuicSession.
  MOCK_METHOD3(OnConnectionClosed,
               void(QuicErrorCode error,
                    const std::string& error_details,
                    ConnectionCloseSource source));
  MOCK_METHOD1(CreateIncomingDynamicStream, QuicSpdyStream*(QuicStreamId id));
  MOCK_METHOD1(CreateOutgoingDynamicStream,
               QuicChromiumClientStream*(SpdyPriority priority));
  MOCK_METHOD6(
      WritevData,
      QuicConsumedData(QuicStream* stream,
                       QuicStreamId id,
                       QuicIOVector data,
                       QuicStreamOffset offset,
                       bool fin,
                       QuicReferenceCountedPointer<QuicAckListenerInterface>));
  MOCK_METHOD3(SendRstStream,
               void(QuicStreamId stream_id,
                    QuicRstStreamErrorCode error,
                    QuicStreamOffset bytes_written));

  MOCK_METHOD2(OnStreamHeaders,
               void(QuicStreamId stream_id, base::StringPiece headers_data));
  MOCK_METHOD2(OnStreamHeadersPriority,
               void(QuicStreamId stream_id, SpdyPriority priority));
  MOCK_METHOD3(OnStreamHeadersComplete,
               void(QuicStreamId stream_id, bool fin, size_t frame_len));
  MOCK_METHOD2(OnPromiseHeaders,
               void(QuicStreamId stream_id, StringPiece headers_data));
  MOCK_METHOD3(OnPromiseHeadersComplete,
               void(QuicStreamId stream_id,
                    QuicStreamId promised_stream_id,
                    size_t frame_len));
  MOCK_METHOD0(IsCryptoHandshakeConfirmed, bool());
  // Methods taking non-copyable types like SpdyHeaderBlock by value cannot be
  // mocked directly.
  size_t WriteHeaders(QuicStreamId id,
                      SpdyHeaderBlock headers,
                      bool fin,
                      SpdyPriority priority,
                      QuicReferenceCountedPointer<QuicAckListenerInterface>
                          ack_listener) override {
    return WriteHeadersMock(id, headers, fin, priority,
                            std::move(ack_listener));
  }
  MOCK_METHOD5(
      WriteHeadersMock,
      size_t(QuicStreamId id,
             const SpdyHeaderBlock& headers,
             bool fin,
             SpdyPriority priority,
             const QuicReferenceCountedPointer<QuicAckListenerInterface>&
                 ack_listener));
  MOCK_METHOD1(OnHeadersHeadOfLineBlocking, void(QuicTime::Delta delta));

  using QuicSession::ActivateStream;

  // Returns a QuicConsumedData that indicates all of |data| (and |fin| if set)
  // has been consumed.
  static QuicConsumedData ConsumeAllData(
      QuicStreamId id,
      const QuicIOVector& data,
      QuicStreamOffset offset,
      bool fin,
      QuicAckListenerInterface* ack_listener);

  void OnProofValid(
      const QuicCryptoClientConfig::CachedState& cached) override {}
  void OnProofVerifyDetailsAvailable(
      const ProofVerifyDetails& verify_details) override {}
  bool IsAuthorized(const std::string& hostname) override { return true; }

 protected:
  MOCK_METHOD1(ShouldCreateIncomingDynamicStream, bool(QuicStreamId id));
  MOCK_METHOD0(ShouldCreateOutgoingDynamicStream, bool());

 private:
  std::unique_ptr<QuicCryptoStream> crypto_stream_;

  DISALLOW_COPY_AND_ASSIGN(MockQuicClientSessionBase);
};

MockQuicClientSessionBase::MockQuicClientSessionBase(
    QuicConnection* connection,
    QuicClientPushPromiseIndex* push_promise_index)
    : QuicClientSessionBase(connection,
                            push_promise_index,
                            DefaultQuicConfig()) {
  crypto_stream_.reset(new QuicCryptoStream(this));
  Initialize();
  ON_CALL(*this, WritevData(_, _, _, _, _, _))
      .WillByDefault(testing::Return(QuicConsumedData(0, false)));
}

MockQuicClientSessionBase::~MockQuicClientSessionBase() {}

class QuicChromiumClientStreamTest
    : public ::testing::TestWithParam<QuicVersion> {
 public:
  QuicChromiumClientStreamTest()
      : crypto_config_(crypto_test_utils::ProofVerifierForTesting()),
        session_(new MockQuicConnection(&helper_,
                                        &alarm_factory_,
                                        Perspective::IS_CLIENT,
                                        SupportedVersions(GetParam())),
                 &push_promise_index_) {
    stream_ = new QuicChromiumClientStream(kTestStreamId, &session_,
                                           NetLogWithSource());
    session_.ActivateStream(base::WrapUnique(stream_));
    stream_->SetDelegate(&delegate_);
  }

  void InitializeHeaders() {
    headers_[":host"] = "www.google.com";
    headers_[":path"] = "/index.hml";
    headers_[":scheme"] = "https";
    headers_["cookie"] =
        "__utma=208381060.1228362404.1372200928.1372200928.1372200928.1; "
        "__utmc=160408618; "
        "GX=DQAAAOEAAACWJYdewdE9rIrW6qw3PtVi2-d729qaa-74KqOsM1NVQblK4VhX"
        "hoALMsy6HOdDad2Sz0flUByv7etmo3mLMidGrBoljqO9hSVA40SLqpG_iuKKSHX"
        "RW3Np4bq0F0SDGDNsW0DSmTS9ufMRrlpARJDS7qAI6M3bghqJp4eABKZiRqebHT"
        "pMU-RXvTI5D5oCF1vYxYofH_l1Kviuiy3oQ1kS1enqWgbhJ2t61_SNdv-1XJIS0"
        "O3YeHLmVCs62O6zp89QwakfAWK9d3IDQvVSJzCQsvxvNIvaZFa567MawWlXg0Rh"
        "1zFMi5vzcns38-8_Sns; "
        "GA=v*2%2Fmem*57968640*47239936%2Fmem*57968640*47114716%2Fno-nm-"
        "yj*15%2Fno-cc-yj*5%2Fpc-ch*133685%2Fpc-s-cr*133947%2Fpc-s-t*1339"
        "47%2Fno-nm-yj*4%2Fno-cc-yj*1%2Fceft-as*1%2Fceft-nqas*0%2Fad-ra-c"
        "v_p%2Fad-nr-cv_p-f*1%2Fad-v-cv_p*859%2Fad-ns-cv_p-f*1%2Ffn-v-ad%"
        "2Fpc-t*250%2Fpc-cm*461%2Fpc-s-cr*722%2Fpc-s-t*722%2Fau_p*4"
        "SICAID=AJKiYcHdKgxum7KMXG0ei2t1-W4OD1uW-ecNsCqC0wDuAXiDGIcT_HA2o1"
        "3Rs1UKCuBAF9g8rWNOFbxt8PSNSHFuIhOo2t6bJAVpCsMU5Laa6lewuTMYI8MzdQP"
        "ARHKyW-koxuhMZHUnGBJAM1gJODe0cATO_KGoX4pbbFxxJ5IicRxOrWK_5rU3cdy6"
        "edlR9FsEdH6iujMcHkbE5l18ehJDwTWmBKBzVD87naobhMMrF6VvnDGxQVGp9Ir_b"
        "Rgj3RWUoPumQVCxtSOBdX0GlJOEcDTNCzQIm9BSfetog_eP_TfYubKudt5eMsXmN6"
        "QnyXHeGeK2UINUzJ-D30AFcpqYgH9_1BvYSpi7fc7_ydBU8TaD8ZRxvtnzXqj0RfG"
        "tuHghmv3aD-uzSYJ75XDdzKdizZ86IG6Fbn1XFhYZM-fbHhm3mVEXnyRW4ZuNOLFk"
        "Fas6LMcVC6Q8QLlHYbXBpdNFuGbuZGUnav5C-2I_-46lL0NGg3GewxGKGHvHEfoyn"
        "EFFlEYHsBQ98rXImL8ySDycdLEFvBPdtctPmWCfTxwmoSMLHU2SCVDhbqMWU5b0yr"
        "JBCScs_ejbKaqBDoB7ZGxTvqlrB__2ZmnHHjCr8RgMRtKNtIeuZAo ";
  }

  void ReadData(StringPiece expected_data) {
    scoped_refptr<IOBuffer> buffer(new IOBuffer(expected_data.length() + 1));
    EXPECT_EQ(static_cast<int>(expected_data.length()),
              stream_->Read(buffer.get(), expected_data.length() + 1));
    EXPECT_EQ(expected_data,
              StringPiece(buffer->data(), expected_data.length()));
  }

  QuicHeaderList ProcessHeaders(const SpdyHeaderBlock& headers) {
    QuicHeaderList h = AsHeaderList(headers);
    stream_->OnStreamHeaderList(false, h.uncompressed_header_bytes(), h);
    return h;
  }

  QuicHeaderList ProcessTrailers(const SpdyHeaderBlock& headers) {
    QuicHeaderList h = AsHeaderList(headers);
    stream_->OnStreamHeaderList(true, h.uncompressed_header_bytes(), h);
    return h;
  }

  QuicHeaderList ProcessHeadersFull(const SpdyHeaderBlock& headers) {
    QuicHeaderList h = ProcessHeaders(headers);
    EXPECT_CALL(delegate_,
                OnHeadersAvailableMock(_, h.uncompressed_header_bytes()));
    base::RunLoop().RunUntilIdle();
    EXPECT_EQ(headers, delegate_.headers_);
    EXPECT_TRUE(stream_->header_list().empty());
    return h;
  }

  QuicCryptoClientConfig crypto_config_;
  testing::StrictMock<MockDelegate> delegate_;
  MockQuicConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
  MockQuicClientSessionBase session_;
  QuicChromiumClientStream* stream_;
  SpdyHeaderBlock headers_;
  QuicClientPushPromiseIndex push_promise_index_;
};

INSTANTIATE_TEST_CASE_P(Version,
                        QuicChromiumClientStreamTest,
                        ::testing::ValuesIn(AllSupportedVersions()));

TEST_P(QuicChromiumClientStreamTest, OnFinRead) {
  InitializeHeaders();
  QuicStreamOffset offset = 0;
  ProcessHeadersFull(headers_);
  QuicStreamFrame frame2(kTestStreamId, true, offset, StringPiece());
  EXPECT_CALL(delegate_, OnClose());
  stream_->OnStreamFrame(frame2);
}

TEST_P(QuicChromiumClientStreamTest, OnDataAvailableBeforeHeaders) {
  EXPECT_CALL(delegate_, OnClose());

  EXPECT_CALL(delegate_, OnDataAvailable()).Times(0);
  stream_->OnDataAvailable();
}

TEST_P(QuicChromiumClientStreamTest, OnDataAvailable) {
  InitializeHeaders();
  ProcessHeadersFull(headers_);

  const char data[] = "hello world!";
  stream_->OnStreamFrame(QuicStreamFrame(kTestStreamId, /*fin=*/false,
                                         /*offset=*/0, data));

  EXPECT_CALL(delegate_, OnDataAvailable())
      .WillOnce(testing::Invoke(
          CreateFunctor(&QuicChromiumClientStreamTest::ReadData,
                        base::Unretained(this),
                        StringPiece(data, arraysize(data) - 1))));
  base::RunLoop().RunUntilIdle();

  EXPECT_CALL(delegate_, OnClose());
}

TEST_P(QuicChromiumClientStreamTest, ProcessHeadersWithError) {
  SpdyHeaderBlock bad_headers;
  bad_headers["NAME"] = "...";
  EXPECT_CALL(session_,
              SendRstStream(kTestStreamId, QUIC_BAD_APPLICATION_PAYLOAD, 0));

  auto headers = AsHeaderList(bad_headers);
  stream_->OnStreamHeaderList(false, headers.uncompressed_header_bytes(),
                              headers);

  base::RunLoop().RunUntilIdle();

  EXPECT_CALL(delegate_, OnClose());
}

TEST_P(QuicChromiumClientStreamTest, OnDataAvailableWithError) {
  InitializeHeaders();
  auto headers = AsHeaderList(headers_);
  ProcessHeadersFull(headers_);

  const char data[] = "hello world!";
  stream_->OnStreamFrame(QuicStreamFrame(kTestStreamId, /*fin=*/false,
                                         /*offset=*/0, data));
  EXPECT_CALL(delegate_, OnDataAvailable())
      .WillOnce(testing::Invoke(CreateFunctor(
          &QuicChromiumClientStream::Reset,
          base::Unretained(stream_), QUIC_STREAM_CANCELLED)));
  base::RunLoop().RunUntilIdle();

  EXPECT_CALL(delegate_, OnClose());
}

TEST_P(QuicChromiumClientStreamTest, OnError) {
  EXPECT_CALL(delegate_, OnError(ERR_INTERNET_DISCONNECTED));

  stream_->OnError(ERR_INTERNET_DISCONNECTED);
  EXPECT_FALSE(stream_->GetDelegate());
}

TEST_P(QuicChromiumClientStreamTest, OnTrailers) {
  InitializeHeaders();
  ProcessHeadersFull(headers_);

  const char data[] = "hello world!";
  stream_->OnStreamFrame(QuicStreamFrame(kTestStreamId, /*fin=*/false,
                                         /*offset=*/0, data));

  EXPECT_CALL(delegate_, OnDataAvailable())
      .WillOnce(testing::Invoke(CreateFunctor(
          &QuicChromiumClientStreamTest::ReadData, base::Unretained(this),
          StringPiece(data, arraysize(data) - 1))));

  SpdyHeaderBlock trailers;
  trailers["bar"] = "foo";
  trailers[kFinalOffsetHeaderKey] = base::IntToString(strlen(data));

  auto t = ProcessTrailers(trailers);
  base::RunLoop run_loop;
  EXPECT_CALL(delegate_,
              OnHeadersAvailableMock(_, t.uncompressed_header_bytes()))
      .WillOnce(testing::InvokeWithoutArgs([&run_loop]() { run_loop.Quit(); }));

  run_loop.Run();

  // OnDataAvailable callback should follow trailers notification.
  base::RunLoop run_loop3;
  EXPECT_CALL(delegate_, OnDataAvailable())
      .Times(1)
      .WillOnce(testing::DoAll(
          testing::Invoke(CreateFunctor(&QuicChromiumClientStreamTest::ReadData,
                                        base::Unretained(this), StringPiece())),
          testing::InvokeWithoutArgs([&run_loop3]() { run_loop3.Quit(); })));
  run_loop3.Run();

  // Make sure kFinalOffsetHeaderKey is gone from the delivered actual trailers.
  trailers.erase(kFinalOffsetHeaderKey);
  EXPECT_EQ(trailers, delegate_.headers_);
  base::RunLoop().RunUntilIdle();
  EXPECT_CALL(delegate_, OnClose());
}

// Tests that trailers are marked as consumed only before delegate is to be
// immediately notified about trailers.
TEST_P(QuicChromiumClientStreamTest, MarkTrailersConsumedWhenNotifyDelegate) {
  InitializeHeaders();
  ProcessHeadersFull(headers_);

  const char data[] = "hello world!";
  stream_->OnStreamFrame(QuicStreamFrame(kTestStreamId, /*fin=*/false,
                                         /*offset=*/0, data));

  base::RunLoop run_loop;
  EXPECT_CALL(delegate_, OnDataAvailable())
      .Times(1)
      .WillOnce(testing::DoAll(
          testing::Invoke(CreateFunctor(
              &QuicChromiumClientStreamTest::ReadData, base::Unretained(this),
              StringPiece(data, arraysize(data) - 1))),
          testing::Invoke([&run_loop]() { run_loop.Quit(); })));

  // Wait for the read to complete.
  run_loop.Run();

  // Read again, and it will be pending.
  scoped_refptr<IOBuffer> buffer(new IOBuffer(1));
  EXPECT_THAT(stream_->Read(buffer.get(), 1), IsError(ERR_IO_PENDING));

  SpdyHeaderBlock trailers;
  trailers["bar"] = "foo";
  trailers[kFinalOffsetHeaderKey] = base::IntToString(strlen(data));
  QuicHeaderList t = ProcessTrailers(trailers);
  EXPECT_FALSE(stream_->IsDoneReading());

  base::RunLoop run_loop2;
  EXPECT_CALL(delegate_,
              OnHeadersAvailableMock(_, t.uncompressed_header_bytes()))
      .WillOnce(
          testing::InvokeWithoutArgs([&run_loop2]() { run_loop2.Quit(); }));

  run_loop2.Run();

  // OnDataAvailable callback should follow trailers notification.
  base::RunLoop run_loop3;
  EXPECT_CALL(delegate_, OnDataAvailable())
      .Times(1)
      .WillOnce(testing::DoAll(
          testing::Invoke(CreateFunctor(&QuicChromiumClientStreamTest::ReadData,
                                        base::Unretained(this), StringPiece())),
          testing::InvokeWithoutArgs([&run_loop3]() { run_loop3.Quit(); })));
  run_loop3.Run();

  // Make sure the stream is properly closed since trailers and data are all
  // consumed.
  EXPECT_TRUE(stream_->IsDoneReading());
  // Make sure kFinalOffsetHeaderKey is gone from the delivered actual trailers.
  trailers.erase(kFinalOffsetHeaderKey);
  EXPECT_EQ(trailers, delegate_.headers_);

  base::RunLoop().RunUntilIdle();
  EXPECT_CALL(delegate_, OnClose());
}

// Test that if Read() is called after response body is read and after trailers
// are received but not yet delivered, Read() will return ERR_IO_PENDING instead
// of 0 (EOF).
TEST_P(QuicChromiumClientStreamTest, ReadAfterTrailersReceivedButNotDelivered) {
  InitializeHeaders();
  ProcessHeadersFull(headers_);

  const char data[] = "hello world!";
  stream_->OnStreamFrame(QuicStreamFrame(kTestStreamId, /*fin=*/false,
                                         /*offset=*/0, data));

  base::RunLoop run_loop;
  EXPECT_CALL(delegate_, OnDataAvailable())
      .Times(1)
      .WillOnce(testing::DoAll(
          testing::Invoke(CreateFunctor(
              &QuicChromiumClientStreamTest::ReadData, base::Unretained(this),
              StringPiece(data, arraysize(data) - 1))),
          testing::Invoke([&run_loop]() { run_loop.Quit(); })));

  // Wait for the read to complete.
  run_loop.Run();

  // Deliver trailers. Delegate notification is posted asynchronously.
  SpdyHeaderBlock trailers;
  trailers["bar"] = "foo";
  trailers[kFinalOffsetHeaderKey] = base::IntToString(strlen(data));

  QuicHeaderList t = ProcessTrailers(trailers);

  // Read again, it return ERR_IO_PENDING.
  scoped_refptr<IOBuffer> buffer(new IOBuffer(1));
  EXPECT_THAT(stream_->Read(buffer.get(), 1), ERR_IO_PENDING);

  // Trailers are not delivered
  EXPECT_FALSE(stream_->IsDoneReading());

  base::RunLoop run_loop2;
  EXPECT_CALL(delegate_,
              OnHeadersAvailableMock(_, t.uncompressed_header_bytes()))
      .WillOnce(
          testing::InvokeWithoutArgs([&run_loop2]() { run_loop2.Quit(); }));

  run_loop2.Run();

  base::RunLoop run_loop3;
  // OnDataAvailable() should follow right after and Read() will return 0.
  EXPECT_CALL(delegate_, OnDataAvailable())
      .WillOnce(testing::DoAll(
          testing::Invoke(CreateFunctor(&QuicChromiumClientStreamTest::ReadData,
                                        base::Unretained(this), StringPiece())),
          testing::Invoke([&run_loop3]() { run_loop3.Quit(); })));
  run_loop3.Run();

  // Make sure the stream is properly closed since trailers and data are all
  // consumed.
  EXPECT_TRUE(stream_->IsDoneReading());

  // Make sure kFinalOffsetHeaderKey is gone from the delivered actual trailers.
  trailers.erase(kFinalOffsetHeaderKey);
  EXPECT_EQ(trailers, delegate_.headers_);

  base::RunLoop().RunUntilIdle();
  EXPECT_CALL(delegate_, OnClose());
}

TEST_P(QuicChromiumClientStreamTest, WriteStreamData) {
  EXPECT_CALL(delegate_, OnClose());

  const char kData1[] = "hello world";
  const size_t kDataLen = arraysize(kData1);

  // All data written.
  EXPECT_CALL(session_, WritevData(stream_, stream_->id(), _, _, _, _))
      .WillOnce(Return(QuicConsumedData(kDataLen, true)));
  TestCompletionCallback callback;
  EXPECT_EQ(OK, stream_->WriteStreamData(base::StringPiece(kData1, kDataLen),
                                         true, callback.callback()));
}

TEST_P(QuicChromiumClientStreamTest, WriteStreamDataAsync) {
  EXPECT_CALL(delegate_, HasSendHeadersComplete()).Times(AnyNumber());
  EXPECT_CALL(delegate_, OnClose());

  const char kData1[] = "hello world";
  const size_t kDataLen = arraysize(kData1);

  // No data written.
  EXPECT_CALL(session_, WritevData(stream_, stream_->id(), _, _, _, _))
      .WillOnce(Return(QuicConsumedData(0, false)));
  TestCompletionCallback callback;
  EXPECT_EQ(ERR_IO_PENDING,
            stream_->WriteStreamData(base::StringPiece(kData1, kDataLen), true,
                                     callback.callback()));
  ASSERT_FALSE(callback.have_result());

  // All data written.
  EXPECT_CALL(session_, WritevData(stream_, stream_->id(), _, _, _, _))
      .WillOnce(Return(QuicConsumedData(kDataLen, true)));
  stream_->OnCanWrite();
  ASSERT_TRUE(callback.have_result());
  EXPECT_THAT(callback.WaitForResult(), IsOk());
}

TEST_P(QuicChromiumClientStreamTest, WritevStreamData) {
  EXPECT_CALL(delegate_, OnClose());

  scoped_refptr<StringIOBuffer> buf1(new StringIOBuffer("hello world!"));
  scoped_refptr<StringIOBuffer> buf2(
      new StringIOBuffer("Just a small payload"));

  // All data written.
  EXPECT_CALL(session_, WritevData(stream_, stream_->id(), _, _, _, _))
      .WillOnce(Return(QuicConsumedData(buf1->size(), false)))
      .WillOnce(Return(QuicConsumedData(buf2->size(), true)));
  TestCompletionCallback callback;
  EXPECT_EQ(
      OK, stream_->WritevStreamData({buf1, buf2}, {buf1->size(), buf2->size()},
                                    true, callback.callback()));
}

TEST_P(QuicChromiumClientStreamTest, WritevStreamDataAsync) {
  EXPECT_CALL(delegate_, HasSendHeadersComplete()).Times(AnyNumber());
  EXPECT_CALL(delegate_, OnClose());

  scoped_refptr<StringIOBuffer> buf1(new StringIOBuffer("hello world!"));
  scoped_refptr<StringIOBuffer> buf2(
      new StringIOBuffer("Just a small payload"));

  // Only a part of the data is written.
  EXPECT_CALL(session_, WritevData(stream_, stream_->id(), _, _, _, _))
      // First piece of data is written.
      .WillOnce(Return(QuicConsumedData(buf1->size(), false)))
      // Second piece of data is queued.
      .WillOnce(Return(QuicConsumedData(0, false)));
  TestCompletionCallback callback;
  EXPECT_EQ(ERR_IO_PENDING,
            stream_->WritevStreamData({buf1.get(), buf2.get()},
                                      {buf1->size(), buf2->size()}, true,
                                      callback.callback()));
  ASSERT_FALSE(callback.have_result());

  // The second piece of data is written.
  EXPECT_CALL(session_, WritevData(stream_, stream_->id(), _, _, _, _))
      .WillOnce(Return(QuicConsumedData(buf2->size(), true)));
  stream_->OnCanWrite();
  ASSERT_TRUE(callback.have_result());
  EXPECT_THAT(callback.WaitForResult(), IsOk());
}

TEST_P(QuicChromiumClientStreamTest, HeadersBeforeDelegate) {
  // We don't use stream_ because we want an incoming server push
  // stream.
  QuicChromiumClientStream* stream = new QuicChromiumClientStream(
      kServerDataStreamId1, &session_, NetLogWithSource());
  session_.ActivateStream(base::WrapUnique(stream));

  InitializeHeaders();
  stream->SetDelegate(&delegate_);
  ProcessHeadersFull(headers_);

  // Times(2) because OnClose will be called for stream and stream_.
  EXPECT_CALL(delegate_, OnClose()).Times(2);
}

}  // namespace
}  // namespace test
}  // namespace net
