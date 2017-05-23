// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/spdy/chromium/spdy_write_queue.h"

#include <cstddef>
#include <cstring>
#include <memory>
#include <utility>

#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/memory/ref_counted.h"
#include "base/strings/string_number_conversions.h"
#include "net/base/request_priority.h"
#include "net/log/net_log_with_source.h"
#include "net/spdy/chromium/spdy_buffer_producer.h"
#include "net/spdy/chromium/spdy_stream.h"
#include "net/spdy/platform/api/spdy_string.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "url/gurl.h"

using base::MakeUnique;

namespace net {

namespace {

const char kOriginal[] = "original";
const char kRequeued[] = "requeued";

class SpdyWriteQueueTest : public ::testing::Test {};

// Makes a SpdyFrameProducer producing a frame with the data in the
// given string.
std::unique_ptr<SpdyBufferProducer> StringToProducer(const SpdyString& s) {
  auto data = MakeUnique<char[]>(s.size());
  std::memcpy(data.get(), s.data(), s.size());
  auto frame = MakeUnique<SpdySerializedFrame>(data.release(), s.size(), true);
  auto buffer = MakeUnique<SpdyBuffer>(std::move(frame));
  return MakeUnique<SimpleBufferProducer>(std::move(buffer));
}

// Makes a SpdyBufferProducer producing a frame with the data in the
// given int (converted to a string).
std::unique_ptr<SpdyBufferProducer> IntToProducer(int i) {
  return StringToProducer(base::IntToString(i));
}

// Producer whose produced buffer will enqueue yet another buffer into the
// SpdyWriteQueue upon destruction.
class RequeingBufferProducer : public SpdyBufferProducer {
 public:
  explicit RequeingBufferProducer(SpdyWriteQueue* queue) {
    buffer_ = MakeUnique<SpdyBuffer>(kOriginal, arraysize(kOriginal));
    buffer_->AddConsumeCallback(
        base::Bind(RequeingBufferProducer::ConsumeCallback, queue));
  }

  std::unique_ptr<SpdyBuffer> ProduceBuffer() override {
    return std::move(buffer_);
  }

  size_t EstimateMemoryUsage() const override {
    NOTREACHED();
    return 0;
  }

  static void ConsumeCallback(SpdyWriteQueue* queue,
                              size_t size,
                              SpdyBuffer::ConsumeSource source) {
    auto buffer = MakeUnique<SpdyBuffer>(kRequeued, arraysize(kRequeued));
    auto buffer_producer = MakeUnique<SimpleBufferProducer>(std::move(buffer));

    queue->Enqueue(MEDIUM, SpdyFrameType::RST_STREAM,
                   std::move(buffer_producer), base::WeakPtr<SpdyStream>());
  }

 private:
  std::unique_ptr<SpdyBuffer> buffer_;
};

// Produces a frame with the given producer and returns a copy of its
// data as a string.
SpdyString ProducerToString(std::unique_ptr<SpdyBufferProducer> producer) {
  std::unique_ptr<SpdyBuffer> buffer = producer->ProduceBuffer();
  return SpdyString(buffer->GetRemainingData(), buffer->GetRemainingSize());
}

// Produces a frame with the given producer and returns a copy of its
// data as an int (converted from a string).
int ProducerToInt(std::unique_ptr<SpdyBufferProducer> producer) {
  int i = 0;
  EXPECT_TRUE(base::StringToInt(ProducerToString(std::move(producer)), &i));
  return i;
}

// Makes a SpdyStream with the given priority and a NULL SpdySession
// -- be careful to not call any functions that expect the session to
// be there.
std::unique_ptr<SpdyStream> MakeTestStream(RequestPriority priority) {
  return MakeUnique<SpdyStream>(SPDY_BIDIRECTIONAL_STREAM,
                                base::WeakPtr<SpdySession>(), GURL(), priority,
                                0, 0, NetLogWithSource());
}

// Add some frame producers of different priority. The producers
// should be dequeued in priority order with their associated stream.
TEST_F(SpdyWriteQueueTest, DequeuesByPriority) {
  SpdyWriteQueue write_queue;

  std::unique_ptr<SpdyBufferProducer> producer_low = StringToProducer("LOW");
  std::unique_ptr<SpdyBufferProducer> producer_medium =
      StringToProducer("MEDIUM");
  std::unique_ptr<SpdyBufferProducer> producer_highest =
      StringToProducer("HIGHEST");

  std::unique_ptr<SpdyStream> stream_medium = MakeTestStream(MEDIUM);
  std::unique_ptr<SpdyStream> stream_highest = MakeTestStream(HIGHEST);

  // A NULL stream should still work.
  write_queue.Enqueue(LOW, SpdyFrameType::HEADERS, std::move(producer_low),
                      base::WeakPtr<SpdyStream>());
  write_queue.Enqueue(MEDIUM, SpdyFrameType::HEADERS,
                      std::move(producer_medium), stream_medium->GetWeakPtr());
  write_queue.Enqueue(HIGHEST, SpdyFrameType::RST_STREAM,
                      std::move(producer_highest),
                      stream_highest->GetWeakPtr());

  SpdyFrameType frame_type = SpdyFrameType::DATA;
  std::unique_ptr<SpdyBufferProducer> frame_producer;
  base::WeakPtr<SpdyStream> stream;
  ASSERT_TRUE(write_queue.Dequeue(&frame_type, &frame_producer, &stream));
  EXPECT_EQ(SpdyFrameType::RST_STREAM, frame_type);
  EXPECT_EQ("HIGHEST", ProducerToString(std::move(frame_producer)));
  EXPECT_EQ(stream_highest.get(), stream.get());

  ASSERT_TRUE(write_queue.Dequeue(&frame_type, &frame_producer, &stream));
  EXPECT_EQ(SpdyFrameType::HEADERS, frame_type);
  EXPECT_EQ("MEDIUM", ProducerToString(std::move(frame_producer)));
  EXPECT_EQ(stream_medium.get(), stream.get());

  ASSERT_TRUE(write_queue.Dequeue(&frame_type, &frame_producer, &stream));
  EXPECT_EQ(SpdyFrameType::HEADERS, frame_type);
  EXPECT_EQ("LOW", ProducerToString(std::move(frame_producer)));
  EXPECT_EQ(nullptr, stream.get());

  EXPECT_FALSE(write_queue.Dequeue(&frame_type, &frame_producer, &stream));
}

// Add some frame producers with the same priority. The producers
// should be dequeued in FIFO order with their associated stream.
TEST_F(SpdyWriteQueueTest, DequeuesFIFO) {
  SpdyWriteQueue write_queue;

  std::unique_ptr<SpdyBufferProducer> producer1 = IntToProducer(1);
  std::unique_ptr<SpdyBufferProducer> producer2 = IntToProducer(2);
  std::unique_ptr<SpdyBufferProducer> producer3 = IntToProducer(3);

  std::unique_ptr<SpdyStream> stream1 = MakeTestStream(DEFAULT_PRIORITY);
  std::unique_ptr<SpdyStream> stream2 = MakeTestStream(DEFAULT_PRIORITY);
  std::unique_ptr<SpdyStream> stream3 = MakeTestStream(DEFAULT_PRIORITY);

  write_queue.Enqueue(DEFAULT_PRIORITY, SpdyFrameType::HEADERS,
                      std::move(producer1), stream1->GetWeakPtr());
  write_queue.Enqueue(DEFAULT_PRIORITY, SpdyFrameType::HEADERS,
                      std::move(producer2), stream2->GetWeakPtr());
  write_queue.Enqueue(DEFAULT_PRIORITY, SpdyFrameType::RST_STREAM,
                      std::move(producer3), stream3->GetWeakPtr());

  SpdyFrameType frame_type = SpdyFrameType::DATA;
  std::unique_ptr<SpdyBufferProducer> frame_producer;
  base::WeakPtr<SpdyStream> stream;
  ASSERT_TRUE(write_queue.Dequeue(&frame_type, &frame_producer, &stream));
  EXPECT_EQ(SpdyFrameType::HEADERS, frame_type);
  EXPECT_EQ(1, ProducerToInt(std::move(frame_producer)));
  EXPECT_EQ(stream1.get(), stream.get());

  ASSERT_TRUE(write_queue.Dequeue(&frame_type, &frame_producer, &stream));
  EXPECT_EQ(SpdyFrameType::HEADERS, frame_type);
  EXPECT_EQ(2, ProducerToInt(std::move(frame_producer)));
  EXPECT_EQ(stream2.get(), stream.get());

  ASSERT_TRUE(write_queue.Dequeue(&frame_type, &frame_producer, &stream));
  EXPECT_EQ(SpdyFrameType::RST_STREAM, frame_type);
  EXPECT_EQ(3, ProducerToInt(std::move(frame_producer)));
  EXPECT_EQ(stream3.get(), stream.get());

  EXPECT_FALSE(write_queue.Dequeue(&frame_type, &frame_producer, &stream));
}

// Enqueue a bunch of writes and then call
// RemovePendingWritesForStream() on one of the streams. No dequeued
// write should be for that stream.
TEST_F(SpdyWriteQueueTest, RemovePendingWritesForStream) {
  SpdyWriteQueue write_queue;

  std::unique_ptr<SpdyStream> stream1 = MakeTestStream(DEFAULT_PRIORITY);
  std::unique_ptr<SpdyStream> stream2 = MakeTestStream(DEFAULT_PRIORITY);

  for (int i = 0; i < 100; ++i) {
    base::WeakPtr<SpdyStream> stream =
        (((i % 3) == 0) ? stream1 : stream2)->GetWeakPtr();
    write_queue.Enqueue(DEFAULT_PRIORITY, SpdyFrameType::HEADERS,
                        IntToProducer(i), stream);
  }

  write_queue.RemovePendingWritesForStream(stream2->GetWeakPtr());

  for (int i = 0; i < 100; i += 3) {
    SpdyFrameType frame_type = SpdyFrameType::DATA;
    std::unique_ptr<SpdyBufferProducer> frame_producer;
    base::WeakPtr<SpdyStream> stream;
    ASSERT_TRUE(write_queue.Dequeue(&frame_type, &frame_producer, &stream));
    EXPECT_EQ(SpdyFrameType::HEADERS, frame_type);
    EXPECT_EQ(i, ProducerToInt(std::move(frame_producer)));
    EXPECT_EQ(stream1.get(), stream.get());
  }

  SpdyFrameType frame_type = SpdyFrameType::DATA;
  std::unique_ptr<SpdyBufferProducer> frame_producer;
  base::WeakPtr<SpdyStream> stream;
  EXPECT_FALSE(write_queue.Dequeue(&frame_type, &frame_producer, &stream));
}

// Enqueue a bunch of writes and then call
// RemovePendingWritesForStreamsAfter(). No dequeued write should be for
// those streams without a stream id, or with a stream_id after that
// argument.
TEST_F(SpdyWriteQueueTest, RemovePendingWritesForStreamsAfter) {
  SpdyWriteQueue write_queue;

  std::unique_ptr<SpdyStream> stream1 = MakeTestStream(DEFAULT_PRIORITY);
  stream1->set_stream_id(1);
  std::unique_ptr<SpdyStream> stream2 = MakeTestStream(DEFAULT_PRIORITY);
  stream2->set_stream_id(3);
  std::unique_ptr<SpdyStream> stream3 = MakeTestStream(DEFAULT_PRIORITY);
  stream3->set_stream_id(5);
  // No stream id assigned.
  std::unique_ptr<SpdyStream> stream4 = MakeTestStream(DEFAULT_PRIORITY);
  base::WeakPtr<SpdyStream> streams[] = {
    stream1->GetWeakPtr(), stream2->GetWeakPtr(),
    stream3->GetWeakPtr(), stream4->GetWeakPtr()
  };

  for (int i = 0; i < 100; ++i) {
    write_queue.Enqueue(DEFAULT_PRIORITY, SpdyFrameType::HEADERS,
                        IntToProducer(i), streams[i % arraysize(streams)]);
  }

  write_queue.RemovePendingWritesForStreamsAfter(stream1->stream_id());

  for (int i = 0; i < 100; i += arraysize(streams)) {
    SpdyFrameType frame_type = SpdyFrameType::DATA;
    std::unique_ptr<SpdyBufferProducer> frame_producer;
    base::WeakPtr<SpdyStream> stream;
    ASSERT_TRUE(write_queue.Dequeue(&frame_type, &frame_producer, &stream))
        << "Unable to Dequeue i: " << i;
    EXPECT_EQ(SpdyFrameType::HEADERS, frame_type);
    EXPECT_EQ(i, ProducerToInt(std::move(frame_producer)));
    EXPECT_EQ(stream1.get(), stream.get());
  }

  SpdyFrameType frame_type = SpdyFrameType::DATA;
  std::unique_ptr<SpdyBufferProducer> frame_producer;
  base::WeakPtr<SpdyStream> stream;
  EXPECT_FALSE(write_queue.Dequeue(&frame_type, &frame_producer, &stream));
}

// Enqueue a bunch of writes and then call Clear(). The write queue
// should clean up the memory properly, and Dequeue() should return
// false.
TEST_F(SpdyWriteQueueTest, Clear) {
  SpdyWriteQueue write_queue;

  for (int i = 0; i < 100; ++i) {
    write_queue.Enqueue(DEFAULT_PRIORITY, SpdyFrameType::HEADERS,
                        IntToProducer(i), base::WeakPtr<SpdyStream>());
  }

  write_queue.Clear();

  SpdyFrameType frame_type = SpdyFrameType::DATA;
  std::unique_ptr<SpdyBufferProducer> frame_producer;
  base::WeakPtr<SpdyStream> stream;
  EXPECT_FALSE(write_queue.Dequeue(&frame_type, &frame_producer, &stream));
}

TEST_F(SpdyWriteQueueTest, RequeingProducerWithoutReentrance) {
  SpdyWriteQueue queue;
  queue.Enqueue(DEFAULT_PRIORITY, SpdyFrameType::HEADERS,
                MakeUnique<RequeingBufferProducer>(&queue),
                base::WeakPtr<SpdyStream>());
  {
    SpdyFrameType frame_type;
    std::unique_ptr<SpdyBufferProducer> producer;
    base::WeakPtr<SpdyStream> stream;

    EXPECT_TRUE(queue.Dequeue(&frame_type, &producer, &stream));
    EXPECT_TRUE(queue.IsEmpty());
    EXPECT_EQ(SpdyString(kOriginal),
              producer->ProduceBuffer()->GetRemainingData());
  }
  // |producer| was destroyed, and a buffer is re-queued.
  EXPECT_FALSE(queue.IsEmpty());

  SpdyFrameType frame_type;
  std::unique_ptr<SpdyBufferProducer> producer;
  base::WeakPtr<SpdyStream> stream;

  EXPECT_TRUE(queue.Dequeue(&frame_type, &producer, &stream));
  EXPECT_EQ(SpdyString(kRequeued),
            producer->ProduceBuffer()->GetRemainingData());
}

TEST_F(SpdyWriteQueueTest, ReentranceOnClear) {
  SpdyWriteQueue queue;
  queue.Enqueue(DEFAULT_PRIORITY, SpdyFrameType::HEADERS,
                MakeUnique<RequeingBufferProducer>(&queue),
                base::WeakPtr<SpdyStream>());

  queue.Clear();
  EXPECT_FALSE(queue.IsEmpty());

  SpdyFrameType frame_type;
  std::unique_ptr<SpdyBufferProducer> producer;
  base::WeakPtr<SpdyStream> stream;

  EXPECT_TRUE(queue.Dequeue(&frame_type, &producer, &stream));
  EXPECT_EQ(SpdyString(kRequeued),
            producer->ProduceBuffer()->GetRemainingData());
}

TEST_F(SpdyWriteQueueTest, ReentranceOnRemovePendingWritesAfter) {
  std::unique_ptr<SpdyStream> stream = MakeTestStream(DEFAULT_PRIORITY);
  stream->set_stream_id(2);

  SpdyWriteQueue queue;
  queue.Enqueue(DEFAULT_PRIORITY, SpdyFrameType::HEADERS,
                MakeUnique<RequeingBufferProducer>(&queue),
                stream->GetWeakPtr());

  queue.RemovePendingWritesForStreamsAfter(1);
  EXPECT_FALSE(queue.IsEmpty());

  SpdyFrameType frame_type;
  std::unique_ptr<SpdyBufferProducer> producer;
  base::WeakPtr<SpdyStream> weak_stream;

  EXPECT_TRUE(queue.Dequeue(&frame_type, &producer, &weak_stream));
  EXPECT_EQ(SpdyString(kRequeued),
            producer->ProduceBuffer()->GetRemainingData());
}

TEST_F(SpdyWriteQueueTest, ReentranceOnRemovePendingWritesForStream) {
  std::unique_ptr<SpdyStream> stream = MakeTestStream(DEFAULT_PRIORITY);
  stream->set_stream_id(2);

  SpdyWriteQueue queue;
  queue.Enqueue(DEFAULT_PRIORITY, SpdyFrameType::HEADERS,
                MakeUnique<RequeingBufferProducer>(&queue),
                stream->GetWeakPtr());

  queue.RemovePendingWritesForStream(stream->GetWeakPtr());
  EXPECT_FALSE(queue.IsEmpty());

  SpdyFrameType frame_type;
  std::unique_ptr<SpdyBufferProducer> producer;
  base::WeakPtr<SpdyStream> weak_stream;

  EXPECT_TRUE(queue.Dequeue(&frame_type, &producer, &weak_stream));
  EXPECT_EQ(SpdyString(kRequeued),
            producer->ProduceBuffer()->GetRemainingData());
}

}  // namespace

}  // namespace net
