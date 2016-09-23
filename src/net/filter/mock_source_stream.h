// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_FILTER_MOCK_SOURCE_STREAM_H_
#define NET_FILTER_MOCK_SOURCE_STREAM_H_

#include <queue>
#include <string>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "net/base/completion_callback.h"
#include "net/base/net_errors.h"
#include "net/filter/source_stream.h"

namespace net {

class IOBuffer;

// A SourceStream implementation used in tests. This allows tests to specify
// what data to return for each Read() call.
class MockSourceStream : public SourceStream {
 public:
  enum Mode {
    SYNC,
    ASYNC,
  };
  MockSourceStream();
  // The destructor will crash in debug build if there is any pending read.
  ~MockSourceStream() override;

  // SourceStream implementation
  int Read(IOBuffer* dest_buffer,
           int buffer_size,
           const CompletionCallback& callback) override;
  std::string Description() const override;

  // Enqueues a result to be returned by |Read|. This method does not make a
  // copy of |data|, so |data| must outlive this object. If |mode| is SYNC,
  // |Read| will return the supplied data synchronously; otherwise, consumer
  // needs to call |CompleteNextRead|
  void AddReadResult(const char* data, int len, Error error, Mode mode);

  // Completes a pending Read() call. Crash in debug build if there is no
  // pending read.
  void CompleteNextRead();

 private:
  struct QueuedResult {
    QueuedResult(const char* data, int len, Error error, Mode mode);

    const char* data;
    const int len;
    const Error error;
    const Mode mode;
  };

  std::queue<QueuedResult> results_;
  bool awaiting_completion_;
  scoped_refptr<IOBuffer> dest_buffer_;
  CompletionCallback callback_;
  int dest_buffer_size_;

  DISALLOW_COPY_AND_ASSIGN(MockSourceStream);
};

}  // namespace net

#endif  // NET_FILTER_MOCK_SOURCE_STREAM_H_
