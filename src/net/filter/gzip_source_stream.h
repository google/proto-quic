// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_FILTER_GZIP_SOURCE_STREAM_H_
#define NET_FILTER_GZIP_SOURCE_STREAM_H_

#include <memory>
#include <string>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "net/base/io_buffer.h"
#include "net/base/net_export.h"
#include "net/filter/filter_source_stream.h"
#include "net/filter/gzip_header.h"

typedef struct z_stream_s z_stream;

namespace net {

class IOBuffer;

// GZipSourceStream applies gzip and deflate content encoding/decoding to a data
// stream. As specified by HTTP 1.1, with gzip encoding the content is
// wrapped with a gzip header, and with deflate encoding the content is in
// a raw, headerless DEFLATE stream.
//
// Internally GZipSourceStream uses zlib inflate to do decoding.
//
class NET_EXPORT_PRIVATE GzipSourceStream : public FilterSourceStream {
 public:
  ~GzipSourceStream() override;

  // Creates a GzipSourceStream. Return nullptr if initialization fails.
  static std::unique_ptr<GzipSourceStream> Create(
      std::unique_ptr<SourceStream> previous,
      SourceStream::SourceType type);

 private:
  enum InputState {
    // Starts processing the input stream. Checks whether the stream is valid
    // and whether a fallback to plain data is needed.
    STATE_START,
    // Gzip header of the input stream is being processed.
    STATE_GZIP_HEADER,
    // The input stream is being decoded.
    STATE_COMPRESSED_BODY,
    // Gzip footer of the input stream is being processed.
    STATE_GZIP_FOOTER,
    // The input stream is being passed through undecoded.
    STATE_UNCOMPRESSED_BODY,
  };

  GzipSourceStream(std::unique_ptr<SourceStream> previous,
                   SourceStream::SourceType type);

  // Returns true if initialization is successful, false otherwise.
  // For instance, this method returns false if there is not enough memory or
  // if there is a version mismatch.
  bool Init();

  // SourceStream implementation
  std::string GetTypeAsString() const override;
  int FilterData(IOBuffer* output_buffer,
                 int output_buffer_size,
                 IOBuffer* input_buffer,
                 int input_buffer_size,
                 int* consumed_bytes,
                 bool upstream_end_reached) override;

  // Inserts a zlib header to the data stream before calling zlib inflate.
  // This is used to work around server bugs. The function returns true on
  // success.
  bool InsertZlibHeader();

  // Returns whether this stream looks like it could be plain text (ie, not
  // actually gzipped). Right now this uses an extremely simple heuristic; see
  // the source for details. This method checks the first byte of the stream.
  bool ShouldFallbackToPlain(char first_byte);

  // The control block of zlib which actually does the decoding.
  // This data structure is initialized by Init and updated only by
  // FilterData(), with InsertZlibHeader() being the exception as a workaround.
  std::unique_ptr<z_stream> zlib_stream_;

  // A flag used by FilterData() to record whether we've successfully added
  // a zlib header to this stream.
  bool zlib_header_added_;

  // Used to parse the gzip header in gzip stream.
  // It is used when the decoding mode is GZIP_SOURCE_STREAM_GZIP.
  GZipHeader gzip_header_;

  // Tracks how many bytes of gzip footer are yet to be filtered.
  size_t gzip_footer_bytes_left_;

  // Tracks the state of the input stream.
  InputState input_state_;

  DISALLOW_COPY_AND_ASSIGN(GzipSourceStream);
};

}  // namespace net

#endif  // NET_FILTER_GZIP_SOURCE_STREAM_H__
