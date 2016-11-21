// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/filter/gzip_source_stream.h"

#include <algorithm>
#include <utility>

#include "base/bind.h"
#include "base/bit_cast.h"
#include "base/logging.h"
#include "net/base/io_buffer.h"
#include "third_party/zlib/zlib.h"

namespace net {

namespace {

const char kDeflate[] = "DEFLATE";
const char kGzip[] = "GZIP";
const char kGzipFallback[] = "GZIP_FALLBACK";

}  // namespace

GzipSourceStream::~GzipSourceStream() {
  if (zlib_stream_)
    inflateEnd(zlib_stream_.get());
}

std::unique_ptr<GzipSourceStream> GzipSourceStream::Create(
    std::unique_ptr<SourceStream> upstream,
    SourceStream::SourceType type) {
  std::unique_ptr<GzipSourceStream> source(
      new GzipSourceStream(std::move(upstream), type));

  if (!source->Init())
    return nullptr;
  return source;
}

GzipSourceStream::GzipSourceStream(std::unique_ptr<SourceStream> upstream,
                                   SourceStream::SourceType type)
    : FilterSourceStream(type, std::move(upstream)),
      zlib_header_added_(false),
      gzip_footer_bytes_left_(0),
      input_state_(STATE_START) {}

bool GzipSourceStream::Init() {
  zlib_stream_.reset(new z_stream);
  if (!zlib_stream_)
    return false;
  memset(zlib_stream_.get(), 0, sizeof(z_stream));

  int ret;
  if (type() == TYPE_GZIP || type() == TYPE_GZIP_FALLBACK) {
    ret = inflateInit2(zlib_stream_.get(), -MAX_WBITS);
  } else {
    ret = inflateInit(zlib_stream_.get());
  }
  DCHECK_NE(Z_VERSION_ERROR, ret);
  return ret == Z_OK;
}

std::string GzipSourceStream::GetTypeAsString() const {
  switch (type()) {
    case TYPE_GZIP:
      return kGzip;
    case TYPE_GZIP_FALLBACK:
      return kGzipFallback;
    case TYPE_DEFLATE:
      return kDeflate;
    default:
      NOTREACHED();
      return "";
  }
}

int GzipSourceStream::FilterData(IOBuffer* output_buffer,
                                 int output_buffer_size,
                                 IOBuffer* input_buffer,
                                 int input_buffer_size,
                                 int* consumed_bytes,
                                 bool /*upstream_end_reached*/) {
  *consumed_bytes = 0;
  char* input_data = input_buffer->data();
  int input_data_size = input_buffer_size;
  int bytes_out = 0;
  bool state_compressed_entered = false;
  while (input_data_size > 0 && bytes_out < output_buffer_size) {
    InputState state = input_state_;
    switch (state) {
      case STATE_START: {
        if (type() == TYPE_DEFLATE) {
          input_state_ = STATE_COMPRESSED_BODY;
          break;
        }
        // If this stream is not really gzipped as detected by
        // ShouldFallbackToPlain, pretend that the zlib stream has ended.
        DCHECK_LT(0, input_data_size);
        if (ShouldFallbackToPlain(input_data[0])) {
          input_state_ = STATE_UNCOMPRESSED_BODY;
        } else {
          input_state_ = STATE_GZIP_HEADER;
        }
        break;
      }
      case STATE_GZIP_HEADER: {
        const size_t kGzipFooterBytes = 8;
        const char* end = nullptr;
        GZipHeader::Status status =
            gzip_header_.ReadMore(input_data, input_data_size, &end);
        if (status == GZipHeader::INCOMPLETE_HEADER) {
          input_data += input_data_size;
          input_data_size = 0;
        } else if (status == GZipHeader::COMPLETE_HEADER) {
          // If there is a valid header, there should also be a valid footer.
          gzip_footer_bytes_left_ = kGzipFooterBytes;
          int bytes_consumed = end - input_data;
          input_data += bytes_consumed;
          input_data_size -= bytes_consumed;
          input_state_ = STATE_COMPRESSED_BODY;
        } else if (status == GZipHeader::INVALID_HEADER) {
          return ERR_CONTENT_DECODING_FAILED;
        }
        break;
      }
      case STATE_COMPRESSED_BODY: {
        DCHECK(!state_compressed_entered);
        DCHECK_LE(0, input_data_size);

        state_compressed_entered = true;
        zlib_stream_.get()->next_in = bit_cast<Bytef*>(input_data);
        zlib_stream_.get()->avail_in = input_data_size;
        zlib_stream_.get()->next_out = bit_cast<Bytef*>(output_buffer->data());
        zlib_stream_.get()->avail_out = output_buffer_size;

        int ret = inflate(zlib_stream_.get(), Z_NO_FLUSH);

        // Sometimes misconfigured servers omit the zlib header, relying on
        // clients to splice it back in.
        if (ret < 0 && !zlib_header_added_) {
          zlib_header_added_ = true;
          if (!InsertZlibHeader())
            return ERR_CONTENT_DECODING_FAILED;

          zlib_stream_.get()->next_in = bit_cast<Bytef*>(input_data);
          zlib_stream_.get()->avail_in = input_data_size;
          zlib_stream_.get()->next_out =
              bit_cast<Bytef*>(output_buffer->data());
          zlib_stream_.get()->avail_out = output_buffer_size;

          ret = inflate(zlib_stream_.get(), Z_NO_FLUSH);
          // TODO(xunjieli): add a histogram to see how often this happens. The
          // original bug for this behavior was ancient and maybe it doesn't
          // happen in the wild any more? crbug.com/649339
        }
        if (ret != Z_STREAM_END && ret != Z_OK)
          return ERR_CONTENT_DECODING_FAILED;

        int bytes_used = input_data_size - zlib_stream_.get()->avail_in;
        bytes_out = output_buffer_size - zlib_stream_.get()->avail_out;
        input_data_size -= bytes_used;
        input_data += bytes_used;
        if (ret == Z_STREAM_END)
          input_state_ = STATE_GZIP_FOOTER;
        // zlib has written as much data to |output_buffer| as it could.
        // There might still be some unconsumed data in |input_buffer| if there
        // is no space in |output_buffer|.
        break;
      }
      case STATE_GZIP_FOOTER: {
        size_t to_read = std::min(gzip_footer_bytes_left_,
                                  base::checked_cast<size_t>(input_data_size));
        gzip_footer_bytes_left_ -= to_read;
        input_data_size -= to_read;
        input_data += to_read;
        if (gzip_footer_bytes_left_ == 0)
          input_state_ = STATE_UNCOMPRESSED_BODY;
        break;
      }
      case STATE_UNCOMPRESSED_BODY: {
        int to_copy = std::min(input_data_size, output_buffer_size - bytes_out);
        memcpy(output_buffer->data() + bytes_out, input_data, to_copy);
        input_data_size -= to_copy;
        input_data += to_copy;
        bytes_out += to_copy;
        break;
      }
    }
  }
  *consumed_bytes = input_buffer_size - input_data_size;
  return bytes_out;
}

bool GzipSourceStream::InsertZlibHeader() {
  char dummy_header[] = {0x78, 0x01};
  char dummy_output[4];

  inflateReset(zlib_stream_.get());
  zlib_stream_.get()->next_in = bit_cast<Bytef*>(&dummy_header[0]);
  zlib_stream_.get()->avail_in = sizeof(dummy_header);
  zlib_stream_.get()->next_out = bit_cast<Bytef*>(&dummy_output[0]);
  zlib_stream_.get()->avail_out = sizeof(dummy_output);

  int ret = inflate(zlib_stream_.get(), Z_NO_FLUSH);
  return ret == Z_OK;
}

// Dumb heuristic. Gzip files always start with a two-byte magic value per RFC
// 1952 2.3.1, so if the first byte isn't the first byte of the gzip magic, and
// this filter is checking whether it should fallback, then fallback.
bool GzipSourceStream::ShouldFallbackToPlain(char first_byte) {
  if (type() != TYPE_GZIP_FALLBACK)
    return false;
  static const char kGzipFirstByte = 0x1f;
  return first_byte != kGzipFirstByte;
}

}  // namespace net
