// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/filter/sdch_source_stream.h"

#include "base/auto_reset.h"
#include "base/bind.h"
#include "base/logging.h"
#include "base/numerics/safe_conversions.h"
#include "base/values.h"
#include "net/base/io_buffer.h"
#include "net/log/net_log_capture_mode.h"
#include "sdch/open-vcdiff/src/google/vcdecoder.h"

namespace net {

namespace {

const size_t kServerIdLength = 9;
const char kSdch[] = "SDCH";
const char kSdchPossible[] = "SDCH_POSSIBLE";

// Flushes as many bytes as possible from |buffered_output_ to |output_buffer|.
// Return the number of bytes flushed.
int FlushBufferedOutput(char* output_buffer,
                        int output_buffer_size,
                        const std::string& buffered_output) {
  size_t to_flush = std::min(base::checked_cast<size_t>(output_buffer_size),
                             buffered_output.length());
  memcpy(output_buffer, buffered_output.data(), to_flush);
  return to_flush;
}

}  // namespace

SdchSourceStream::SdchSourceStream(std::unique_ptr<SourceStream> previous,
                                   std::unique_ptr<Delegate> delegate,
                                   SourceStream::SourceType type)
    : FilterSourceStream(type, std::move(previous)),
      delegate_(std::move(delegate)),
      input_state_(STATE_LOAD_DICTIONARY) {}

SdchSourceStream::~SdchSourceStream() {
  bool decoding_not_finished = decoder_ && !decoder_->FinishDecoding();
  delegate_->OnStreamDestroyed(input_state_, !buffered_output_.empty(),
                               decoding_not_finished);
}

std::string SdchSourceStream::GetTypeAsString() const {
  if (type() == TYPE_SDCH)
    return kSdch;
  DCHECK_EQ(TYPE_SDCH_POSSIBLE, type());
  return kSdchPossible;
}

int SdchSourceStream::FilterData(IOBuffer* output_buffer,
                                 int output_buffer_size,
                                 IOBuffer* input_buffer,
                                 int input_buffer_size,
                                 int* consumed_bytes,
                                 bool /*upstream_end_reached*/) {
  DCHECK_LE(0, input_buffer_size);
  int input_data_size = input_buffer_size;
  char* input_data = input_buffer->data();
  int bytes_out = 0;
  while ((input_data_size > 0 || !buffered_output_.empty()) &&
         output_buffer_size - bytes_out > 0) {
    switch (input_state_) {
      case STATE_LOAD_DICTIONARY: {
        // Copy at most |kServerIdLength| from |input_buffer|.
        size_t to_copy =
            std::min(kServerIdLength - dictionary_server_id_.length(),
                     base::checked_cast<size_t>(input_data_size));
        dictionary_server_id_.append(input_data, to_copy);
        input_data_size -= to_copy;
        input_data += to_copy;

        // Not enough bytes for a dictionary ID accumulated yet.
        if (dictionary_server_id_.length() != kServerIdLength) {
          DCHECK_EQ(0, input_data_size);
          *consumed_bytes = input_buffer_size;
          return 0;
        }
        if (!CouldBeDictionaryId(dictionary_server_id_)) {
          // If |dictionary_server_id_| is bogus, it should appear in output
          // stream, so append it to |buffered_output_| here.
          buffered_output_.append(dictionary_server_id_);
          if (!HandleError(delegate_->OnDictionaryIdError(&buffered_output_)))
            return ERR_CONTENT_DECODING_FAILED;
          break;
        }
        const std::string* dictionary_text = nullptr;
        // To avoid passing a std::string with a null terminator into
        // GetDictionary(), server hash here removes the last byte blindly.
        if (!delegate_->OnGetDictionary(
                dictionary_server_id_.substr(0, kServerIdLength - 1),
                &dictionary_text)) {
          // If GetDictionaryId fails and delegate chooses to pass through,
          // preserve the dictionary id in the output.
          buffered_output_.append(dictionary_server_id_);
          if (!HandleError(
                  delegate_->OnGetDictionaryError(&buffered_output_))) {
            return ERR_CONTENT_DECODING_FAILED;
          }
          break;
        }
        decoder_.reset(new open_vcdiff::VCDiffStreamingDecoder);
        decoder_->SetAllowVcdTarget(false);
        decoder_->StartDecoding(dictionary_text->data(),
                                dictionary_text->length());
        input_state_ = STATE_DECODE;
        break;
      }
      case STATE_DECODE: {
        int flushed = FlushBufferedOutput(output_buffer->data() + bytes_out,
                                          output_buffer_size - bytes_out,
                                          buffered_output_);
        buffered_output_.erase(0, flushed);
        bytes_out += flushed;
        if (!buffered_output_.empty())
          break;
        bool ok = decoder_->DecodeChunk(input_data, input_data_size,
                                        &buffered_output_);
        // Calls to DecodeChunk always consume all their input, so this always
        // drains the entire buffer.
        input_data += input_data_size;
        input_data_size = 0;
        if (!ok) {
          decoder_.reset();
          if (!HandleError(delegate_->OnDecodingError(&buffered_output_)))
            return ERR_CONTENT_DECODING_FAILED;
        }
        break;
      }
      case STATE_OUTPUT_REPLACE: {
        // Drains the entire input since the replacement will be returned.
        input_data_size = 0;
        int flushed = FlushBufferedOutput(output_buffer->data() + bytes_out,
                                          output_buffer_size - bytes_out,
                                          buffered_output_);
        buffered_output_.erase(0, flushed);
        bytes_out += flushed;
        break;
      }
      case STATE_PASS_THROUGH: {
        if (!buffered_output_.empty()) {
          int flushed = FlushBufferedOutput(output_buffer->data() + bytes_out,
                                            output_buffer_size - bytes_out,
                                            buffered_output_);
          buffered_output_.erase(0, flushed);
          bytes_out += flushed;
        }
        if (!buffered_output_.empty())
          break;
        size_t to_copy =
            std::min(output_buffer_size - bytes_out, input_data_size);
        memcpy(output_buffer->data() + bytes_out, input_data, to_copy);
        bytes_out += to_copy;
        input_data += to_copy;
        input_data_size -= to_copy;
        break;
      }
    }
  }
  *consumed_bytes = input_buffer_size - input_data_size;
  return bytes_out;
}

bool SdchSourceStream::CouldBeDictionaryId(const std::string& id) const {
  for (size_t i = 0; i < kServerIdLength - 1; i++) {
    char base64_char = id[i];
    if (!isalnum(base64_char) && '-' != base64_char && '_' != base64_char)
      return false;
  }
  if (id[kServerIdLength - 1] != '\0')
    return false;
  return true;
}

bool SdchSourceStream::HandleError(Delegate::ErrorRecovery error_recover) {
  switch (error_recover) {
    case Delegate::NONE:
      return false;
    case Delegate::PASS_THROUGH:
      input_state_ = STATE_PASS_THROUGH;
      break;
    case Delegate::REPLACE_OUTPUT:
      input_state_ = STATE_OUTPUT_REPLACE;
      break;
  }
  return true;
}

}  // namespace net
