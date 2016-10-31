// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_FILTER_SDCH_SOURCE_STREAM_H_
#define NET_FILTER_SDCH_SOURCE_STREAM_H_

#include <memory>

#include "base/macros.h"
#include "net/base/net_export.h"
#include "net/base/sdch_dictionary.h"
#include "net/base/sdch_manager.h"
#include "net/filter/filter_source_stream.h"
#include "net/filter/source_stream.h"

namespace open_vcdiff {
class VCDiffStreamingDecoder;
}  // namespace open_vcdiff

namespace net {

class IOBuffer;

// SdchSourceStream applies open_vcdiff content decoding to a datastream.
// This decoding uses a pre-cached dictionary of text fragments to decode
// (expand) the stream back to its original contents.
//
// This SdchSourceStream internally uses open_vcdiff/vcdec library to do
// decoding.
class NET_EXPORT_PRIVATE SdchSourceStream : public FilterSourceStream {
 public:
  enum InputState {
    STATE_LOAD_DICTIONARY,
    STATE_DECODE,
    STATE_OUTPUT_REPLACE,
    STATE_PASS_THROUGH,
  };

  // The Delegate interface is responsible for error recovery and stats
  // gathering. See the methods below for descriptions of which errors the
  // delegate is expected to handle and what it can do to repair them.
  class NET_EXPORT_PRIVATE Delegate {
   public:
    enum ErrorRecovery {
      // Do not recover the error.
      NONE,
      // Pass remaining input unchanged to downstream.
      PASS_THROUGH,
      // Pass an alternative output to downstream.
      REPLACE_OUTPUT,
    };
    virtual ~Delegate(){};

    // Called by the SdchSourceStream if an error occurs while parsing the
    // server-sent dictionary ID, or if the specified dictionary can't be loaded
    // (i.e., GetDictionary returned false). This method is expected to handle
    // the error condition by returning a ErrorRecovery enum. If REPLACE_OUTPUT
    // is returned, it will also write the output to be replaced with to
    // |replace_output|.
    virtual ErrorRecovery OnDictionaryIdError(std::string* replace_output) = 0;

    // Called by the SdchSourceStream if the specified dictionary can't be
    // loaded (i.e., GetDictionary returned false). This method is expected to
    // handle the error condition by returning a ErrorRecovery enum.
    // If REPLACE_OUTPUT is returned, it will also write the output to be
    // replaced with to |replace_output|.
    virtual ErrorRecovery OnGetDictionaryError(std::string* replace_output) = 0;

    // Called by the SdchSourceStream if an error occurs while decoding the
    // vcdiff-compressed data stream. This method is expected to
    // handle the error condition by returning a ErrorRecovery enum.
    // If REPLACE_OUTPUT is returned, it will also write the output to be
    // replaced with to |replace_output|.
    virtual ErrorRecovery OnDecodingError(std::string* replace_output) = 0;

    // Called by the SdchSourceStream to request the text of the specified
    // dictionary. This method must either:
    //   * Fill in |*text| and return true, or
    //   * Leave |*text| untouched and return false.
    // The delegate is required to make sure that the pointer written into
    // |*text| remains valid for the lifetime of the delegate.
    // The return value is true if the named dictionary could be found and false
    // otherwise.
    //
    // The |server_id| string is guaranteed to be a syntactically valid SDCH
    // server-id.
    // TODO(xunjieli): If an async interface is required. Change |text| to use
    // an IOBuffer buffer and add a callback.
    virtual bool OnGetDictionary(const std::string& server_id,
                                 const std::string** text) = 0;

    // Called by the SdchSourceStream to notify the delegate that it is being
    // destroyed.|input_state| indicates the InputState of the stream's input
    // data. |buffered_output_present| indicates whether there is still data
    // in the buffered output that is not consumed. If |decoding_not_finished|
    // is true, it indicates that decoding has not finished.
    virtual void OnStreamDestroyed(InputState input_state,
                                   bool buffered_output_present,
                                   bool decoding_not_finished) = 0;
  };

  SdchSourceStream(std::unique_ptr<SourceStream> previous,
                   std::unique_ptr<Delegate> delegate,
                   SourceStream::SourceType type);
  ~SdchSourceStream() override;

 private:
  // SourceStream implementation:
  std::string GetTypeAsString() const override;
  int FilterData(IOBuffer* output_buffer,
                 int output_buffer_size,
                 IOBuffer* input_buffer,
                 int input_buffer_size,
                 int* consumed_bytes,
                 bool upstream_end_reached) override;

  // Returns whether |id| looks like a dictionary ID, meaning 8 characters of
  // base64url followed by a null character.
  bool CouldBeDictionaryId(const std::string& id) const;

  // Helper method to handle error returned by Delegate. It sets |input_state_|
  // and returns true if the error can be handles, and false if the error is
  // not recoverable.
  bool HandleError(Delegate::ErrorRecovery error_recover);

  std::unique_ptr<open_vcdiff::VCDiffStreamingDecoder> decoder_;
  std::unique_ptr<Delegate> delegate_;

  // After the encoded response SDCH header is read, this variable contains
  // the server hash with trailing null byte.
  std::string dictionary_server_id_;

  // Since vcdiff may generate quite a bit of output at once, SdchSourceStream
  // has to buffer excess output (more than requested by the caller) here to
  // return later. This could become quite large. crbug.com/651577.
  std::string buffered_output_;

  // State of the input stream.
  InputState input_state_;

  DISALLOW_COPY_AND_ASSIGN(SdchSourceStream);
};

}  // namespace net

#endif  // NET_FILTER_SDCH_SOURCE_STREAM_H_
