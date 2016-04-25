// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// The basic usage of the Filter interface is described in the comment at
// the beginning of filter.h. If Filter::Factory is passed a vector of
// size greater than 1, that interface is implemented by a series of filters
// connected in a chain. In such a case the first filter
// in the chain proxies calls to ReadData() so that its return values
// apply to the entire chain.
//
// In a filter chain, the data flows from first filter (held by the
// caller) down the chain. When ReadData() is called on any filter
// except for the last filter, it proxies the call down the chain,
// filling in the input buffers of subsequent filters if needed (==
// that filter's last_status() value is FILTER_NEED_MORE_DATA) and
// available (== the current filter has data it can output). The last
// Filter will then output data if possible, and return
// FILTER_NEED_MORE_DATA if not. Because the indirection pushes
// data along the filter chain at each level if it's available and the
// next filter needs it, a return value of FILTER_NEED_MORE_DATA from the
// final filter will apply to the entire chain.

#include "net/filter/filter.h"

#include "base/files/file_path.h"
#include "base/strings/string_util.h"
#include "base/values.h"
#include "net/base/io_buffer.h"
#include "net/base/sdch_net_log_params.h"
#include "net/filter/brotli_filter.h"
#include "net/filter/gzip_filter.h"
#include "net/filter/sdch_filter.h"
#include "net/url_request/url_request_context.h"
#include "url/gurl.h"

namespace net {

namespace {

// Filter types (using canonical lower case only):
const char kBrotli[]       = "br";
const char kDeflate[]      = "deflate";
const char kGZip[]         = "gzip";
const char kXGZip[]        = "x-gzip";
const char kSdch[]         = "sdch";
// compress and x-compress are currently not supported. If we decide to support
// them, we'll need the same mime type compatibility hack we have for gzip. For
// more information, see Firefox's nsHttpChannel::ProcessNormal.

// Mime types:
const char kTextHtml[]             = "text/html";

// Buffer size allocated when de-compressing data.
const int kFilterBufSize = 32 * 1024;

void LogSdchProblem(const FilterContext& filter_context,
                    SdchProblemCode problem) {
  SdchManager::SdchErrorRecovery(problem);
  filter_context.GetNetLog().AddEvent(
      NetLog::TYPE_SDCH_DECODING_ERROR,
      base::Bind(&NetLogSdchResourceProblemCallback, problem));
}

std::string FilterTypeAsString(Filter::FilterType type_id) {
  switch (type_id) {
    case Filter::FILTER_TYPE_BROTLI:
      return "FILTER_TYPE_BROTLI";
    case Filter::FILTER_TYPE_DEFLATE:
      return "FILTER_TYPE_DEFLATE";
    case Filter::FILTER_TYPE_GZIP:
      return "FILTER_TYPE_GZIP";
    case Filter::FILTER_TYPE_GZIP_HELPING_SDCH:
      return "FILTER_TYPE_GZIP_HELPING_SDCH";
    case Filter::FILTER_TYPE_SDCH:
      return "FILTER_TYPE_SDCH";
    case Filter::FILTER_TYPE_SDCH_POSSIBLE  :
      return "FILTER_TYPE_SDCH_POSSIBLE  ";
    case Filter::FILTER_TYPE_UNSUPPORTED:
      return "FILTER_TYPE_UNSUPPORTED";
    case Filter::FILTER_TYPE_MAX:
      return "FILTER_TYPE_MAX";
  }
  return "";
}

}  // namespace

FilterContext::~FilterContext() {
}

Filter::~Filter() {}

// static
Filter* Filter::Factory(const std::vector<FilterType>& filter_types,
                        const FilterContext& filter_context) {
  if (filter_types.empty())
    return NULL;

  Filter* filter_list = NULL;  // Linked list of filters.
  for (size_t i = 0; i < filter_types.size(); i++) {
    filter_list = PrependNewFilter(filter_types[i], filter_context,
                                   kFilterBufSize, filter_list);
    if (!filter_list)
      return NULL;
  }
  return filter_list;
}

// static
Filter* Filter::GZipFactory() {
  return InitGZipFilter(FILTER_TYPE_GZIP, kFilterBufSize);
}

// static
Filter* Filter::FactoryForTests(const std::vector<FilterType>& filter_types,
                                const FilterContext& filter_context,
                                int buffer_size) {
  if (filter_types.empty())
    return NULL;

  Filter* filter_list = NULL;  // Linked list of filters.
  for (size_t i = 0; i < filter_types.size(); i++) {
    filter_list = PrependNewFilter(filter_types[i], filter_context,
                                   buffer_size, filter_list);
    if (!filter_list)
      return NULL;
  }
  return filter_list;
}

Filter::FilterStatus Filter::ReadData(char* dest_buffer, int* dest_len) {
  const int dest_buffer_capacity = *dest_len;
  if (last_status_ == FILTER_ERROR)
    return last_status_;
  if (!next_filter_.get())
    return last_status_ = ReadFilteredData(dest_buffer, dest_len);

  // This filter needs more data, but it's not clear that the rest of
  // the chain does; delegate the actual status return to the next filter.
  if (last_status_ == FILTER_NEED_MORE_DATA && !stream_data_len())
    return next_filter_->ReadData(dest_buffer, dest_len);

  do {
    if (next_filter_->last_status() == FILTER_NEED_MORE_DATA) {
      PushDataIntoNextFilter();
      if (FILTER_ERROR == last_status_)
        return FILTER_ERROR;
    }
    *dest_len = dest_buffer_capacity;  // Reset the input/output parameter.
    next_filter_->ReadData(dest_buffer, dest_len);
    if (FILTER_NEED_MORE_DATA == last_status_)
        return next_filter_->last_status();

    // In the case where this filter has data internally, and is indicating such
    // with a last_status_ of FILTER_OK, but at the same time the next filter in
    // the chain indicated it FILTER_NEED_MORE_DATA, we have to be cautious
    // about confusing the caller. The API confusion can appear if we return
    // FILTER_OK (suggesting we have more data in aggregate), but yet we don't
    // populate our output buffer. When that is the case, we need to
    // alternately call our filter element, and the next_filter element until we
    // get out of this state (by pumping data into the next filter until it
    // outputs data, or it runs out of data and reports that it NEED_MORE_DATA.)
  } while (FILTER_OK == last_status_ &&
           FILTER_NEED_MORE_DATA == next_filter_->last_status() &&
           0 == *dest_len);

  if (next_filter_->last_status() == FILTER_ERROR)
    return FILTER_ERROR;
  return FILTER_OK;
}

bool Filter::FlushStreamBuffer(int stream_data_len) {
  DCHECK_LE(stream_data_len, stream_buffer_size_);
  if (stream_data_len <= 0 || stream_data_len > stream_buffer_size_)
    return false;

  DCHECK(stream_buffer());
  // Bail out if there is more data in the stream buffer to be filtered.
  if (!stream_buffer() || stream_data_len_)
    return false;

  next_stream_data_ = stream_buffer()->data();
  stream_data_len_ = stream_data_len;
  last_status_ = FILTER_OK;
  return true;
}

// static
Filter::FilterType Filter::ConvertEncodingToType(
    const std::string& filter_type) {
  FilterType type_id;
  if (base::LowerCaseEqualsASCII(filter_type, kBrotli)) {
    type_id = FILTER_TYPE_BROTLI;
  } else if (base::LowerCaseEqualsASCII(filter_type, kDeflate)) {
    type_id = FILTER_TYPE_DEFLATE;
  } else if (base::LowerCaseEqualsASCII(filter_type, kGZip) ||
             base::LowerCaseEqualsASCII(filter_type, kXGZip)) {
    type_id = FILTER_TYPE_GZIP;
  } else if (base::LowerCaseEqualsASCII(filter_type, kSdch)) {
    type_id = FILTER_TYPE_SDCH;
  } else {
    // Note we also consider "identity" and "uncompressed" UNSUPPORTED as
    // filter should be disabled in such cases.
    type_id = FILTER_TYPE_UNSUPPORTED;
  }
  return type_id;
}

// static
void Filter::FixupEncodingTypes(
    const FilterContext& filter_context,
    std::vector<FilterType>* encoding_types) {
  std::string mime_type;
  bool success = filter_context.GetMimeType(&mime_type);
  DCHECK(success || mime_type.empty());

  // If the request was for SDCH content, then we might need additional fixups.
  if (!filter_context.SdchDictionariesAdvertised()) {
    // It was not an SDCH request, so we'll just record stats.
    if (1 < encoding_types->size()) {
      // Multiple filters were intended to only be used for SDCH (thus far!)
      LogSdchProblem(filter_context, SDCH_MULTIENCODING_FOR_NON_SDCH_REQUEST);
    }
    if ((1 == encoding_types->size()) &&
        (FILTER_TYPE_SDCH == encoding_types->front())) {
      LogSdchProblem(filter_context,
                     SDCH_SDCH_CONTENT_ENCODE_FOR_NON_SDCH_REQUEST);
    }
    return;
  }

  // The request was tagged as an SDCH request, which means the server supplied
  // a dictionary, and we advertised it in the request. Some proxies will do
  // very strange things to the request, or the response, so we have to handle
  // them gracefully.

  // If content encoding included SDCH, then everything is "relatively" fine.
  if (!encoding_types->empty() &&
      (FILTER_TYPE_SDCH == encoding_types->front())) {
    // Some proxies (found currently in Argentina) strip the Content-Encoding
    // text from "sdch,gzip" to a mere "sdch" without modifying the compressed
    // payload.  To handle this gracefully, we simulate the "probably" deleted
    // ",gzip" by appending a tentative gzip decode, which will default to a
    // no-op pass through filter if it doesn't get gzip headers where expected.
    if (1 == encoding_types->size()) {
      encoding_types->push_back(FILTER_TYPE_GZIP_HELPING_SDCH);
      LogSdchProblem(filter_context, SDCH_OPTIONAL_GUNZIP_ENCODING_ADDED);
    }
    return;
  }

  // There are now several cases to handle for an SDCH request. Foremost, if
  // the outbound request was stripped so as not to advertise support for
  // encodings, we might get back content with no encoding, or (for example)
  // just gzip. We have to be sure that any changes we make allow for such
  // minimal coding to work. That issue is why we use TENTATIVE filters if we
  // add any, as those filters sniff the content, and act as pass-through
  // filters if headers are not found.

  // If the outbound GET is not modified, then the server will generally try to
  // send us SDCH encoded content. As that content returns, there are several
  // corruptions of the header "content-encoding" that proxies may perform (and
  // have been detected in the wild). We already dealt with the a honest
  // content encoding of "sdch,gzip" being corrupted into "sdch" with on change
  // of the actual content. Another common corruption is to either disscard
  // the accurate content encoding, or to replace it with gzip only (again, with
  // no change in actual content). The last observed corruption it to actually
  // change the content, such as by re-gzipping it, and that may happen along
  // with corruption of the stated content encoding (wow!).

  // The one unresolved failure mode comes when we advertise a dictionary, and
  // the server tries to *send* a gzipped file (not gzip encode content), and
  // then we could do a gzip decode :-(. Since SDCH is only (currently)
  // supported server side on paths that only send HTML content, this mode has
  // never surfaced in the wild (and is unlikely to).
  // We will gather a lot of stats as we perform the fixups
  if (base::StartsWith(mime_type, kTextHtml,
                       base::CompareCase::INSENSITIVE_ASCII)) {
    // Suspicious case: Advertised dictionary, but server didn't use sdch, and
    // we're HTML tagged.
    if (encoding_types->empty()) {
      LogSdchProblem(filter_context, SDCH_ADDED_CONTENT_ENCODING);
    } else if (1 == encoding_types->size()) {
      LogSdchProblem(filter_context, SDCH_FIXED_CONTENT_ENCODING);
    } else {
      LogSdchProblem(filter_context, SDCH_FIXED_CONTENT_ENCODINGS);
    }
  } else {
    // Remarkable case!?!  We advertised an SDCH dictionary, content-encoding
    // was not marked for SDCH processing: Why did the server suggest an SDCH
    // dictionary in the first place??. Also, the content isn't
    // tagged as HTML, despite the fact that SDCH encoding is mostly likely for
    // HTML: Did some anti-virus system strip this tag (sometimes they strip
    // accept-encoding headers on the request)??  Does the content encoding not
    // start with "text/html" for some other reason??  We'll report this as a
    // fixup to a binary file, but it probably really is text/html (some how).
    if (encoding_types->empty()) {
      LogSdchProblem(filter_context, SDCH_BINARY_ADDED_CONTENT_ENCODING);
    } else if (1 == encoding_types->size()) {
      LogSdchProblem(filter_context, SDCH_BINARY_FIXED_CONTENT_ENCODING);
    } else {
      LogSdchProblem(filter_context, SDCH_BINARY_FIXED_CONTENT_ENCODINGS);
    }
  }

  // Leave the existing encoding type to be processed first, and add our
  // tentative decodings to be done afterwards. Vodaphone UK reportedyl will
  // perform a second layer of gzip encoding atop the server's sdch,gzip
  // encoding, and then claim that the content encoding is a mere gzip. As a
  // result we'll need (in that case) to do the gunzip, plus our tentative
  // gunzip and tentative SDCH decoding.
  // This approach nicely handles the empty() list as well, and should work with
  // other (as yet undiscovered) proxies the choose to re-compressed with some
  // other encoding (such as bzip2, etc.).
  encoding_types->insert(encoding_types->begin(),
                         FILTER_TYPE_GZIP_HELPING_SDCH);
  encoding_types->insert(encoding_types->begin(), FILTER_TYPE_SDCH_POSSIBLE);
  return;
}

std::string Filter::OrderedFilterList() const {
  if (next_filter_) {
    return FilterTypeAsString(type_id_) + "," +
        next_filter_->OrderedFilterList();
  } else {
    return FilterTypeAsString(type_id_);
  }
}

Filter::Filter(FilterType type_id)
    : stream_buffer_(NULL),
      stream_buffer_size_(0),
      next_stream_data_(NULL),
      stream_data_len_(0),
      last_status_(FILTER_NEED_MORE_DATA),
      type_id_(type_id) {}

Filter::FilterStatus Filter::CopyOut(char* dest_buffer, int* dest_len) {
  int out_len;
  int input_len = *dest_len;
  *dest_len = 0;

  if (0 == stream_data_len_)
    return Filter::FILTER_NEED_MORE_DATA;

  out_len = std::min(input_len, stream_data_len_);
  memcpy(dest_buffer, next_stream_data_, out_len);
  *dest_len += out_len;
  stream_data_len_ -= out_len;
  if (0 == stream_data_len_) {
    next_stream_data_ = NULL;
    return Filter::FILTER_NEED_MORE_DATA;
  } else {
    next_stream_data_ += out_len;
    return Filter::FILTER_OK;
  }
}

// static
Filter* Filter::InitBrotliFilter(FilterType type_id, int buffer_size) {
  std::unique_ptr<Filter> brotli_filter(CreateBrotliFilter(type_id));
  if (!brotli_filter.get())
    return nullptr;

  brotli_filter->InitBuffer(buffer_size);
  return brotli_filter.release();
}

// static
Filter* Filter::InitGZipFilter(FilterType type_id, int buffer_size) {
  std::unique_ptr<GZipFilter> gz_filter(new GZipFilter(type_id));
  gz_filter->InitBuffer(buffer_size);
  return gz_filter->InitDecoding(type_id) ? gz_filter.release() : NULL;
}

// static
Filter* Filter::InitSdchFilter(FilterType type_id,
                               const FilterContext& filter_context,
                               int buffer_size) {
  std::unique_ptr<SdchFilter> sdch_filter(
      new SdchFilter(type_id, filter_context));
  sdch_filter->InitBuffer(buffer_size);
  return sdch_filter->InitDecoding(type_id) ? sdch_filter.release() : NULL;
}

// static
Filter* Filter::PrependNewFilter(FilterType type_id,
                                 const FilterContext& filter_context,
                                 int buffer_size,
                                 Filter* filter_list) {
  std::unique_ptr<Filter> first_filter;  // Soon to be start of chain.
  switch (type_id) {
    case FILTER_TYPE_BROTLI:
      first_filter.reset(InitBrotliFilter(type_id, buffer_size));
      break;
    case FILTER_TYPE_GZIP_HELPING_SDCH:
    case FILTER_TYPE_DEFLATE:
    case FILTER_TYPE_GZIP:
      first_filter.reset(InitGZipFilter(type_id, buffer_size));
      break;
    case FILTER_TYPE_SDCH:
    case FILTER_TYPE_SDCH_POSSIBLE:
      if (filter_context.GetURLRequestContext()->sdch_manager()) {
        first_filter.reset(
            InitSdchFilter(type_id, filter_context, buffer_size));
      }
      break;
    default:
      break;
  }

  if (!first_filter.get())
    return NULL;

  first_filter->next_filter_.reset(filter_list);
  return first_filter.release();
}

void Filter::InitBuffer(int buffer_size) {
  DCHECK(!stream_buffer());
  DCHECK_GT(buffer_size, 0);
  stream_buffer_ = new IOBuffer(buffer_size);
  stream_buffer_size_ = buffer_size;
}

void Filter::PushDataIntoNextFilter() {
  IOBuffer* next_buffer = next_filter_->stream_buffer();
  int next_size = next_filter_->stream_buffer_size();
  last_status_ = ReadFilteredData(next_buffer->data(), &next_size);
  if (FILTER_ERROR != last_status_)
    next_filter_->FlushStreamBuffer(next_size);
}

}  // namespace net
