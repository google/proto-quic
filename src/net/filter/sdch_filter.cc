// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/filter/sdch_filter.h"

#include <ctype.h>
#include <limits.h>
#include <algorithm>
#include <utility>

#include "base/logging.h"
#include "base/metrics/histogram_macros.h"
#include "base/values.h"
#include "net/base/sdch_manager.h"
#include "net/base/sdch_net_log_params.h"
#include "net/base/sdch_problem_codes.h"
#include "net/url_request/url_request_context.h"
#include "sdch/open-vcdiff/src/google/vcdecoder.h"

namespace net {

namespace {

const size_t kServerIdLength = 9;  // Dictionary hash plus null from server.

// Disambiguate various types of responses that trigger a meta-refresh,
// failure, or fallback to pass-through.
enum ResponseCorruptionDetectionCause {
  RESPONSE_NONE,

  // 404 Http Response Code
  RESPONSE_404 = 1,

  // Not a 200 Http Response Code
  RESPONSE_NOT_200 = 2,

  // Cached before dictionary retrieved.
  RESPONSE_OLD_UNENCODED = 3,

  // Speculative but incorrect SDCH filtering was added added.
  RESPONSE_TENTATIVE_SDCH = 4,

  // Missing correct dict for decoding.
  RESPONSE_NO_DICTIONARY = 5,

  // Not an SDCH response but should be.
  RESPONSE_CORRUPT_SDCH = 6,

  // No dictionary was advertised with the request, the server claims
  // to have encoded with SDCH anyway, but it isn't an SDCH response.
  RESPONSE_ENCODING_LIE = 7,

  RESPONSE_MAX,
};

const char* ResponseCorruptionDetectionCauseToString(
    ResponseCorruptionDetectionCause cause) {
  const char* cause_string = "<unknown>";
  switch (cause) {
    case RESPONSE_NONE:
      cause_string = "NONE";
      break;
    case RESPONSE_404:
      cause_string = "404";
      break;
    case RESPONSE_NOT_200:
      cause_string = "NOT_200";
      break;
    case RESPONSE_OLD_UNENCODED:
      cause_string = "OLD_UNENCODED";
      break;
    case RESPONSE_TENTATIVE_SDCH:
      cause_string = "TENTATIVE_SDCH";
      break;
    case RESPONSE_NO_DICTIONARY:
      cause_string = "NO_DICTIONARY";
      break;
    case RESPONSE_CORRUPT_SDCH:
      cause_string = "CORRUPT_SDCH";
      break;
    case RESPONSE_ENCODING_LIE:
      cause_string = "ENCODING_LIE";
      break;
    case RESPONSE_MAX:
      cause_string = "<Error: max enum value>";
      break;
  }
  return cause_string;
}

std::unique_ptr<base::Value> NetLogSdchResponseCorruptionDetectionCallback(
    ResponseCorruptionDetectionCause cause,
    bool cached,
    NetLogCaptureMode capture_mode) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetString("cause", ResponseCorruptionDetectionCauseToString(cause));
  dict->SetBoolean("cached", cached);
  return std::move(dict);
}

}  // namespace

SdchFilter::SdchFilter(FilterType type, const FilterContext& filter_context)
    : Filter(type),
      filter_context_(filter_context),
      decoding_status_(DECODING_UNINITIALIZED),
      dictionary_hash_(),
      dictionary_hash_is_plausible_(false),
      url_request_context_(filter_context.GetURLRequestContext()),
      dest_buffer_excess_(),
      dest_buffer_excess_index_(0),
      source_bytes_(0),
      output_bytes_(0),
      possible_pass_through_(false) {
  bool success = filter_context.GetMimeType(&mime_type_);
  DCHECK(success);
  success = filter_context.GetURL(&url_);
  DCHECK(success);
  DCHECK(url_request_context_->sdch_manager());
}

SdchFilter::~SdchFilter() {
  // All code here is for gathering stats, and can be removed when SDCH is
  // considered stable.

  // References to filter_context_ and vcdiff_streaming_decoder_ (which
  // contains a reference to the dictionary text) are safe because
  // ~URLRequestHttpJob calls URLRequestJob::DestroyFilters, destroying
  // this object before the filter context in URLRequestHttpJob and its
  // members go out of scope.

  static int filter_use_count = 0;
  ++filter_use_count;
  if (META_REFRESH_RECOVERY == decoding_status_) {
    UMA_HISTOGRAM_COUNTS("Sdch3.FilterUseBeforeDisabling", filter_use_count);
  }

  if (vcdiff_streaming_decoder_.get()) {
    if (!vcdiff_streaming_decoder_->FinishDecoding()) {
      decoding_status_ = DECODING_ERROR;
      LogSdchProblem(SDCH_INCOMPLETE_SDCH_CONTENT);
      // Make it possible for the user to hit reload, and get non-sdch content.
      // Note this will "wear off" quickly enough, and is just meant to assure
      // in some rare case that the user is not stuck.
      url_request_context_->sdch_manager()->BlacklistDomain(
          url_, SDCH_INCOMPLETE_SDCH_CONTENT);
      UMA_HISTOGRAM_COUNTS("Sdch3.PartialBytesIn",
           static_cast<int>(filter_context_.GetByteReadCount()));
      UMA_HISTOGRAM_COUNTS("Sdch3.PartialVcdiffIn", source_bytes_);
      UMA_HISTOGRAM_COUNTS("Sdch3.PartialVcdiffOut", output_bytes_);
    }
  }

  if (!dest_buffer_excess_.empty()) {
    // Filter chaining error, or premature teardown.
    LogSdchProblem(SDCH_UNFLUSHED_CONTENT);
    UMA_HISTOGRAM_COUNTS("Sdch3.UnflushedBytesIn",
         static_cast<int>(filter_context_.GetByteReadCount()));
    UMA_HISTOGRAM_COUNTS("Sdch3.UnflushedBufferSize",
                         dest_buffer_excess_.size());
    UMA_HISTOGRAM_COUNTS("Sdch3.UnflushedVcdiffIn", source_bytes_);
    UMA_HISTOGRAM_COUNTS("Sdch3.UnflushedVcdiffOut", output_bytes_);
  }

  if (filter_context_.IsCachedContent()) {
    // Not a real error, but it is useful to have this tally.
    // TODO(jar): Remove this stat after SDCH stability is validated.
    LogSdchProblem(SDCH_CACHE_DECODED);
    return;  // We don't need timing stats, and we aready got ratios.
  }

  switch (decoding_status_) {
    case DECODING_IN_PROGRESS: {
      if (output_bytes_) {
        UMA_HISTOGRAM_PERCENTAGE("Sdch3.Network_Decode_Ratio_a",
            static_cast<int>(
                (filter_context_.GetByteReadCount() * 100) / output_bytes_));
        UMA_HISTOGRAM_COUNTS("Sdch3.NetworkBytesSavedByCompression",
            output_bytes_ - source_bytes_);
      }
      UMA_HISTOGRAM_COUNTS("Sdch3.Network_Decode_Bytes_VcdiffOut_a",
                           output_bytes_);
      filter_context_.RecordPacketStats(FilterContext::SDCH_DECODE);

      // Allow latency experiments to proceed.
      url_request_context_->sdch_manager()->SetAllowLatencyExperiment(
          url_, true);

      // Notify successful dictionary usage.
      url_request_context_->sdch_manager()->OnDictionaryUsed(
          std::string(dictionary_hash_, 0, kServerIdLength - 1));

      return;
    }
    case PASS_THROUGH: {
      filter_context_.RecordPacketStats(FilterContext::SDCH_PASSTHROUGH);
      return;
    }
    case DECODING_UNINITIALIZED: {
      LogSdchProblem(SDCH_UNINITIALIZED);
      return;
    }
    case WAITING_FOR_DICTIONARY_SELECTION: {
      LogSdchProblem(SDCH_PRIOR_TO_DICTIONARY);
      return;
    }
    case DECODING_ERROR: {
      LogSdchProblem(SDCH_DECODE_ERROR);
      return;
    }
    case META_REFRESH_RECOVERY: {
      // Already accounted for when set.
      return;
    }
  }  // end of switch.
}

bool SdchFilter::InitDecoding(Filter::FilterType filter_type) {
  if (decoding_status_ != DECODING_UNINITIALIZED)
    return false;

  // Handle case  where sdch filter is guessed, but not required.
  if (FILTER_TYPE_SDCH_POSSIBLE == filter_type)
    possible_pass_through_ = true;

  // Initialize decoder only after we have a dictionary in hand.
  decoding_status_ = WAITING_FOR_DICTIONARY_SELECTION;
  return true;
}

#ifndef NDEBUG
static const char* kDecompressionErrorHtml =
  "<head><META HTTP-EQUIV=\"Refresh\" CONTENT=\"0\"></head>"
  "<div style=\"position:fixed;top:0;left:0;width:100%;border-width:thin;"
  "border-color:black;border-style:solid;text-align:left;font-family:arial;"
  "font-size:10pt;foreground-color:black;background-color:white\">"
  "An error occurred. This page will be reloaded shortly. "
  "Or press the \"reload\" button now to reload it immediately."
  "</div>";
#else
static const char* kDecompressionErrorHtml =
  "<head><META HTTP-EQUIV=\"Refresh\" CONTENT=\"0\"></head>";
#endif

Filter::FilterStatus SdchFilter::ReadFilteredData(char* dest_buffer,
                                                  int* dest_len) {
  int available_space = *dest_len;
  *dest_len = 0;  // Nothing output yet.

  if (!dest_buffer || available_space <= 0)
    return FILTER_ERROR;

  if (WAITING_FOR_DICTIONARY_SELECTION == decoding_status_) {
    FilterStatus status = InitializeDictionary();
    if (FILTER_NEED_MORE_DATA == status)
      return FILTER_NEED_MORE_DATA;
    if (FILTER_ERROR == status) {
      DCHECK_EQ(DECODING_ERROR, decoding_status_);
      DCHECK_EQ(0u, dest_buffer_excess_index_);
      DCHECK(dest_buffer_excess_.empty());
      // This is where we try very hard to do error recovery, and make this
      // protocol robust in the face of proxies that do many different things.
      // If we decide that things are looking very bad (too hard to recover),
      // we may even issue a "meta-refresh" to reload the page without an SDCH
      // advertisement (so that we are sure we're not hurting anything).
      //
      // Watch out for an error page inserted by the proxy as part of a 40x
      // error response. When we see such content molestation, we certainly
      // need to fall into the meta-refresh case.
      ResponseCorruptionDetectionCause cause = RESPONSE_NONE;
      if (filter_context_.GetResponseCode() == 404) {
        // We could be more generous, but for now, only a "NOT FOUND" code will
        // cause a pass through. All other bad codes will fall into a
        // meta-refresh.
        LogSdchProblem(SDCH_PASS_THROUGH_404_CODE);
        cause = RESPONSE_404;
        decoding_status_ = PASS_THROUGH;
      } else if (filter_context_.GetResponseCode() != 200) {
        // We need to meta-refresh, with SDCH disabled.
        cause = RESPONSE_NOT_200;
      } else if (filter_context_.IsCachedContent()
                 && !dictionary_hash_is_plausible_) {
        // We must have hit the back button, and gotten content that was fetched
        // before we *really* advertised SDCH and a dictionary.
        LogSdchProblem(SDCH_PASS_THROUGH_OLD_CACHED);
        decoding_status_ = PASS_THROUGH;
        cause = RESPONSE_OLD_UNENCODED;
      } else if (possible_pass_through_) {
        // This is the potentially most graceful response. There really was no
        // error. We were just overly cautious when we added a TENTATIVE_SDCH.
        // We added the sdch coding tag, and it should not have been added.
        // This can happen in server experiments, where the server decides
        // not to use sdch, even though there is a dictionary. To be
        // conservative, we locally added the tentative sdch (fearing that a
        // proxy stripped it!) and we must now recant (pass through).
        //
        // However.... just to be sure we don't get burned by proxies that
        // re-compress with gzip or other system, we can sniff to see if this
        // is compressed data etc. For now, we do nothing, which gets us into
        // the meta-refresh result.
        // TODO(jar): Improve robustness by sniffing for valid text that we can
        // actual use re: decoding_status_ = PASS_THROUGH;
        cause = RESPONSE_TENTATIVE_SDCH;
      } else if (dictionary_hash_is_plausible_) {
        // We need a meta-refresh since we don't have the dictionary.
        // The common cause is a restart of the browser, where we try to render
        // cached content that was saved when we had a dictionary.
        cause = RESPONSE_NO_DICTIONARY;
      } else if (filter_context_.SdchDictionariesAdvertised()) {
        // This is a very corrupt SDCH request response. We can't decode it.
        // We'll use a meta-refresh, and get content without asking for SDCH.
        // This will also progressively disable SDCH for this domain.
        cause = RESPONSE_CORRUPT_SDCH;
      } else {
        // One of the first 9 bytes precluded consideration as a hash.
        // This can't be an SDCH payload, even though the server said it was.
        // This is a major error, as the server or proxy tagged this SDCH even
        // though it is not!
        // Meta-refresh won't help, as we didn't advertise an SDCH dictionary!!
        // Worse yet, meta-refresh could lead to an infinite refresh loop.
        LogSdchProblem(SDCH_PASSING_THROUGH_NON_SDCH);
        decoding_status_ = PASS_THROUGH;
        // ... but further back-off on advertising SDCH support.
        url_request_context_->sdch_manager()->BlacklistDomain(
            url_, SDCH_PASSING_THROUGH_NON_SDCH);
        cause = RESPONSE_ENCODING_LIE;
      }
      DCHECK_NE(RESPONSE_NONE, cause);

      // Use if statement rather than ?: because UMA_HISTOGRAM_ENUMERATION
      // caches the histogram name based on the call site.
      if (filter_context_.IsCachedContent()) {
        UMA_HISTOGRAM_ENUMERATION(
            "Sdch3.ResponseCorruptionDetection.Cached", cause, RESPONSE_MAX);
      } else {
        UMA_HISTOGRAM_ENUMERATION(
            "Sdch3.ResponseCorruptionDetection.Uncached", cause, RESPONSE_MAX);
      }
      filter_context_.GetNetLog().AddEvent(
          NetLog::TYPE_SDCH_RESPONSE_CORRUPTION_DETECTION,
          base::Bind(&NetLogSdchResponseCorruptionDetectionCallback, cause,
                     filter_context_.IsCachedContent()));

      if (decoding_status_ == PASS_THROUGH) {
        dest_buffer_excess_ = dictionary_hash_;  // Send what we scanned.
      } else {
        // This is where we try to do the expensive meta-refresh.
        if (std::string::npos == mime_type_.find("text/html")) {
          // Since we can't do a meta-refresh (along with an exponential
          // backoff), we'll just make sure this NEVER happens again.
          SdchProblemCode problem = (filter_context_.IsCachedContent()
                                         ? SDCH_CACHED_META_REFRESH_UNSUPPORTED
                                         : SDCH_META_REFRESH_UNSUPPORTED);
          url_request_context_->sdch_manager()->BlacklistDomainForever(
              url_, problem);
          LogSdchProblem(problem);
          return FILTER_ERROR;
        }
        // HTML content means we can issue a meta-refresh, and get the content
        // again, perhaps without SDCH (to be safe).
        if (filter_context_.IsCachedContent()) {
          // Cached content is probably a startup tab, so we'll just get fresh
          // content and try again, without disabling sdch.
          LogSdchProblem(SDCH_META_REFRESH_CACHED_RECOVERY);
        } else {
          // Since it wasn't in the cache, we definately need at least some
          // period of blacklisting to get the correct content.
          url_request_context_->sdch_manager()->BlacklistDomain(
              url_, SDCH_META_REFRESH_RECOVERY);
          LogSdchProblem(SDCH_META_REFRESH_RECOVERY);
        }
        decoding_status_ = META_REFRESH_RECOVERY;
        // Issue a meta redirect with SDCH disabled.
        dest_buffer_excess_ = kDecompressionErrorHtml;
      }
    } else {
      DCHECK_EQ(DECODING_IN_PROGRESS, decoding_status_);
    }
  }

  int amount = OutputBufferExcess(dest_buffer, available_space);
  *dest_len += amount;
  dest_buffer += amount;
  available_space -= amount;
  DCHECK_GE(available_space, 0);

  if (available_space <= 0)
    return FILTER_OK;
  DCHECK(dest_buffer_excess_.empty());
  DCHECK_EQ(0u, dest_buffer_excess_index_);

  if (decoding_status_ != DECODING_IN_PROGRESS) {
    if (META_REFRESH_RECOVERY == decoding_status_) {
      // Absorb all input data. We've already output page reload HTML.
      next_stream_data_ = NULL;
      stream_data_len_ = 0;
      return FILTER_NEED_MORE_DATA;
    }
    if (PASS_THROUGH == decoding_status_) {
      // We must pass in available_space, but it will be changed to bytes_used.
      FilterStatus result = CopyOut(dest_buffer, &available_space);
      // Accumulate the returned count of bytes_used (a.k.a., available_space).
      *dest_len += available_space;
      return result;
    }
    DCHECK(false);
    decoding_status_ = DECODING_ERROR;
    return FILTER_ERROR;
  }

  if (!next_stream_data_ || stream_data_len_ <= 0)
    return FILTER_NEED_MORE_DATA;

  // A note on accounting: DecodeChunk() appends to its output buffer, so any
  // preexisting data in |dest_buffer_excess_| could skew the value of
  // |output_bytes_|. However, OutputBufferExcess guarantees that it will
  // consume all of |dest_buffer_excess_| when called above unless the
  // destination buffer runs out of space, and if the destination buffer runs
  // out of space, this code returns FILTER_OK early above. Therefore, if
  // execution reaches this point, |dest_buffer_excess_| is empty, which is
  // DCHECKed above.
  bool ret = vcdiff_streaming_decoder_->DecodeChunk(
    next_stream_data_, stream_data_len_, &dest_buffer_excess_);
  // Assume all data was used in decoding.
  next_stream_data_ = NULL;
  source_bytes_ += stream_data_len_;
  stream_data_len_ = 0;
  output_bytes_ += dest_buffer_excess_.size();
  if (!ret) {
    vcdiff_streaming_decoder_.reset(NULL);  // Don't call it again.
    decoding_status_ = DECODING_ERROR;
    LogSdchProblem(SDCH_DECODE_BODY_ERROR);
    return FILTER_ERROR;
  }

  amount = OutputBufferExcess(dest_buffer, available_space);
  *dest_len += amount;
  dest_buffer += amount;
  available_space -= amount;
  if (0 == available_space && !dest_buffer_excess_.empty())
      return FILTER_OK;
  return FILTER_NEED_MORE_DATA;
}

Filter::FilterStatus SdchFilter::InitializeDictionary() {
  size_t bytes_needed = kServerIdLength - dictionary_hash_.size();
  DCHECK_GT(bytes_needed, 0u);
  if (!next_stream_data_)
    return FILTER_NEED_MORE_DATA;
  if (static_cast<size_t>(stream_data_len_) < bytes_needed) {
    dictionary_hash_.append(next_stream_data_, stream_data_len_);
    next_stream_data_ = NULL;
    stream_data_len_ = 0;
    return FILTER_NEED_MORE_DATA;
  }
  dictionary_hash_.append(next_stream_data_, bytes_needed);
  DCHECK(kServerIdLength == dictionary_hash_.size());
  stream_data_len_ -= bytes_needed;
  DCHECK_LE(0, stream_data_len_);
  if (stream_data_len_ > 0)
    next_stream_data_ += bytes_needed;
  else
    next_stream_data_ = NULL;

  const std::string* dictionary_text = nullptr;
  dictionary_hash_is_plausible_ = true;  // Assume plausible, but check.

  SdchProblemCode rv = SDCH_OK;
  if ('\0' == dictionary_hash_[kServerIdLength - 1]) {
    std::string server_hash(dictionary_hash_, 0, kServerIdLength - 1);
    SdchManager::DictionarySet* handle =
        filter_context_.SdchDictionariesAdvertised();
    if (handle)
      dictionary_text = handle->GetDictionaryText(server_hash);
    if (!dictionary_text) {
      // This is a hack. Naively, the dictionaries available for
      // decoding should be only the ones advertised. However, there are
      // cases, specifically resources encoded with old dictionaries living
      // in the cache, that mean the full set of dictionaries should be made
      // available for decoding. It's not known how often this happens;
      // if it happens rarely enough, this code can be removed.
      //
      // TODO(rdsmith): Long-term, a better solution is necessary, since
      // an entry in the cache being encoded with the dictionary doesn't
      // guarantee that the dictionary is present. That solution probably
      // involves storing unencoded resources in the cache, but might
      // involve evicting encoded resources on dictionary removal.
      // See http://crbug.com/383405.
      unexpected_dictionary_handle_ =
          url_request_context_->sdch_manager()->GetDictionarySetByHash(
              url_, server_hash, &rv);
      if (unexpected_dictionary_handle_) {
        dictionary_text =
            unexpected_dictionary_handle_->GetDictionaryText(server_hash);
        // Override SDCH_OK rv; this is still worth logging.
        rv = (filter_context_.IsCachedContent() ?
              SDCH_UNADVERTISED_DICTIONARY_USED_CACHED :
              SDCH_UNADVERTISED_DICTIONARY_USED);
      } else {
        // Since dictionary was not found, check to see if hash was
        // even plausible.
        DCHECK(dictionary_hash_.size() == kServerIdLength);
        rv = SDCH_DICTIONARY_HASH_NOT_FOUND;
        for (size_t i = 0; i < kServerIdLength - 1; ++i) {
          char base64_char = dictionary_hash_[i];
          if (!isalnum(base64_char) &&
              '-' != base64_char && '_' != base64_char) {
            dictionary_hash_is_plausible_ = false;
            rv = SDCH_DICTIONARY_HASH_MALFORMED;
            break;
          }
        }
      }
    }
  } else {
    dictionary_hash_is_plausible_ = false;
    rv = SDCH_DICTIONARY_HASH_MALFORMED;
  }

  if (rv != SDCH_OK)
    LogSdchProblem(rv);

  if (!dictionary_text) {
    decoding_status_ = DECODING_ERROR;
    return FILTER_ERROR;
  }

  vcdiff_streaming_decoder_.reset(new open_vcdiff::VCDiffStreamingDecoder);
  vcdiff_streaming_decoder_->SetAllowVcdTarget(false);

  // The validity of the dictionary_text pointer is guaranteed for the
  // lifetime of the SdchFilter by the ownership of the DictionarySet by
  // the FilterContext/URLRequestHttpJob.  All URLRequestJob filters are
  // torn down in ~URLRequestHttpJob by a call to
  // URLRequestJob::DestroyFilters.
  vcdiff_streaming_decoder_->StartDecoding(dictionary_text->data(),
                                           dictionary_text->size());
  decoding_status_ = DECODING_IN_PROGRESS;
  return FILTER_OK;
}

int SdchFilter::OutputBufferExcess(char* const dest_buffer,
                                   size_t available_space) {
  if (dest_buffer_excess_.empty())
    return 0;
  DCHECK(dest_buffer_excess_.size() > dest_buffer_excess_index_);
  size_t amount = std::min(available_space,
      dest_buffer_excess_.size() - dest_buffer_excess_index_);
  memcpy(dest_buffer, dest_buffer_excess_.data() + dest_buffer_excess_index_,
         amount);
  dest_buffer_excess_index_ += amount;
  if (dest_buffer_excess_.size() <= dest_buffer_excess_index_) {
    DCHECK(dest_buffer_excess_.size() == dest_buffer_excess_index_);
    dest_buffer_excess_.clear();
    dest_buffer_excess_index_ = 0;
  }
  return amount;
}

void SdchFilter::LogSdchProblem(SdchProblemCode problem) {
  SdchManager::SdchErrorRecovery(problem);
  filter_context_.GetNetLog().AddEvent(
      NetLog::TYPE_SDCH_DECODING_ERROR,
      base::Bind(&NetLogSdchResourceProblemCallback, problem));
}

}  // namespace net
