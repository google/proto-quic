// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/filter/sdch_policy_delegate.h"

#include "base/metrics/histogram_macros.h"
#include "base/strings/string_util.h"
#include "base/values.h"
#include "net/base/sdch_problem_codes.h"
#include "net/log/net_log.h"
#include "net/log/net_log_event_type.h"
#include "net/url_request/url_request_http_job.h"

namespace net {

namespace {

const char kRefreshHtml[] =
    "<head><META HTTP-EQUIV=\"Refresh\" CONTENT=\"0\"></head>";
// Mime types:
const char kTextHtml[] = "text/html";

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

std::unique_ptr<base::Value> NetLogResponseCorruptionDetectionCallback(
    ResponseCorruptionDetectionCause cause,
    bool cached,
    NetLogCaptureMode capture_mode) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());
  dict->SetString("cause", ResponseCorruptionDetectionCauseToString(cause));
  dict->SetBoolean("cached", cached);
  return std::move(dict);
}

void LogCorruptionDetection(const NetLogWithSource& net_log,
                            bool is_cached_content,
                            ResponseCorruptionDetectionCause cause) {
  // Use if statement rather than ?: because UMA_HISTOGRAM_ENUMERATION
  // caches the histogram name based on the call site.
  if (is_cached_content) {
    UMA_HISTOGRAM_ENUMERATION("Sdch3.ResponseCorruptionDetection.Cached", cause,
                              RESPONSE_MAX);
  } else {
    UMA_HISTOGRAM_ENUMERATION("Sdch3.ResponseCorruptionDetection.Uncached",
                              cause, RESPONSE_MAX);
  }
  net_log.AddEvent(NetLogEventType::SDCH_RESPONSE_CORRUPTION_DETECTION,
                   base::Bind(&NetLogResponseCorruptionDetectionCallback, cause,
                              is_cached_content));
}

}  // namespace

SdchPolicyDelegate::SdchPolicyDelegate(
    bool possible_pass_through,
    URLRequestHttpJob* job,
    std::string mime_type,
    const GURL& url,
    bool is_cached_content,
    SdchManager* sdch_manager,
    std::unique_ptr<SdchManager::DictionarySet> dictionary_set,
    int response_code,
    const NetLogWithSource& net_log)
    : possible_pass_through_(possible_pass_through),
      job_(job),
      mime_type_(mime_type),
      url_(url),
      is_cached_content_(is_cached_content),
      sdch_manager_(sdch_manager),
      dictionary_set_(std::move(dictionary_set)),
      response_code_(response_code),
      net_log_(net_log) {
  DCHECK(sdch_manager_);
}

SdchPolicyDelegate::~SdchPolicyDelegate() {}

// static
void SdchPolicyDelegate::FixUpSdchContentEncodings(
    const NetLogWithSource& net_log,
    const std::string& mime_type,
    SdchManager::DictionarySet* dictionary_set,
    std::vector<SourceStream::SourceType>* types) {
  if (!dictionary_set) {
    // If sdch dictionary is advertised, we might need to add some decoding, as
    // some proxies strip encoding completely.
    // It was not an SDCH request, so we'll just record stats.
    if (1 < types->size()) {
      // Multiple filters were intended to only be used for SDCH (thus far!)
      SdchManager::LogSdchProblem(net_log,
                                  SDCH_MULTIENCODING_FOR_NON_SDCH_REQUEST);
    }
    if ((1 == types->size()) && (SourceStream::TYPE_SDCH == types->front())) {
      SdchManager::LogSdchProblem(
          net_log, SDCH_SDCH_CONTENT_ENCODE_FOR_NON_SDCH_REQUEST);
    }
    return;
  }
  // If content encoding included SDCH, then everything is "relatively" fine.
  if (!types->empty() && types->front() == SourceStream::TYPE_SDCH) {
    // Some proxies (found currently in Argentina) strip the Content-Encoding
    // text from "sdch,gzip" to a mere "sdch" without modifying the compressed
    // payload.  To handle this gracefully, we simulate the "probably" deleted
    // ",gzip" by appending a tentative gzip decode, which will default to a
    // no-op pass through filter if it doesn't get gzip headers where
    // expected.
    if (1 == types->size()) {
      types->push_back(SourceStream::TYPE_GZIP_FALLBACK);
      SdchManager::LogSdchProblem(net_log, SDCH_OPTIONAL_GUNZIP_ENCODING_ADDED);
    }
    return;
  }

  // There are now several cases to handle for an SDCH request. Foremost, if
  // the outbound request was stripped so as not to advertise support for
  // encodings, we might get back content with no encoding, or (for example)
  // just gzip. We have to be sure that any changes we make allow for such
  // minimal coding to work. That issue is why we use POSSIBLE_SDCH filters,
  // as those filters sniff the content, and act as pass-through filters if
  // headers are not found. TODO(xunjieli): Currently POSSIBLE_SDCH filters
  // issue meta-refresh instead of pass-throughs to match old code. Change it
  // to do pass-throughs.

  // If the outbound GET is not modified, then the server will generally try to
  // send us SDCH encoded content. As that content returns, there are several
  // corruptions of the header "content-encoding" that proxies may perform (and
  // have been detected in the wild). We already dealt with the a honest
  // content encoding of "sdch,gzip" being corrupted into "sdch" with no change
  // of the actual content. Another common corruption is to either discard
  // the accurate content encoding, or to replace it with gzip only (again, with
  // no change in actual content). The last observed corruption it to actually
  // change the content, such as by re-gzipping it, and that may happen along
  // with corruption of the stated content encoding (wow!).

  // The one unresolved failure mode comes when we advertise a dictionary, and
  // the server tries to *send* a gzipped file (not gzip encode content), and
  // then we could do a gzip decode :-(.
  // We will gather a lot of stats as we perform the fixups.
  if (base::StartsWith(mime_type, kTextHtml,
                       base::CompareCase::INSENSITIVE_ASCII)) {
    // Suspicious case: Advertised dictionary, but server didn't use sdch, and
    // we're HTML tagged.
    if (types->empty()) {
      SdchManager::LogSdchProblem(net_log, SDCH_ADDED_CONTENT_ENCODING);
    } else if (1 == types->size()) {
      SdchManager::LogSdchProblem(net_log, SDCH_FIXED_CONTENT_ENCODING);
    } else {
      SdchManager::LogSdchProblem(net_log, SDCH_FIXED_CONTENT_ENCODINGS);
    }
  } else {
    // Remarkable case!?!  We advertised an SDCH dictionary, content-encoding
    // was not marked for SDCH processing: Why did the server suggest an SDCH
    // dictionary in the first place??. Also, the content isn't
    // tagged as HTML, despite the fact that SDCH encoding is mostly likely
    // for HTML: Did some anti-virus system strip this tag (sometimes they
    // strip accept-encoding headers on the request)??  Does the content
    // encoding not start with "text/html" for some other reason??  We'll
    // report this as a fixup to a binary file, but it probably really is
    // text/html (some how).
    if (types->empty()) {
      SdchManager::LogSdchProblem(net_log, SDCH_BINARY_ADDED_CONTENT_ENCODING);
    } else if (1 == types->size()) {
      SdchManager::LogSdchProblem(net_log, SDCH_BINARY_FIXED_CONTENT_ENCODING);
    } else {
      SdchManager::LogSdchProblem(net_log, SDCH_BINARY_FIXED_CONTENT_ENCODINGS);
    }
  }

  // Leave the existing encoding type to be processed first, and add our
  // tentative decodings to be done afterwards. Vodaphone UK reportedly will
  // perform a second layer of gzip encoding atop the server's sdch,gzip
  // encoding, and then claim that the content encoding is a mere gzip. As a
  // result we'll need (in that case) to do the gunzip, plus our tentative
  // gunzip and tentative SDCH decoding. This approach nicely handles the
  // empty() list as well, and should work with other (as yet undiscovered)
  // proxies the choose to re-compressed with some other encoding (such as
  // bzip2, etc.).
  types->insert(types->begin(), SourceStream::TYPE_GZIP_FALLBACK);
  types->insert(types->begin(), SourceStream::TYPE_SDCH_POSSIBLE);
}

// Dictionary id errors are often the first indication that the SDCH stream has
// become corrupt. There are many possible causes: non-200 response codes, a
// cached non-SDCH-ified reply, or a response that claims to be SDCH but isn't
// actually. These are handled here by issuing a meta-refresh or swapping to the
// "passthrough" mode if appropriate, or failing the request if the error is
// unrecoverable.
SdchPolicyDelegate::ErrorRecovery SdchPolicyDelegate::OnDictionaryIdError(
    std::string* replace_output) {
  if (possible_pass_through_) {
    LogCorruptionDetection(net_log_, is_cached_content_,
                           RESPONSE_TENTATIVE_SDCH);
    // Ideally we should return PASS_THROUGH here, but this is done to match
    // the old behavior in sdch_filter.cc.
  }
  // HTTP 404 might be an unencoded error page, so if decoding failed, pass it
  // through. TODO(xunjieli): Remove this. crbug.com/516773.
  if (response_code_ == 404) {
    SdchManager::LogSdchProblem(net_log_, SDCH_PASS_THROUGH_404_CODE);
    LogCorruptionDetection(net_log_, is_cached_content_, RESPONSE_404);
    return PASS_THROUGH;
  }

  // HTTP !200 gets a meta-refresh for HTML.
  // TODO(xunjieli): remove this. crbug.com/654393.
  if (response_code_ != 200) {
    LogCorruptionDetection(net_log_, is_cached_content_, RESPONSE_NOT_200);
    return IssueMetaRefreshIfPossible(replace_output);
  }

  // If this is a cached result and the source hasn't requested a dictionary, it
  // probably never had a dictionary to begin and is an unencoded response from
  // earlier.
  if (is_cached_content_) {
    SdchManager::LogSdchProblem(net_log_, SDCH_PASS_THROUGH_OLD_CACHED);
    LogCorruptionDetection(net_log_, is_cached_content_,
                           RESPONSE_OLD_UNENCODED);
    return PASS_THROUGH;
  }

  // The original request didn't advertise any dictionaries, but the
  // response claimed to be SDCH. There is no way to repair this situation: the
  // original request already didn't advertise any dictionaries, and retrying it
  // would likely have the/ same result. Blacklist the domain and try passing
  // through.
  if (!dictionary_set_) {
    sdch_manager_->BlacklistDomain(url_, SDCH_PASSING_THROUGH_NON_SDCH);
    LogCorruptionDetection(net_log_, is_cached_content_, RESPONSE_ENCODING_LIE);
    return PASS_THROUGH;
  }
  // Since SDCH dictionaries are advertised, this is a corrupt SDCH response.
  LogCorruptionDetection(net_log_, is_cached_content_, RESPONSE_CORRUPT_SDCH);
  return IssueMetaRefreshIfPossible(replace_output);
}

// Dictionary fails to load when we have a plausible dictionay id. There are
// many possible causes: a cached SDCH-ified reply for which the SdchManager did
// not have the dictionary or a corrupted response. These are handled here by
// issuing a meta-refresh except the case where response code is 404.
SdchPolicyDelegate::ErrorRecovery SdchPolicyDelegate::OnGetDictionaryError(
    std::string* replace_output) {
  if (possible_pass_through_) {
    LogCorruptionDetection(net_log_, is_cached_content_,
                           RESPONSE_TENTATIVE_SDCH);
    // Ideally we should return PASS_THROUGH here, but this is done to match
    // the old behavior in sdch_filter.cc.
  }
  // HTTP 404 might be an unencoded error page, so if decoding failed, pass it
  // through. TODO(xunjieli): Remove this case crbug.com/516773.
  if (response_code_ == 404) {
    SdchManager::LogSdchProblem(net_log_, SDCH_PASS_THROUGH_404_CODE);
    LogCorruptionDetection(net_log_, is_cached_content_, RESPONSE_404);
    return PASS_THROUGH;
  }
  SdchManager::LogSdchProblem(net_log_, SDCH_DICTIONARY_HASH_NOT_FOUND);
  LogCorruptionDetection(net_log_, is_cached_content_, RESPONSE_NO_DICTIONARY);
  return IssueMetaRefreshIfPossible(replace_output);
}

SdchPolicyDelegate::ErrorRecovery SdchPolicyDelegate::OnDecodingError(
    std::string* replace_output) {
  // A decoding error, as opposed to a dictionary error, indicates a
  // decompression failure partway through the payload of the SDCH stream,
  // which means that the filter already witnessed a valid dictionary ID and
  // successfully retrieved a dictionary for it. Decoding errors are not
  // recoverable and it is not appropriate to stop decoding, so there are
  // relatively few error cases here.
  //
  // In particular, a decoding error for an HTML payload is recoverable by
  // issuing a meta-refresh, but to avoid having that happen too often, this
  // class also temporarily blacklists the domain. A decoding error for a
  // non-HTML payload is unrecoverable, so such an error gets a permanent
  // blacklist entry. If the content was cached, no blacklisting is needed.
  // TODO(xunjieli): This case should be removed. crbug.com/651821.
  return IssueMetaRefreshIfPossible(replace_output);
}

bool SdchPolicyDelegate::OnGetDictionary(const std::string& server_id,
                                         const std::string** text) {
  if (dictionary_set_) {
    *text = dictionary_set_->GetDictionaryText(server_id);
    if (*text) {
      server_id_ = server_id;
      return true;
    }
  }
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
  SdchProblemCode rv = SDCH_OK;
  unexpected_dictionary_set_ =
      sdch_manager_->GetDictionarySetByHash(url_, server_id, &rv);
  if (unexpected_dictionary_set_) {
    *text = unexpected_dictionary_set_->GetDictionaryText(server_id);
    SdchManager::LogSdchProblem(
        net_log_, is_cached_content_ ? SDCH_UNADVERTISED_DICTIONARY_USED_CACHED
                                     : SDCH_UNADVERTISED_DICTIONARY_USED);
    if (*text) {
      server_id_ = server_id;
      return true;
    }
  }
  return false;
}

void SdchPolicyDelegate::OnStreamDestroyed(
    SdchSourceStream::InputState input_state,
    bool buffered_output_present,
    bool decoding_not_finished) {
  if (decoding_not_finished) {
    SdchManager::LogSdchProblem(net_log_, SDCH_INCOMPLETE_SDCH_CONTENT);
    // Make it possible for the user to hit reload, and get non-sdch content.
    // Note this will "wear off" quickly enough, and is just meant to assure
    // in some rare case that the user is not stuck.
    sdch_manager_->BlacklistDomain(url_, SDCH_INCOMPLETE_SDCH_CONTENT);
  }
  // Filter chaining error, or premature teardown.
  if (buffered_output_present)
    SdchManager::LogSdchProblem(net_log_, SDCH_UNFLUSHED_CONTENT);

  // Only record packet stats for non-cached content.
  if (is_cached_content_) {
    // Not a real error, but it is useful to have this tally.
    // TODO(jar): Remove this stat after SDCH stability is validated.
    SdchManager::LogSdchProblem(net_log_, SDCH_CACHE_DECODED);
    return;  // We don't need timing stats, and we aready got ratios.
  }
  switch (input_state) {
    case SdchSourceStream::STATE_DECODE: {
      job_->RecordPacketStats(StatisticSelector::SDCH_DECODE);
      // Allow latency experiments to proceed.
      sdch_manager_->SetAllowLatencyExperiment(url_, true);

      // Notify successful dictionary usage.
      DCHECK(!server_id_.empty());
      sdch_manager_->OnDictionaryUsed(server_id_);
      return;
    }
    case SdchSourceStream::STATE_LOAD_DICTIONARY:
      SdchManager::LogSdchProblem(net_log_, SDCH_PRIOR_TO_DICTIONARY);
      return;
    case SdchSourceStream::STATE_PASS_THROUGH:
      job_->RecordPacketStats(StatisticSelector::SDCH_PASSTHROUGH);
      return;
    case SdchSourceStream::STATE_OUTPUT_REPLACE:
      // This is meta refresh case. Already accounted for when set.
      return;
  }  // end of switch.
}

// TODO(xunjieli): Remove meta refresh. crbug.com/651821.
SdchPolicyDelegate::ErrorRecovery
SdchPolicyDelegate::IssueMetaRefreshIfPossible(std::string* replace_output) {
  // Errors for non-HTML payloads are unrecoverable and get the domain
  // blacklisted indefinitely.
  if (mime_type_.npos == mime_type_.find("text/html")) {
    SdchProblemCode problem =
        (is_cached_content_ ? SDCH_CACHED_META_REFRESH_UNSUPPORTED
                            : SDCH_META_REFRESH_UNSUPPORTED);
    sdch_manager_->BlacklistDomainForever(url_, problem);
    SdchManager::LogSdchProblem(net_log_, problem);
    return NONE;
  }

  if (is_cached_content_) {
    // Cached content is a probably startup tab, so just get the fresh content
    // and try again, without disabling SDCH.
    SdchManager::LogSdchProblem(net_log_, SDCH_META_REFRESH_CACHED_RECOVERY);
  } else {
    // Since it wasn't in the cache, blacklist for some period to get the
    // correct content.
    sdch_manager_->BlacklistDomain(url_, SDCH_META_REFRESH_RECOVERY);
    SdchManager::LogSdchProblem(net_log_, SDCH_META_REFRESH_RECOVERY);
  }

  *replace_output = std::string(kRefreshHtml, strlen(kRefreshHtml));
  return REPLACE_OUTPUT;
}

}  // namespace net
