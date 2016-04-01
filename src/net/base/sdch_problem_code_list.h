// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file intentionally does not have header guards, it's included
// inside a macro to generate enum values.

// This file contains list of sdch-related problem codes.
// No error.
SDCH_PROBLEM_CODE(OK, 0)

// Content-encoding correction problems.
SDCH_PROBLEM_CODE(ADDED_CONTENT_ENCODING, 1)
SDCH_PROBLEM_CODE(FIXED_CONTENT_ENCODING, 2)
SDCH_PROBLEM_CODE(FIXED_CONTENT_ENCODINGS, 3)

// Content decoding errors.
SDCH_PROBLEM_CODE(DECODE_HEADER_ERROR, 4)
SDCH_PROBLEM_CODE(DECODE_BODY_ERROR, 5)

// More content-encoding correction problems.
SDCH_PROBLEM_CODE(OPTIONAL_GUNZIP_ENCODING_ADDED, 6)

// Content encoding correction when we're not even tagged as HTML!?!
SDCH_PROBLEM_CODE(BINARY_ADDED_CONTENT_ENCODING, 7)
SDCH_PROBLEM_CODE(BINARY_FIXED_CONTENT_ENCODING, 8)
SDCH_PROBLEM_CODE(BINARY_FIXED_CONTENT_ENCODINGS, 9)

// Dictionary selection for use problems.
SDCH_PROBLEM_CODE(DICTIONARY_FOUND_HAS_WRONG_DOMAIN, 10)
SDCH_PROBLEM_CODE(DICTIONARY_FOUND_HAS_WRONG_PORT_LIST, 11)
SDCH_PROBLEM_CODE(DICTIONARY_FOUND_HAS_WRONG_PATH, 12)
SDCH_PROBLEM_CODE(DICTIONARY_FOUND_HAS_WRONG_SCHEME, 13)
SDCH_PROBLEM_CODE(DICTIONARY_HASH_NOT_FOUND, 14)
SDCH_PROBLEM_CODE(DICTIONARY_HASH_MALFORMED, 15)
// defunct = 16, no longer used

// Dictionary saving problems.
SDCH_PROBLEM_CODE(DICTIONARY_HAS_NO_HEADER, 20)
SDCH_PROBLEM_CODE(DICTIONARY_HEADER_LINE_MISSING_COLON, 21)
SDCH_PROBLEM_CODE(DICTIONARY_MISSING_DOMAIN_SPECIFIER, 22)
SDCH_PROBLEM_CODE(DICTIONARY_SPECIFIES_TOP_LEVEL_DOMAIN, 23)
SDCH_PROBLEM_CODE(DICTIONARY_DOMAIN_NOT_MATCHING_SOURCE_URL, 24)
SDCH_PROBLEM_CODE(DICTIONARY_PORT_NOT_MATCHING_SOURCE_URL, 25)
SDCH_PROBLEM_CODE(DICTIONARY_HAS_NO_TEXT, 26)
SDCH_PROBLEM_CODE(DICTIONARY_REFERER_URL_HAS_DOT_IN_PREFIX, 27)
SDCH_PROBLEM_CODE(DICTIONARY_UNSUPPORTED_VERSION, 28)

// Dictionary loading problems.
SDCH_PROBLEM_CODE(DICTIONARY_LOAD_ATTEMPT_FROM_DIFFERENT_HOST, 30)
SDCH_PROBLEM_CODE(DICTIONARY_SELECTED_FOR_SSL, 31)
SDCH_PROBLEM_CODE(DICTIONARY_ALREADY_LOADED, 32)
SDCH_PROBLEM_CODE(DICTIONARY_SELECTED_FROM_NON_HTTP, 33)
// defunct = 34, // Now recorded in separate histogram; see sdch_owner.cc.
// defunct = 35, // Now recorded in separate histogram; see sdch_owner.cc.
// defunct = 36, // DICTIONARY_PREVIOUSLY_SCHEDULED_TO_DOWNLOAD used instead.
// defunct = 37, // DICTIONARY_PREVIOUSLY_SCHEDULED_TO_DOWNLOAD used instead.
// defunct = 38, // No longer paying attention to URLRequest::Read return.
SDCH_PROBLEM_CODE(DICTIONARY_PREVIOUSLY_SCHEDULED_TO_DOWNLOAD, 39)

// Failsafe hack.
SDCH_PROBLEM_CODE(ATTEMPT_TO_DECODE_NON_HTTP_DATA, 40)

// More dictionary loading problems.
SDCH_PROBLEM_CODE(DICTIONARY_NO_ROOM, 44)

// Content-Encoding problems detected, with no action taken.
SDCH_PROBLEM_CODE(MULTIENCODING_FOR_NON_SDCH_REQUEST, 50)
SDCH_PROBLEM_CODE(SDCH_CONTENT_ENCODE_FOR_NON_SDCH_REQUEST, 51)

// A dictionary that wasn't advertised is being used for decoding.
SDCH_PROBLEM_CODE(UNADVERTISED_DICTIONARY_USED, 52)
SDCH_PROBLEM_CODE(UNADVERTISED_DICTIONARY_USED_CACHED, 53)

// Dictionary manager issues.
SDCH_PROBLEM_CODE(DOMAIN_BLACKLIST_INCLUDES_TARGET, 61)

// Problematic decode recovery methods.
// Dictionary not found.
SDCH_PROBLEM_CODE(META_REFRESH_RECOVERY, 70)
// defunct =  71, // Almost the same as META_REFRESH_UNSUPPORTED.
// defunct = 72,  // Almost the same as CACHED_META_REFRESH_UNSUPPORTED.
// defunct = 73,  // PASSING_THROUGH_NON_SDCH plus DISCARD_TENTATIVE_SDCH.
// Unrecoverable error.
SDCH_PROBLEM_CODE(META_REFRESH_UNSUPPORTED, 74)
// As above, but pulled from cache.
SDCH_PROBLEM_CODE(CACHED_META_REFRESH_UNSUPPORTED, 75)
// Tagged sdch but missing dictionary-hash.
SDCH_PROBLEM_CODE(PASSING_THROUGH_NON_SDCH, 76)
// Last window was not completely decoded.
SDCH_PROBLEM_CODE(INCOMPLETE_SDCH_CONTENT, 77)
// URL not found message passing through.
SDCH_PROBLEM_CODE(PASS_THROUGH_404_CODE, 78)

// This next report is very common, and not really an error scenario, but
// it exercises the error recovery logic.
// Back button got pre-SDCH cached content.
SDCH_PROBLEM_CODE(PASS_THROUGH_OLD_CACHED, 79)

// Common decoded recovery methods.
// Probably startup tab loading.
SDCH_PROBLEM_CODE(META_REFRESH_CACHED_RECOVERY, 80)
// defunct = 81, // Now tracked by ResponseCorruptionDetectionCause histo.

// Non SDCH problems, only accounted for to make stat counting complete
// (i.e., be able to be sure all dictionary advertisements are accounted
// for).
// Possible error in filter chaining.
SDCH_PROBLEM_CODE(UNFLUSHED_CONTENT, 90)
// defunct = 91,           // MISSING_TIME_STATS (Should never happen.)
// No timing stats recorded.
SDCH_PROBLEM_CODE(CACHE_DECODED, 92)
// defunct = 93,           // OVER_10_MINUTES (No timing stats recorded.)
// Filter never even got initialized.
SDCH_PROBLEM_CODE(UNINITIALIZED, 94)
// We hadn't even parsed a dictionary selector.
SDCH_PROBLEM_CODE(PRIOR_TO_DICTIONARY, 95)
// Something went wrong during decode.
SDCH_PROBLEM_CODE(DECODE_ERROR, 96)

// Problem during the latency test.
// SDCH now failing, but it worked before!
SDCH_PROBLEM_CODE(LATENCY_TEST_DISALLOWED, 100)

// General SDCH problems.
// SDCH is enabled or disabled per URLRequestContext now so this value is never
// used.
// SDCH_PROBLEM_CODE(DISABLED, 105)

// SDCH always supports secure schemes now, so this enum value is unused.
// SDCH_PROBLEM_CODE(SECURE_SCHEME_NOT_SUPPORTED, 106)

// A dictionary used notification occurred after dictionary deletion.
SDCH_PROBLEM_CODE(DICTIONARY_USED_AFTER_DELETION, 107)

// Used to bound histogram.
SDCH_PROBLEM_CODE(MAX_PROBLEM_CODE, 110)

// These values are not used in histograms.
