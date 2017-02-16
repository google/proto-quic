// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "url/url_util.h"

#include <stddef.h>
#include <string.h>

#include "base/debug/leak_annotations.h"
#include "base/logging.h"
#include "base/strings/string_util.h"
#include "url/url_canon_internal.h"
#include "url/url_constants.h"
#include "url/url_file.h"
#include "url/url_util_internal.h"

namespace url {

namespace {

// Pass this enum through for methods which would like to know if whitespace
// removal is necessary.
enum WhitespaceRemovalPolicy {
  REMOVE_WHITESPACE,
  DO_NOT_REMOVE_WHITESPACE,
};

const SchemeWithType kStandardURLSchemes[] = {
    {kHttpScheme, SCHEME_WITH_PORT},
    {kHttpsScheme, SCHEME_WITH_PORT},
    // Yes, file URLs can have a hostname, so file URLs should be handled as
    // "standard". File URLs never have a port as specified by the SchemeType
    // field.
    {kFileScheme, SCHEME_WITHOUT_PORT},
    {kFtpScheme, SCHEME_WITH_PORT},
    {kGopherScheme, SCHEME_WITH_PORT},
    {kWsScheme, SCHEME_WITH_PORT},   // WebSocket.
    {kWssScheme, SCHEME_WITH_PORT},  // WebSocket secure.
    {kFileSystemScheme, SCHEME_WITHOUT_AUTHORITY},
    {kHttpSuboriginScheme, SCHEME_WITH_PORT},
    {kHttpsSuboriginScheme, SCHEME_WITH_PORT},
};

const SchemeWithType kReferrerURLSchemes[] = {
    {kHttpScheme, SCHEME_WITH_PORT},
    {kHttpsScheme, SCHEME_WITH_PORT},
    {kHttpSuboriginScheme, SCHEME_WITH_PORT},
    {kHttpsSuboriginScheme, SCHEME_WITH_PORT},
};

const char* kSecureSchemes[] = {
  kHttpsScheme,
  kAboutScheme,
  kDataScheme,
  kWssScheme,
};

const char* kLocalSchemes[] = {
  kFileScheme,
};

const char* kNoAccessSchemes[] = {
  kAboutScheme,
  kJavaScriptScheme,
  kDataScheme,
};

const char* kCORSEnabledSchemes[] = {
  kHttpScheme,
  kHttpsScheme,
  kDataScheme,
};

const char* kWebStorageSchemes[] = {
  kHttpScheme,
  kHttpsScheme,
  kFileScheme,
  kFtpScheme,
  kWsScheme,
  kWssScheme,
};

bool initialized = false;

// Lists of the currently installed standard and referrer schemes. These lists
// are lazily initialized by Initialize and are leaked on shutdown to prevent
// any destructors from being called that will slow us down or cause problems.
std::vector<SchemeWithType>* standard_schemes = nullptr;
std::vector<SchemeWithType>* referrer_schemes = nullptr;

// Similar to above, initialized by the Init*Schemes methods.
std::vector<std::string>* secure_schemes = nullptr;
std::vector<std::string>* local_schemes = nullptr;
std::vector<std::string>* no_access_schemes = nullptr;
std::vector<std::string>* cors_enabled_schemes = nullptr;
std::vector<std::string>* web_storage_schemes = nullptr;
std::vector<std::string>* csp_bypassing_schemes = nullptr;

// See the LockSchemeRegistries declaration in the header.
bool scheme_registries_locked = false;

// This template converts a given character type to the corresponding
// StringPiece type.
template<typename CHAR> struct CharToStringPiece {
};
template<> struct CharToStringPiece<char> {
  typedef base::StringPiece Piece;
};
template<> struct CharToStringPiece<base::char16> {
  typedef base::StringPiece16 Piece;
};

void InitSchemes(std::vector<std::string>** schemes,
                 const char** initial_schemes,
                 size_t size) {
  *schemes = new std::vector<std::string>(size);
  for (size_t i = 0; i < size; i++) {
    (*(*schemes))[i] = initial_schemes[i];
  }
}

void InitSchemesWithType(std::vector<SchemeWithType>** schemes,
                         const SchemeWithType* initial_schemes,
                         size_t size) {
  *schemes = new std::vector<SchemeWithType>(size);
  for (size_t i = 0; i < size; i++) {
    (*(*schemes))[i] = initial_schemes[i];
  }
}

// Given a string and a range inside the string, compares it to the given
// lower-case |compare_to| buffer.
template<typename CHAR>
inline bool DoCompareSchemeComponent(const CHAR* spec,
                                     const Component& component,
                                     const char* compare_to) {
  if (!component.is_nonempty())
    return compare_to[0] == 0;  // When component is empty, match empty scheme.
  return base::LowerCaseEqualsASCII(
      typename CharToStringPiece<CHAR>::Piece(
          &spec[component.begin], component.len),
      compare_to);
}

// Returns true and sets |type| to the SchemeType of the given scheme
// identified by |scheme| within |spec| if in |schemes|.
template<typename CHAR>
bool DoIsInSchemes(const CHAR* spec,
                   const Component& scheme,
                   SchemeType* type,
                   const std::vector<SchemeWithType>& schemes) {
  if (!scheme.is_nonempty())
    return false;  // Empty or invalid schemes are non-standard.

  for (const SchemeWithType& scheme_with_type : schemes) {
    if (base::LowerCaseEqualsASCII(typename CharToStringPiece<CHAR>::Piece(
                                       &spec[scheme.begin], scheme.len),
                                   scheme_with_type.scheme)) {
      *type = scheme_with_type.type;
      return true;
    }
  }
  return false;
}

template<typename CHAR>
bool DoIsStandard(const CHAR* spec, const Component& scheme, SchemeType* type) {
  Initialize();
  return DoIsInSchemes(spec, scheme, type, *standard_schemes);
}


template<typename CHAR>
bool DoFindAndCompareScheme(const CHAR* str,
                            int str_len,
                            const char* compare,
                            Component* found_scheme) {
  // Before extracting scheme, canonicalize the URL to remove any whitespace.
  // This matches the canonicalization done in DoCanonicalize function.
  RawCanonOutputT<CHAR> whitespace_buffer;
  int spec_len;
  const CHAR* spec = RemoveURLWhitespace(str, str_len,
                                         &whitespace_buffer, &spec_len);

  Component our_scheme;
  if (!ExtractScheme(spec, spec_len, &our_scheme)) {
    // No scheme.
    if (found_scheme)
      *found_scheme = Component();
    return false;
  }
  if (found_scheme)
    *found_scheme = our_scheme;
  return DoCompareSchemeComponent(spec, our_scheme, compare);
}

template <typename CHAR>
bool DoCanonicalize(const CHAR* spec,
                    int spec_len,
                    bool trim_path_end,
                    WhitespaceRemovalPolicy whitespace_policy,
                    CharsetConverter* charset_converter,
                    CanonOutput* output,
                    Parsed* output_parsed) {
  output->ReserveSizeIfNeeded(spec_len);

  // Remove any whitespace from the middle of the relative URL if necessary.
  // Possibly this will result in copying to the new buffer.
  RawCanonOutputT<CHAR> whitespace_buffer;
  if (whitespace_policy == REMOVE_WHITESPACE) {
    int original_len = spec_len;
    spec =
        RemoveURLWhitespace(spec, original_len, &whitespace_buffer, &spec_len);
    if (spec_len != original_len)
      output_parsed->whitespace_removed = true;
  }

  Parsed parsed_input;
#ifdef WIN32
  // For Windows, we allow things that look like absolute Windows paths to be
  // fixed up magically to file URLs. This is done for IE compatibility. For
  // example, this will change "c:/foo" into a file URL rather than treating
  // it as a URL with the protocol "c". It also works for UNC ("\\foo\bar.txt").
  // There is similar logic in url_canon_relative.cc for
  //
  // For Max & Unix, we don't do this (the equivalent would be "/foo/bar" which
  // has no meaning as an absolute path name. This is because browsers on Mac
  // & Unix don't generally do this, so there is no compatibility reason for
  // doing so.
  if (DoesBeginUNCPath(spec, 0, spec_len, false) ||
      DoesBeginWindowsDriveSpec(spec, 0, spec_len)) {
    ParseFileURL(spec, spec_len, &parsed_input);
    return CanonicalizeFileURL(spec, spec_len, parsed_input, charset_converter,
                               output, output_parsed);
  }
#endif

  Component scheme;
  if (!ExtractScheme(spec, spec_len, &scheme))
    return false;

  // This is the parsed version of the input URL, we have to canonicalize it
  // before storing it in our object.
  bool success;
  SchemeType unused_scheme_type = SCHEME_WITH_PORT;
  if (DoCompareSchemeComponent(spec, scheme, url::kFileScheme)) {
    // File URLs are special.
    ParseFileURL(spec, spec_len, &parsed_input);
    success = CanonicalizeFileURL(spec, spec_len, parsed_input,
                                  charset_converter, output, output_parsed);
  } else if (DoCompareSchemeComponent(spec, scheme, url::kFileSystemScheme)) {
    // Filesystem URLs are special.
    ParseFileSystemURL(spec, spec_len, &parsed_input);
    success = CanonicalizeFileSystemURL(spec, spec_len, parsed_input,
                                        charset_converter, output,
                                        output_parsed);

  } else if (DoIsStandard(spec, scheme, &unused_scheme_type)) {
    // All "normal" URLs.
    ParseStandardURL(spec, spec_len, &parsed_input);
    success = CanonicalizeStandardURL(spec, spec_len, parsed_input,
                                      charset_converter, output, output_parsed);

  } else if (DoCompareSchemeComponent(spec, scheme, url::kMailToScheme)) {
    // Mailto URLs are treated like standard URLs, with only a scheme, path,
    // and query.
    ParseMailtoURL(spec, spec_len, &parsed_input);
    success = CanonicalizeMailtoURL(spec, spec_len, parsed_input, output,
                                    output_parsed);

  } else {
    // "Weird" URLs like data: and javascript:.
    ParsePathURL(spec, spec_len, trim_path_end, &parsed_input);
    success = CanonicalizePathURL(spec, spec_len, parsed_input, output,
                                  output_parsed);
  }
  return success;
}

template<typename CHAR>
bool DoResolveRelative(const char* base_spec,
                       int base_spec_len,
                       const Parsed& base_parsed,
                       const CHAR* in_relative,
                       int in_relative_length,
                       CharsetConverter* charset_converter,
                       CanonOutput* output,
                       Parsed* output_parsed) {
  // Remove any whitespace from the middle of the relative URL, possibly
  // copying to the new buffer.
  RawCanonOutputT<CHAR> whitespace_buffer;
  int relative_length;
  const CHAR* relative = RemoveURLWhitespace(in_relative, in_relative_length,
                                             &whitespace_buffer,
                                             &relative_length);
  if (in_relative_length != relative_length)
    output_parsed->whitespace_removed = true;

  bool base_is_authority_based = false;
  bool base_is_hierarchical = false;
  if (base_spec &&
      base_parsed.scheme.is_nonempty()) {
    int after_scheme = base_parsed.scheme.end() + 1;  // Skip past the colon.
    int num_slashes = CountConsecutiveSlashes(base_spec, after_scheme,
                                              base_spec_len);
    base_is_authority_based = num_slashes > 1;
    base_is_hierarchical = num_slashes > 0;
  }

  SchemeType unused_scheme_type = SCHEME_WITH_PORT;
  bool standard_base_scheme =
      base_parsed.scheme.is_nonempty() &&
      DoIsStandard(base_spec, base_parsed.scheme, &unused_scheme_type);

  bool is_relative;
  Component relative_component;
  if (!IsRelativeURL(base_spec, base_parsed, relative, relative_length,
                     (base_is_hierarchical || standard_base_scheme),
                     &is_relative, &relative_component)) {
    // Error resolving.
    return false;
  }

  // Don't reserve buffer space here. Instead, reserve in DoCanonicalize and
  // ReserveRelativeURL, to enable more accurate buffer sizes.

  // Pretend for a moment that |base_spec| is a standard URL. Normally
  // non-standard URLs are treated as PathURLs, but if the base has an
  // authority we would like to preserve it.
  if (is_relative && base_is_authority_based && !standard_base_scheme) {
    Parsed base_parsed_authority;
    ParseStandardURL(base_spec, base_spec_len, &base_parsed_authority);
    if (base_parsed_authority.host.is_nonempty()) {
      RawCanonOutputT<char> temporary_output;
      bool did_resolve_succeed =
          ResolveRelativeURL(base_spec, base_parsed_authority, false, relative,
                             relative_component, charset_converter,
                             &temporary_output, output_parsed);
      // The output_parsed is incorrect at this point (because it was built
      // based on base_parsed_authority instead of base_parsed) and needs to be
      // re-created.
      DoCanonicalize(temporary_output.data(), temporary_output.length(), true,
                     REMOVE_WHITESPACE, charset_converter, output,
                     output_parsed);
      return did_resolve_succeed;
    }
  } else if (is_relative) {
    // Relative, resolve and canonicalize.
    bool file_base_scheme = base_parsed.scheme.is_nonempty() &&
        DoCompareSchemeComponent(base_spec, base_parsed.scheme, kFileScheme);
    return ResolveRelativeURL(base_spec, base_parsed, file_base_scheme, relative,
                              relative_component, charset_converter, output,
                              output_parsed);
  }

  // Not relative, canonicalize the input.
  return DoCanonicalize(relative, relative_length, true,
                        DO_NOT_REMOVE_WHITESPACE, charset_converter, output,
                        output_parsed);
}

template<typename CHAR>
bool DoReplaceComponents(const char* spec,
                         int spec_len,
                         const Parsed& parsed,
                         const Replacements<CHAR>& replacements,
                         CharsetConverter* charset_converter,
                         CanonOutput* output,
                         Parsed* out_parsed) {
  // If the scheme is overridden, just do a simple string substitution and
  // re-parse the whole thing. There are lots of edge cases that we really don't
  // want to deal with. Like what happens if I replace "http://e:8080/foo"
  // with a file. Does it become "file:///E:/8080/foo" where the port number
  // becomes part of the path? Parsing that string as a file URL says "yes"
  // but almost no sane rule for dealing with the components individually would
  // come up with that.
  //
  // Why allow these crazy cases at all? Programatically, there is almost no
  // case for replacing the scheme. The most common case for hitting this is
  // in JS when building up a URL using the location object. In this case, the
  // JS code expects the string substitution behavior:
  //   http://www.w3.org/TR/2008/WD-html5-20080610/structured.html#common3
  if (replacements.IsSchemeOverridden()) {
    // Canonicalize the new scheme so it is 8-bit and can be concatenated with
    // the existing spec.
    RawCanonOutput<128> scheme_replaced;
    Component scheme_replaced_parsed;
    CanonicalizeScheme(replacements.sources().scheme,
                       replacements.components().scheme,
                       &scheme_replaced, &scheme_replaced_parsed);

    // We can assume that the input is canonicalized, which means it always has
    // a colon after the scheme (or where the scheme would be).
    int spec_after_colon = parsed.scheme.is_valid() ? parsed.scheme.end() + 1
                                                    : 1;
    if (spec_len - spec_after_colon > 0) {
      scheme_replaced.Append(&spec[spec_after_colon],
                             spec_len - spec_after_colon);
    }

    // We now need to completely re-parse the resulting string since its meaning
    // may have changed with the different scheme.
    RawCanonOutput<128> recanonicalized;
    Parsed recanonicalized_parsed;
    DoCanonicalize(scheme_replaced.data(), scheme_replaced.length(), true,
                   REMOVE_WHITESPACE, charset_converter, &recanonicalized,
                   &recanonicalized_parsed);

    // Recurse using the version with the scheme already replaced. This will now
    // use the replacement rules for the new scheme.
    //
    // Warning: this code assumes that ReplaceComponents will re-check all
    // components for validity. This is because we can't fail if DoCanonicalize
    // failed above since theoretically the thing making it fail could be
    // getting replaced here. If ReplaceComponents didn't re-check everything,
    // we wouldn't know if something *not* getting replaced is a problem.
    // If the scheme-specific replacers are made more intelligent so they don't
    // re-check everything, we should instead re-canonicalize the whole thing
    // after this call to check validity (this assumes replacing the scheme is
    // much much less common than other types of replacements, like clearing the
    // ref).
    Replacements<CHAR> replacements_no_scheme = replacements;
    replacements_no_scheme.SetScheme(NULL, Component());
    return DoReplaceComponents(recanonicalized.data(), recanonicalized.length(),
                               recanonicalized_parsed, replacements_no_scheme,
                               charset_converter, output, out_parsed);
  }

  // TODO(csharrison): We could be smarter about size to reserve if this is done
  // in callers below, and the code checks to see which components are being
  // replaced, and with what length. If this ends up being a hot spot it should
  // be changed.
  output->ReserveSizeIfNeeded(spec_len);

  // If we get here, then we know the scheme doesn't need to be replaced, so can
  // just key off the scheme in the spec to know how to do the replacements.
  if (DoCompareSchemeComponent(spec, parsed.scheme, url::kFileScheme)) {
    return ReplaceFileURL(spec, parsed, replacements, charset_converter, output,
                          out_parsed);
  }
  if (DoCompareSchemeComponent(spec, parsed.scheme, url::kFileSystemScheme)) {
    return ReplaceFileSystemURL(spec, parsed, replacements, charset_converter,
                                output, out_parsed);
  }
  SchemeType unused_scheme_type = SCHEME_WITH_PORT;
  if (DoIsStandard(spec, parsed.scheme, &unused_scheme_type)) {
    return ReplaceStandardURL(spec, parsed, replacements, charset_converter,
                              output, out_parsed);
  }
  if (DoCompareSchemeComponent(spec, parsed.scheme, url::kMailToScheme)) {
    return ReplaceMailtoURL(spec, parsed, replacements, output, out_parsed);
  }

  // Default is a path URL.
  return ReplacePathURL(spec, parsed, replacements, output, out_parsed);
}

void DoAddScheme(const char* new_scheme, std::vector<std::string>* schemes) {
  DCHECK(schemes);
  // If this assert triggers, it means you've called Add*Scheme after
  // LockSchemeRegistries has been called (see the header file for
  // LockSchemeRegistries for more).
  //
  // This normally means you're trying to set up a new scheme too late in your
  // application's init process. Locate where your app does this initialization
  // and calls LockSchemeRegistries, and add your new scheme there.
  DCHECK(!scheme_registries_locked)
      << "Trying to add a scheme after the lists have been locked.";

  size_t scheme_len = strlen(new_scheme);
  if (scheme_len == 0)
    return;

  DCHECK_EQ(base::ToLowerASCII(new_scheme), new_scheme);
  schemes->push_back(std::string(new_scheme));
}

void DoAddSchemeWithType(const char* new_scheme,
                         SchemeType type,
                         std::vector<SchemeWithType>* schemes) {
  DCHECK(schemes);
  // If this assert triggers, it means you've called Add*Scheme after
  // LockSchemeRegistries has been called (see the header file for
  // LockSchemeRegistries for more).
  //
  // This normally means you're trying to set up a new scheme too late in your
  // application's init process. Locate where your app does this initialization
  // and calls LockSchemeRegistries, and add your new scheme there.
  DCHECK(!scheme_registries_locked)
      << "Trying to add a scheme after the lists have been locked.";

  size_t scheme_len = strlen(new_scheme);
  if (scheme_len == 0)
    return;

  DCHECK_EQ(base::ToLowerASCII(new_scheme), new_scheme);
  // Duplicate the scheme into a new buffer and add it to the list of standard
  // schemes. This pointer will be leaked on shutdown.
  char* dup_scheme = new char[scheme_len + 1];
  ANNOTATE_LEAKING_OBJECT_PTR(dup_scheme);
  memcpy(dup_scheme, new_scheme, scheme_len + 1);

  SchemeWithType scheme_with_type;
  scheme_with_type.scheme = dup_scheme;
  scheme_with_type.type = type;
  schemes->push_back(scheme_with_type);
}

}  // namespace

void Initialize() {
  if (initialized)
    return;
  InitSchemesWithType(&standard_schemes, kStandardURLSchemes,
                      arraysize(kStandardURLSchemes));
  InitSchemesWithType(&referrer_schemes, kReferrerURLSchemes,
                      arraysize(kReferrerURLSchemes));
  InitSchemes(&secure_schemes, kSecureSchemes, arraysize(kSecureSchemes));
  InitSchemes(&local_schemes, kLocalSchemes, arraysize(kLocalSchemes));
  InitSchemes(&no_access_schemes, kNoAccessSchemes,
              arraysize(kNoAccessSchemes));
  InitSchemes(&cors_enabled_schemes, kCORSEnabledSchemes,
              arraysize(kCORSEnabledSchemes));
  InitSchemes(&web_storage_schemes, kWebStorageSchemes,
              arraysize(kWebStorageSchemes));
  InitSchemes(&csp_bypassing_schemes, nullptr, 0);
  initialized = true;
}

void Shutdown() {
  initialized = false;
  delete standard_schemes;
  standard_schemes = nullptr;
  delete referrer_schemes;
  referrer_schemes = nullptr;
  delete secure_schemes;
  secure_schemes = nullptr;
  delete local_schemes;
  local_schemes = nullptr;
  delete no_access_schemes;
  no_access_schemes = nullptr;
  delete cors_enabled_schemes;
  cors_enabled_schemes = nullptr;
  delete web_storage_schemes;
  web_storage_schemes = nullptr;
  delete csp_bypassing_schemes;
  csp_bypassing_schemes = nullptr;
}

void AddStandardScheme(const char* new_scheme, SchemeType type) {
  Initialize();
  DoAddSchemeWithType(new_scheme, type, standard_schemes);
}

void AddReferrerScheme(const char* new_scheme, SchemeType type) {
  Initialize();
  DoAddSchemeWithType(new_scheme, type, referrer_schemes);
}

void AddSecureScheme(const char* new_scheme) {
  Initialize();
  DoAddScheme(new_scheme, secure_schemes);
}

const std::vector<std::string>& GetSecureSchemes() {
  Initialize();
  return *secure_schemes;
}

void AddLocalScheme(const char* new_scheme) {
  Initialize();
  DoAddScheme(new_scheme, local_schemes);
}

const std::vector<std::string>& GetLocalSchemes() {
  Initialize();
  return *local_schemes;
}

void AddNoAccessScheme(const char* new_scheme) {
  Initialize();
  DoAddScheme(new_scheme, no_access_schemes);
}

const std::vector<std::string>& GetNoAccessSchemes() {
  Initialize();
  return *no_access_schemes;
}

void AddCORSEnabledScheme(const char* new_scheme) {
  Initialize();
  DoAddScheme(new_scheme, cors_enabled_schemes);
}

const std::vector<std::string>& GetCORSEnabledSchemes() {
  Initialize();
  return *cors_enabled_schemes;
}

void AddWebStorageScheme(const char* new_scheme) {
  Initialize();
  DoAddScheme(new_scheme, web_storage_schemes);
}

const std::vector<std::string>& GetWebStorageSchemes() {
  Initialize();
  return *web_storage_schemes;
}

void AddCSPBypassingScheme(const char* new_scheme) {
  Initialize();
  DoAddScheme(new_scheme, csp_bypassing_schemes);
}

const std::vector<std::string>& GetCSPBypassingSchemes() {
  Initialize();
  return *csp_bypassing_schemes;
}

void LockSchemeRegistries() {
  scheme_registries_locked = true;
}

bool IsStandard(const char* spec, const Component& scheme) {
  SchemeType unused_scheme_type;
  return DoIsStandard(spec, scheme, &unused_scheme_type);
}

bool GetStandardSchemeType(const char* spec,
                           const Component& scheme,
                           SchemeType* type) {
  return DoIsStandard(spec, scheme, type);
}

bool IsStandard(const base::char16* spec, const Component& scheme) {
  SchemeType unused_scheme_type;
  return DoIsStandard(spec, scheme, &unused_scheme_type);
}

bool IsReferrerScheme(const char* spec, const Component& scheme) {
  Initialize();
  SchemeType unused_scheme_type;
  return DoIsInSchemes(spec, scheme, &unused_scheme_type, *referrer_schemes);
}

bool FindAndCompareScheme(const char* str,
                          int str_len,
                          const char* compare,
                          Component* found_scheme) {
  return DoFindAndCompareScheme(str, str_len, compare, found_scheme);
}

bool FindAndCompareScheme(const base::char16* str,
                          int str_len,
                          const char* compare,
                          Component* found_scheme) {
  return DoFindAndCompareScheme(str, str_len, compare, found_scheme);
}

bool DomainIs(base::StringPiece canonicalized_host,
              base::StringPiece lower_ascii_domain) {
  if (canonicalized_host.empty() || lower_ascii_domain.empty())
    return false;

  // If the host name ends with a dot but the input domain doesn't, then we
  // ignore the dot in the host name.
  size_t host_len = canonicalized_host.length();
  if (canonicalized_host.back() == '.' && lower_ascii_domain.back() != '.')
    --host_len;

  if (host_len < lower_ascii_domain.length())
    return false;

  // |host_first_pos| is the start of the compared part of the host name, not
  // start of the whole host name.
  const char* host_first_pos =
      canonicalized_host.data() + host_len - lower_ascii_domain.length();

  if (!base::LowerCaseEqualsASCII(
          base::StringPiece(host_first_pos, lower_ascii_domain.length()),
          lower_ascii_domain)) {
    return false;
  }

  // Make sure there aren't extra characters in host before the compared part;
  // if the host name is longer than the input domain name, then the character
  // immediately before the compared part should be a dot. For example,
  // www.google.com has domain "google.com", but www.iamnotgoogle.com does not.
  if (lower_ascii_domain[0] != '.' && host_len > lower_ascii_domain.length() &&
      *(host_first_pos - 1) != '.') {
    return false;
  }

  return true;
}

bool HostIsIPAddress(base::StringPiece host) {
  url::RawCanonOutputT<char, 128> ignored_output;
  url::CanonHostInfo host_info;
  url::CanonicalizeIPAddress(host.data(), Component(0, host.length()),
                             &ignored_output, &host_info);
  return host_info.IsIPAddress();
}

bool Canonicalize(const char* spec,
                  int spec_len,
                  bool trim_path_end,
                  CharsetConverter* charset_converter,
                  CanonOutput* output,
                  Parsed* output_parsed) {
  return DoCanonicalize(spec, spec_len, trim_path_end, REMOVE_WHITESPACE,
                        charset_converter, output, output_parsed);
}

bool Canonicalize(const base::char16* spec,
                  int spec_len,
                  bool trim_path_end,
                  CharsetConverter* charset_converter,
                  CanonOutput* output,
                  Parsed* output_parsed) {
  return DoCanonicalize(spec, spec_len, trim_path_end, REMOVE_WHITESPACE,
                        charset_converter, output, output_parsed);
}

bool ResolveRelative(const char* base_spec,
                     int base_spec_len,
                     const Parsed& base_parsed,
                     const char* relative,
                     int relative_length,
                     CharsetConverter* charset_converter,
                     CanonOutput* output,
                     Parsed* output_parsed) {
  return DoResolveRelative(base_spec, base_spec_len, base_parsed,
                           relative, relative_length,
                           charset_converter, output, output_parsed);
}

bool ResolveRelative(const char* base_spec,
                     int base_spec_len,
                     const Parsed& base_parsed,
                     const base::char16* relative,
                     int relative_length,
                     CharsetConverter* charset_converter,
                     CanonOutput* output,
                     Parsed* output_parsed) {
  return DoResolveRelative(base_spec, base_spec_len, base_parsed,
                           relative, relative_length,
                           charset_converter, output, output_parsed);
}

bool ReplaceComponents(const char* spec,
                       int spec_len,
                       const Parsed& parsed,
                       const Replacements<char>& replacements,
                       CharsetConverter* charset_converter,
                       CanonOutput* output,
                       Parsed* out_parsed) {
  return DoReplaceComponents(spec, spec_len, parsed, replacements,
                             charset_converter, output, out_parsed);
}

bool ReplaceComponents(const char* spec,
                       int spec_len,
                       const Parsed& parsed,
                       const Replacements<base::char16>& replacements,
                       CharsetConverter* charset_converter,
                       CanonOutput* output,
                       Parsed* out_parsed) {
  return DoReplaceComponents(spec, spec_len, parsed, replacements,
                             charset_converter, output, out_parsed);
}

void DecodeURLEscapeSequences(const char* input,
                              int length,
                              CanonOutputW* output) {
  RawCanonOutputT<char> unescaped_chars;
  for (int i = 0; i < length; i++) {
    if (input[i] == '%') {
      unsigned char ch;
      if (DecodeEscaped(input, &i, length, &ch)) {
        unescaped_chars.push_back(ch);
      } else {
        // Invalid escape sequence, copy the percent literal.
        unescaped_chars.push_back('%');
      }
    } else {
      // Regular non-escaped 8-bit character.
      unescaped_chars.push_back(input[i]);
    }
  }

  // Convert that 8-bit to UTF-16. It's not clear IE does this at all to
  // JavaScript URLs, but Firefox and Safari do.
  for (int i = 0; i < unescaped_chars.length(); i++) {
    unsigned char uch = static_cast<unsigned char>(unescaped_chars.at(i));
    if (uch < 0x80) {
      // Non-UTF-8, just append directly
      output->push_back(uch);
    } else {
      // next_ch will point to the last character of the decoded
      // character.
      int next_character = i;
      unsigned code_point;
      if (ReadUTFChar(unescaped_chars.data(), &next_character,
                      unescaped_chars.length(), &code_point)) {
        // Valid UTF-8 character, convert to UTF-16.
        AppendUTF16Value(code_point, output);
        i = next_character;
      } else {
        // If there are any sequences that are not valid UTF-8, we keep
        // invalid code points and promote to UTF-16. We copy all characters
        // from the current position to the end of the identified sequence.
        while (i < next_character) {
          output->push_back(static_cast<unsigned char>(unescaped_chars.at(i)));
          i++;
        }
        output->push_back(static_cast<unsigned char>(unescaped_chars.at(i)));
      }
    }
  }
}

void EncodeURIComponent(const char* input, int length, CanonOutput* output) {
  for (int i = 0; i < length; ++i) {
    unsigned char c = static_cast<unsigned char>(input[i]);
    if (IsComponentChar(c))
      output->push_back(c);
    else
      AppendEscapedChar(c, output);
  }
}

bool CompareSchemeComponent(const char* spec,
                            const Component& component,
                            const char* compare_to) {
  return DoCompareSchemeComponent(spec, component, compare_to);
}

bool CompareSchemeComponent(const base::char16* spec,
                            const Component& component,
                            const char* compare_to) {
  return DoCompareSchemeComponent(spec, component, compare_to);
}

}  // namespace url
