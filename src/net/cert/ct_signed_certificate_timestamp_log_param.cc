// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/cert/ct_signed_certificate_timestamp_log_param.h"

#include <algorithm>
#include <memory>
#include <string>
#include <utility>

#include "base/base64.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/stringprintf.h"
#include "base/values.h"
#include "net/cert/ct_sct_to_string.h"
#include "net/cert/ct_verify_result.h"
#include "net/cert/signed_certificate_timestamp.h"

namespace net {

namespace {

// Base64 encode the given |value| string and put it in |dict| with the
// description |key|.
void SetBinaryData(
    const char* key,
    const std::string& value,
    base::DictionaryValue* dict) {
  std::string b64_value;
  base::Base64Encode(value, &b64_value);

  dict->SetString(key, b64_value);
}

// Returns a dictionary where each key is a field of the SCT and its value
// is this field's value in the SCT. This dictionary is meant to be used for
// outputting a de-serialized SCT to the NetLog.
std::unique_ptr<base::DictionaryValue> SCTToDictionary(
    const ct::SignedCertificateTimestamp& sct) {
  std::unique_ptr<base::DictionaryValue> out(new base::DictionaryValue());

  out->SetString("origin", OriginToString(sct.origin));
  out->SetInteger("version", sct.version);

  SetBinaryData("log_id", sct.log_id, out.get());
  base::TimeDelta time_since_unix_epoch =
      sct.timestamp - base::Time::UnixEpoch();
  out->SetString("timestamp",
      base::Int64ToString(time_since_unix_epoch.InMilliseconds()));
  SetBinaryData("extensions", sct.extensions, out.get());

  out->SetString("hash_algorithm",
                 HashAlgorithmToString(sct.signature.hash_algorithm));
  out->SetString("signature_algorithm",
                 SignatureAlgorithmToString(sct.signature.signature_algorithm));
  SetBinaryData("signature_data", sct.signature.signature_data, out.get());

  return out;
}

// Given a list of SCTs, return a ListValue instance where each item in the
// list is a dictionary created by SCTToDictionary.
std::unique_ptr<base::ListValue> SCTListToPrintableValues(
    const ct::SCTList& sct_list) {
  std::unique_ptr<base::ListValue> output_scts(new base::ListValue());
  for (const auto& sct : sct_list)
    output_scts->Append(SCTToDictionary(*(sct.get())));

  return output_scts;
}

}  // namespace

std::unique_ptr<base::Value> NetLogSignedCertificateTimestampCallback(
    const ct::CTVerifyResult* ct_result,
    NetLogCaptureMode capture_mode) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());

  dict->Set("verified_scts",
            SCTListToPrintableValues(ct_result->verified_scts));

  dict->Set("invalid_scts",
            SCTListToPrintableValues(ct_result->invalid_scts));

  dict->Set("unknown_logs_scts",
            SCTListToPrintableValues(ct_result->unknown_logs_scts));

  return std::move(dict);
}

std::unique_ptr<base::Value> NetLogRawSignedCertificateTimestampCallback(
    const std::string* embedded_scts,
    const std::string* sct_list_from_ocsp,
    const std::string* sct_list_from_tls_extension,
    NetLogCaptureMode capture_mode) {
  std::unique_ptr<base::DictionaryValue> dict(new base::DictionaryValue());

  SetBinaryData("embedded_scts", *embedded_scts, dict.get());
  SetBinaryData("scts_from_ocsp_response", *sct_list_from_ocsp, dict.get());
  SetBinaryData("scts_from_tls_extension", *sct_list_from_tls_extension,
                dict.get());

  return std::move(dict);
}

}  // namespace net
