// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Based on [MS-NLMP]: NT LAN Manager (NTLM) Authentication Protocol
// Specification version 28.0 [1]. Additional NTLM reference [2].
//
// [1] https://msdn.microsoft.com/en-us/library/cc236621.aspx
// [2] http://davenport.sourceforge.net/ntlm.html

#ifndef NET_BASE_NTLM_CLIENT_H_
#define NET_BASE_NTLM_CLIENT_H_

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <string>

#include "base/strings/string16.h"
#include "base/strings/string_piece.h"
#include "net/base/net_export.h"
#include "net/ntlm/ntlm_constants.h"

namespace net {
namespace ntlm {

// Provides an implementation of an NTLMv1 Client.
//
// The implementation supports NTLMv1 with extended session security (NTLM2).
class NET_EXPORT_PRIVATE NtlmClient {
 public:
  NtlmClient();
  ~NtlmClient();

  // Returns a |Buffer| containing the Negotiate message.
  Buffer GetNegotiateMessage() const;

  // Returns a |Buffer| containing the Authenticate message. If the method
  // fails an empty |Buffer| is returned.
  //
  // |hostname| can be a short NetBIOS name or an FQDN, however the server will
  // only inspect this field if the default domain policy is to restrict NTLM.
  // In this case the hostname will be compared to a whitelist stored in this
  // group policy [1].
  // |client_challenge| must contain 8 bytes of random data.
  // |server_challenge_message| is the full content of the challenge message
  // sent by the server.
  //
  // [1] - https://technet.microsoft.com/en-us/library/jj852267(v=ws.11).aspx
  Buffer GenerateAuthenticateMessage(
      const base::string16& domain,
      const base::string16& username,
      const base::string16& password,
      const std::string& hostname,
      const uint8_t* client_challenge,
      const Buffer& server_challenge_message) const;

 private:
  // Calculates the lengths and offset for all the payloads in the message.
  void CalculatePayloadLayout(bool is_unicode,
                              const base::string16& domain,
                              const base::string16& username,
                              const std::string& hostname,
                              SecurityBuffer* lm_info,
                              SecurityBuffer* ntlm_info,
                              SecurityBuffer* domain_info,
                              SecurityBuffer* username_info,
                              SecurityBuffer* hostname_info,
                              size_t* authenticate_message_len) const;

  // Returns the length of the header part of the Authenticate message.
  // NOTE: When NTLMv2 support is added this is no longer a fixed value.
  size_t GetAuthenticateHeaderLength() const;

  // Returns the length of the NTLM response.
  // NOTE: When NTLMv2 support is added this is no longer a fixed value.
  size_t GetNtlmResponseLength() const;

  // Generates the negotiate message (which is always the same) into
  // |negotiate_message_|.
  void GenerateNegotiateMessage();

  NegotiateFlags negotiate_flags_;
  Buffer negotiate_message_;

  DISALLOW_COPY_AND_ASSIGN(NtlmClient);
};

}  // namespace ntlm
}  // namespace net

#endif  // NET_BASE_NTLM_CLIENT_H_