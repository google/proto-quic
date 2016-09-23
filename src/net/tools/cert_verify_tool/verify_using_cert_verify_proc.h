// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_TOOLS_CERT_VERIFY_TOOL_VERIFY_USING_CERT_VERIFY_PROC_H_
#define NET_TOOLS_CERT_VERIFY_TOOL_VERIFY_USING_CERT_VERIFY_PROC_H_

#include <string>
#include <vector>

namespace base {
class FilePath;
}

struct CertInput;

// Verifies |target_der_cert| using CertVerifyProc. Returns true if the
// certificate verified successfully, false if it failed to verify or there was
// some other error.
// Informational messages will be printed to stdout/stderr as appropriate.
bool VerifyUsingCertVerifyProc(
    const CertInput& target_der_cert,
    const std::string& hostname,
    const std::vector<CertInput>& intermediate_der_certs,
    const std::vector<CertInput>& root_der_certs,
    const base::FilePath& dump_prefix_path);

#endif  // NET_TOOLS_CERT_VERIFY_TOOL_VERIFY_USING_CERT_VERIFY_PROC_H_
