// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iostream>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "base/message_loop/message_loop.h"
#include "base/time/time.h"
#include "net/tools/cert_verify_tool/cert_verify_tool_util.h"
#include "net/tools/cert_verify_tool/verify_using_cert_verify_proc.h"
#include "net/tools/cert_verify_tool/verify_using_path_builder.h"

namespace {

const char kUsage[] =
    " [flags] <target/chain>\n"
    "\n"
    " <target/chain> is a file containing certificates [1]. Minimally it\n"
    " contains the target certificate. Optionally it may subsequently list\n"
    " additional certificates needed to build a chain (this is equivalent to\n"
    " specifying them through --intermediates)\n"
    "\n"
    "Flags:\n"
    "\n"
    " --hostname=<hostname>\n"
    "      The hostname required to match the end-entity certificate.\n"
    "      Required for the CertVerifyProc implementation.\n"
    "\n"
    " --roots=<certs path>\n"
    "      <certs path> is a file containing certificates [1] to interpret as\n"
    "      trust anchors (without any anchor constraints).\n"
    "\n"
    " --intermediates=<certs path>\n"
    "      <certs path> is a file containing certificates [1] for use when\n"
    "      path building is looking for intermediates.\n"
    "\n"
    " --time=<time>\n"
    "      Use <time> instead of the current system time. <time> is\n"
    "      interpreted in local time if a timezone is not specified.\n"
    "      Many common formats are supported, including:\n"
    "        1994-11-15 12:45:26 GMT\n"
    "        Tue, 15 Nov 1994 12:45:26 GMT\n"
    "        Nov 15 12:45:26 1994 GMT\n"
    "\n"
    " --dump=<file prefix>\n"
    "      Dumps the verified chain to PEM files starting with\n"
    "      <file prefix>.\n"
    "\n"
    "\n"
    "[1] A \"file containing certificates\" means a path to a file that can\n"
    "    either be:\n"
    "    * A binary file containing a single DER-encoded RFC 5280 Certificate\n"
    "    * A PEM file containing one or more CERTIFICATE blocks (DER-encoded\n"
    "      RFC 5280 Certificate)\n";

void PrintUsage(const char* argv0) {
  std::cerr << "Usage: " << argv0 << kUsage;

  // TODO(mattm): allow <certs path> to be a directory containing DER/PEM files?
  // TODO(mattm): allow target to specify an HTTPS URL to check the cert of?
  // TODO(mattm): allow target to be a verify_certificate_chain_unittest PEM
  // file?
}

}  // namespace

int main(int argc, char** argv) {
  base::AtExitManager at_exit_manager;
  // TODO(eroman): Is this needed?
  base::MessageLoopForIO message_loop;
  if (!base::CommandLine::Init(argc, argv)) {
    std::cerr << "ERROR in CommandLine::Init\n";
    return 1;
  }
  base::CommandLine& command_line = *base::CommandLine::ForCurrentProcess();
  logging::LoggingSettings settings;
  settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
  logging::InitLogging(settings);

  base::CommandLine::StringVector args = command_line.GetArgs();
  if (args.size() != 1U || command_line.HasSwitch("help")) {
    PrintUsage(argv[0]);
    return 1;
  }

  std::string hostname = command_line.GetSwitchValueASCII("hostname");

  base::Time verify_time;
  std::string time_flag = command_line.GetSwitchValueASCII("time");
  if (!time_flag.empty()) {
    if (!base::Time::FromString(time_flag.c_str(), &verify_time)) {
      std::cerr << "Error parsing --time flag\n";
      return 1;
    }
  } else {
    verify_time = base::Time::Now();
  }

  base::FilePath roots_path = command_line.GetSwitchValuePath("roots");
  base::FilePath intermediates_path =
      command_line.GetSwitchValuePath("intermediates");
  base::FilePath target_path = base::FilePath(args[0]);

  base::FilePath dump_prefix_path = command_line.GetSwitchValuePath("dump");

  std::vector<CertInput> root_der_certs;
  std::vector<CertInput> intermediate_der_certs;
  CertInput target_der_cert;

  if (!roots_path.empty())
    ReadCertificatesFromFile(roots_path, &root_der_certs);
  if (!intermediates_path.empty())
    ReadCertificatesFromFile(intermediates_path, &intermediate_der_certs);

  if (!ReadChainFromFile(target_path, &target_der_cert,
                         &intermediate_der_certs)) {
    std::cerr << "ERROR: Couldn't read certificate chain\n";
    return 1;
  }

  if (target_der_cert.der_cert.empty()) {
    std::cerr << "ERROR: no target cert\n";
    return 1;
  }

  // TODO(eroman): Also use CertVerifyProcBuiltin.

  std::cout << "CertVerifyProc:\n";
  bool cert_verify_proc_ok = true;
  if (!time_flag.empty()) {
    std::cerr << "ERROR: --time is not supported with CertVerifyProc, "
                 "skipping.\n";
  } else if (hostname.empty()) {
    std::cerr << "ERROR: --hostname is required for CertVerifyProc, skipping\n";
  } else {
    cert_verify_proc_ok = VerifyUsingCertVerifyProc(
        target_der_cert, hostname, intermediate_der_certs, root_der_certs,
        dump_prefix_path);
  }

  std::cout << "\nCertPathBuilder:\n";

  if (!hostname.empty()) {
    std::cerr
        << "WARNING: --hostname is not yet verified with CertPathBuilder\n";
  }

  bool path_builder_ok =
      VerifyUsingPathBuilder(target_der_cert, intermediate_der_certs,
                             root_der_certs, verify_time, dump_prefix_path);

  return (cert_verify_proc_ok && path_builder_ok) ? 0 : 1;
}
