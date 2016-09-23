// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <iterator>
#include <set>
#include <vector>

#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "tools/gn/analyzer.h"
#include "tools/gn/commands.h"
#include "tools/gn/filesystem_utils.h"
#include "tools/gn/location.h"
#include "tools/gn/setup.h"

namespace commands {

const char kAnalyze[] = "analyze";
const char kAnalyze_HelpShort[] =
    "analyze: Analyze which targets are affected by a list of files.";
const char kAnalyze_Help[] =
    "gn analyze <out_dir> <input_path> <output_path>\n"
    "\n"
    "  Analyze which targets are affected by a list of files.\n"
    "\n"
    "  This command takes three arguments:\n"
    "\n"
    "  out_dir is the path to the build directory.\n"
    "\n"
    "  input_path is a path to a file containing a JSON object with three\n"
    "  fields:\n"
    "\n"
    "   - \"files\": A list of the filenames to check.\n"
    "\n"
    "   - \"test_targets\": A list of the labels for targets that\n"
    "     are needed to run the tests we wish to run.\n"
    "\n"
    "   - \"additional_compile_targets\": A list of the labels for\n"
    "     targets that we wish to rebuild, but aren't necessarily needed\n"
    "     for testing. The important difference between this field and\n"
    "     \"test_targets\" is that if an item in the\n"
    "     additional_compile_targets list refers to a group, then\n"
    "     any dependencies of that group will be returned if they are out\n"
    "     of date, but the group itself does not need to be. If the\n"
    "     dependencies themselves are groups, the same filtering is\n"
    "     repeated. This filtering can be used to avoid rebuilding\n"
    "     dependencies of a group that are unaffected by the input files.\n"
    "     The list may also contain the string \"all\" to refer to a\n"
    "     pseudo-group that contains every root target in the build\n"
    "     graph.\n"
    "\n"
    "     This filtering behavior is also known as \"pruning\" the list\n"
    "     of compile targets.\n"
    "\n"
    "  output_path is a path indicating where the results of the command\n"
    "  are to be written. The results will be a file containing a JSON\n"
    "  object with one or more of following fields:\n"
    "\n"
    "   - \"compile_targets\": A list of the labels derived from the input\n"
    "     compile_targets list that are affected by the input files.\n"
    "     Due to the way the filtering works for compile targets as\n"
    "     described above, this list may contain targets that do not appear\n"
    "     in the input list.\n"
    "\n"
    "   - \"test_targets\": A list of the labels from the input\n"
    "     test_targets list that are affected by the input files. This list\n"
    "     will be a proper subset of the input list.\n"
    "\n"
    "   - \"invalid_targets\": A list of any names from the input that\n"
    "     do not exist in the build graph. If this list is non-empty,\n"
    "     the \"error\" field will also be set to \"Invalid targets\".\n"
    "\n"
    "   - \"status\": A string containing one of three values:\n"
    "\n"
    "       - \"Found dependency\"\n"
    "       - \"No dependency\"\n"
    "       - \"Found dependency (all)\"\n"
    "\n"
    "     In the first case, the lists returned in compile_targets and\n"
    "     test_targets should be passed to ninja to build. In the second\n"
    "     case, nothing was affected and no build is necessary. In the third\n"
    "     case, GN could not determine the correct answer and returned the\n"
    "     input as the output in order to be safe.\n"
    "\n"
    "   - \"error\": This will only be present if an error occurred, and\n"
    "     will contain a string describing the error. This includes cases\n"
    "     where the input file is not in the right format, or contains\n"
    "     invalid targets.\n"

    "  The command returns 1 if it is unable to read the input file or write\n"
    "  the output file, or if there is something wrong with the build such\n"
    "  that gen would also fail, and 0 otherwise. In particular, it returns\n"
    "  0 even if the \"error\" key is non-empty and a non-fatal error\n"
    "  occurred. In other words, it tries really hard to always write\n"
    "  something to the output JSON and convey errors that way rather than\n"
    "  via return codes.\n";

int RunAnalyze(const std::vector<std::string>& args) {
  if (args.size() != 3) {
    Err(Location(), "You're holding it wrong.",
        "Usage: \"gn analyze <out_dir> <input_path> <output_path>")
        .PrintToStdout();
    return 1;
  }

  std::string input;
  bool ret = base::ReadFileToString(UTF8ToFilePath(args[1]), &input);
  if (!ret) {
    Err(Location(), "Input file " + args[1] + " not found.").PrintToStdout();
    return 1;
  }

  Setup* setup = new Setup;
  setup->build_settings().set_check_for_bad_items(false);
  if (!setup->DoSetup(args[0], false) || !setup->Run())
    return 1;

  Analyzer analyzer(setup->builder());

  Err err;
  std::string output = Analyzer(setup->builder()).Analyze(input, &err);
  if (err.has_error()) {
    err.PrintToStdout();
    return 1;
  }

  WriteFile(UTF8ToFilePath(args[2]), output, &err);
  if (err.has_error()) {
    err.PrintToStdout();
    return 1;
  }

  return 0;
}

}  // namespace commands
