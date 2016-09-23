// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iostream>
#include <sstream>

#include "base/files/file_util.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "build/build_config.h"
#include "tools/gn/err.h"
#include "tools/gn/filesystem_utils.h"
#include "tools/gn/functions.h"
#include "tools/gn/input_file.h"
#include "tools/gn/parse_tree.h"
#include "tools/gn/scheduler.h"

namespace functions {

const char kWriteFile[] = "write_file";
const char kWriteFile_HelpShort[] =
    "write_file: Write a file to disk.";
const char kWriteFile_Help[] =
    "write_file: Write a file to disk.\n"
    "\n"
    "  write_file(filename, data)\n"
    "\n"
    "  If data is a list, the list will be written one-item-per-line with no\n"
    "  quoting or brackets.\n"
    "\n"
    "  If the file exists and the contents are identical to that being\n"
    "  written, the file will not be updated. This will prevent unnecessary\n"
    "  rebuilds of targets that depend on this file.\n"
    "\n"
    "  One use for write_file is to write a list of inputs to an script\n"
    "  that might be too long for the command line. However, it is\n"
    "  preferrable to use response files for this purpose. See\n"
    "  \"gn help response_file_contents\".\n"
    "\n"
    "  TODO(brettw) we probably need an optional third argument to control\n"
    "  list formatting.\n"
    "\n"
    "Arguments\n"
    "\n"
    "  filename\n"
    "      Filename to write. This must be within the output directory.\n"
    "\n"
    "  data:\n"
    "      The list or string to write.\n";

Value RunWriteFile(Scope* scope,
                   const FunctionCallNode* function,
                   const std::vector<Value>& args,
                   Err* err) {
  if (args.size() != 2) {
    *err = Err(function->function(), "Wrong number of arguments to write_file",
               "I expected two arguments.");
    return Value();
  }

  // Compute the file name and make sure it's in the output dir.
  const SourceDir& cur_dir = scope->GetSourceDir();
  SourceFile source_file = cur_dir.ResolveRelativeFile(args[0], err,
      scope->settings()->build_settings()->root_path_utf8());
  if (err->has_error())
    return Value();
  if (!EnsureStringIsInOutputDir(
          scope->settings()->build_settings()->build_dir(),
          source_file.value(), args[0].origin(), err))
    return Value();
  g_scheduler->AddWrittenFile(source_file);  // Track that we wrote this file.

  // Track how to recreate this file, since we write it a gen time.
  // Note this is a hack since the correct output is not a dependency proper,
  // but an addition of this file to the output of the gn rule that writes it.
  // This dependency will, however, cause the gen step to be re-run and the
  // build restarted if the file is missing.
  g_scheduler->AddGenDependency(
      scope->settings()->build_settings()->GetFullPath(source_file));

  // Compute output.
  std::ostringstream contents;
  if (args[1].type() == Value::LIST) {
    const std::vector<Value>& list = args[1].list_value();
    for (const auto& cur : list)
      contents << cur.ToString(false) << std::endl;
  } else {
    contents << args[1].ToString(false);
  }

  base::FilePath file_path =
      scope->settings()->build_settings()->GetFullPath(source_file);

  // Make sure we're not replacing the same contents.
  if (!WriteFileIfChanged(file_path, contents.str(), err))
    *err = Err(function->function(), err->message(), err->help_text());

  return Value();
}

}  // namespace functions
