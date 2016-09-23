// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <set>

#include "base/command_line.h"
#include "tools/gn/commands.h"
#include "tools/gn/label_pattern.h"
#include "tools/gn/setup.h"
#include "tools/gn/standard_out.h"
#include "tools/gn/switches.h"
#include "tools/gn/target.h"

namespace commands {

const char kLs[] = "ls";
const char kLs_HelpShort[] =
    "ls: List matching targets.";
const char kLs_Help[] =
    "gn ls <out_dir> [<label_pattern>] [--all-toolchains] [--as=...]\n"
    "      [--type=...] [--testonly=...]\n"
    "\n"
    "  Lists all targets matching the given pattern for the given build\n"
    "  directory. By default, only targets in the default toolchain will\n"
    "  be matched unless a toolchain is explicitly supplied.\n"
    "\n"
    "  If the label pattern is unspecified, list all targets. The label\n"
    "  pattern is not a general regular expression (see\n"
    "  \"gn help label_pattern\"). If you need more complex expressions,\n"
    "  pipe the result through grep.\n"
    "\n"
    "Options\n"
    "\n"
    TARGET_PRINTING_MODE_COMMAND_LINE_HELP
    "\n"
    ALL_TOOLCHAINS_SWITCH_HELP
    "\n"
    TARGET_TESTONLY_FILTER_COMMAND_LINE_HELP
    "\n"
    TARGET_TYPE_FILTER_COMMAND_LINE_HELP
    "\n"
    "Examples\n"
    "\n"
    "  gn ls out/Debug\n"
    "      Lists all targets in the default toolchain.\n"
    "\n"
    "  gn ls out/Debug \"//base/*\"\n"
    "      Lists all targets in the directory base and all subdirectories.\n"
    "\n"
    "  gn ls out/Debug \"//base:*\"\n"
    "      Lists all targets defined in //base/BUILD.gn.\n"
    "\n"
    "  gn ls out/Debug //base --as=output\n"
    "      Lists the build output file for //base:base\n"
    "\n"
    "  gn ls out/Debug --type=executable\n"
    "      Lists all executables produced by the build.\n"
    "\n"
    "  gn ls out/Debug \"//base/*\" --as=output | xargs ninja -C out/Debug\n"
    "      Builds all targets in //base and all subdirectories.\n"
    "\n"
    "  gn ls out/Debug //base --all-toolchains\n"
    "      Lists all variants of the target //base:base (it may be referenced\n"
    "      in multiple toolchains).\n";

int RunLs(const std::vector<std::string>& args) {
  if (args.size() == 0) {
    Err(Location(), "You're holding it wrong.",
        "Usage: \"gn ls <build dir> [<label_pattern>]*\"").PrintToStdout();
    return 1;
  }

  Setup* setup = new Setup;
  setup->build_settings().set_check_for_bad_items(false);
  if (!setup->DoSetup(args[0], false) || !setup->Run())
    return 1;

  const base::CommandLine* cmdline = base::CommandLine::ForCurrentProcess();
  bool all_toolchains = cmdline->HasSwitch(switches::kAllToolchains);

  std::vector<const Target*> matches;
  if (args.size() > 1) {
    // Some patterns or explicit labels were specified.
    std::vector<std::string> inputs(args.begin() + 1, args.end());

    UniqueVector<const Target*> target_matches;
    UniqueVector<const Config*> config_matches;
    UniqueVector<const Toolchain*> toolchain_matches;
    UniqueVector<SourceFile> file_matches;
    if (!ResolveFromCommandLineInput(setup, inputs, all_toolchains,
                                     &target_matches, &config_matches,
                                     &toolchain_matches, &file_matches))
      return 1;
    matches.insert(matches.begin(),
                   target_matches.begin(), target_matches.end());
  } else if (all_toolchains) {
    // List all resolved targets.
    matches = setup->builder().GetAllResolvedTargets();
  } else {
    // List all resolved targets in the default toolchain.
    for (auto* target : setup->builder().GetAllResolvedTargets()) {
      if (target->settings()->is_default())
        matches.push_back(target);
    }
  }
  FilterAndPrintTargets(false, &matches);
  return 0;
}

}  // namespace commands
