// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>

#include "base/command_line.h"
#include "base/strings/stringprintf.h"
#include "tools/gn/commands.h"
#include "tools/gn/header_checker.h"
#include "tools/gn/setup.h"
#include "tools/gn/standard_out.h"
#include "tools/gn/switches.h"
#include "tools/gn/target.h"
#include "tools/gn/trace.h"

namespace commands {

const char kNoGnCheck_Help[] =
    "nogncheck: Skip an include line from checking.\n"
    "\n"
    "  GN's header checker helps validate that the includes match the build\n"
    "  dependency graph. Sometimes an include might be conditional or\n"
    "  otherwise problematic, but you want to specifically allow it. In this\n"
    "  case, it can be whitelisted.\n"
    "\n"
    "  Include lines containing the substring \"nogncheck\" will be excluded\n"
    "  from header checking. The most common case is a conditional include:\n"
    "\n"
    "    #if defined(ENABLE_DOOM_MELON)\n"
    "    #include \"tools/doom_melon/doom_melon.h\"  // nogncheck\n"
    "    #endif\n"
    "\n"
    "  If the build file has a conditional dependency on the corresponding\n"
    "  target that matches the conditional include, everything will always\n"
    "  link correctly:\n"
    "\n"
    "    source_set(\"mytarget\") {\n"
    "      ...\n"
    "      if (enable_doom_melon) {\n"
    "        defines = [ \"ENABLE_DOOM_MELON\" ]\n"
    "        deps += [ \"//tools/doom_melon\" ]\n"
    "      }\n"
    "\n"
    "  But GN's header checker does not understand preprocessor directives,\n"
    "  won't know it matches the build dependencies, and will flag this\n"
    "  include as incorrect when the condition is false.\n"
    "\n"
    "More information\n"
    "\n"
    "  The topic \"gn help check\" has general information on how checking\n"
    "  works and advice on fixing problems. Targets can also opt-out of\n"
    "  checking, see \"gn help check_includes\".\n";

const char kCheck[] = "check";
const char kCheck_HelpShort[] =
    "check: Check header dependencies.";
const char kCheck_Help[] =
    "gn check <out_dir> [<label_pattern>] [--force]\n"
    "\n"
    "  GN's include header checker validates that the includes for C-like\n"
    "  source files match the build dependency graph.\n"
    "\n"
    "  \"gn check\" is the same thing as \"gn gen\" with the \"--check\" flag\n"
    "  except that this command does not write out any build files. It's\n"
    "  intended to be an easy way to manually trigger include file checking.\n"
    "\n"
    "  The <label_pattern> can take exact labels or patterns that match more\n"
    "  than one (although not general regular expressions). If specified,\n"
    "  only those matching targets will be checked. See\n"
    "  \"gn help label_pattern\" for details.\n"
    "\n"
    "Command-specific switches\n"
    "\n"
    "  --force\n"
    "      Ignores specifications of \"check_includes = false\" and checks\n"
    "      all target's files that match the target label.\n"
    "\n"
    "What gets checked\n"
    "\n"
    "  The .gn file may specify a list of targets to be checked. Only these\n"
    "  targets will be checked if no label_pattern is specified on the\n"
    "  command line. Otherwise, the command-line list is used instead. See\n"
    "  \"gn help dotfile\".\n"
    "\n"
    "  Targets can opt-out from checking with \"check_includes = false\"\n"
    "  (see \"gn help check_includes\").\n"
    "\n"
    "  For targets being checked:\n"
    "\n"
    "    - GN opens all C-like source files in the targets to be checked and\n"
    "      scans the top for includes.\n"
    "\n"
    "    - Includes with a \"nogncheck\" annotation are skipped (see\n"
    "      \"gn help nogncheck\").\n"
    "\n"
    "    - Only includes using \"quotes\" are checked. <brackets> are assumed\n"
    "      to be system includes.\n"
    "\n"
    "    - Include paths are assumed to be relative to either the source root\n"
    "      or the \"root_gen_dir\" and must include all the path components.\n"
    "      (It might be nice in the future to incorporate GN's knowledge of\n"
    "      the include path to handle other include styles.)\n"
    "\n"
    "    - GN does not run the preprocessor so will not understand\n"
    "      conditional includes.\n"
    "\n"
    "    - Only includes matching known files in the build are checked:\n"
    "      includes matching unknown paths are ignored.\n"
    "\n"
    "  For an include to be valid:\n"
    "\n"
    "    - The included file must be in the current target, or there must\n"
    "      be a path following only public dependencies to a target with the\n"
    "      file in it (\"gn path\" is a good way to diagnose problems).\n"
    "\n"
    "    - There can be multiple targets with an included file: only one\n"
    "      needs to be valid for the include to be allowed.\n"
    "\n"
    "    - If there are only \"sources\" in a target, all are considered to\n"
    "      be public and can be included by other targets with a valid public\n"
    "      dependency path.\n"
    "\n"
    "    - If a target lists files as \"public\", only those files are\n"
    "      able to be included by other targets. Anything in the sources\n"
    "      will be considered private and will not be includable regardless\n"
    "      of dependency paths.\n"
    "\n"
    "    - Ouptuts from actions are treated like public sources on that\n"
    "      target.\n"
    "\n"
    "    - A target can include headers from a target that depends on it\n"
    "      if the other target is annotated accordingly. See\n"
    "      \"gn help allow_circular_includes_from\".\n"
    "\n"
    "Advice on fixing problems\n"
    "\n"
    "  If you have a third party project that uses relative includes,\n"
    "  it's generally best to exclude that target from checking altogether\n"
    "  via \"check_includes = false\".\n"
    "\n"
    "  If you have conditional includes, make sure the build conditions\n"
    "  and the preprocessor conditions match, and annotate the line with\n"
    "  \"nogncheck\" (see \"gn help nogncheck\" for an example).\n"
    "\n"
    "  If two targets are hopelessly intertwined, use the\n"
    "  \"allow_circular_includes_from\" annotation. Ideally each should have\n"
    "  identical dependencies so configs inherited from those dependencies\n"
    "  are consistent (see \"gn help allow_circular_includes_from\").\n"
    "\n"
    "  If you have a standalone header file or files that need to be shared\n"
    "  between a few targets, you can consider making a source_set listing\n"
    "  only those headers as public sources. With only header files, the\n"
    "  source set will be a no-op from a build perspective, but will give a\n"
    "  central place to refer to those headers. That source set's files\n"
    "  will still need to pass \"gn check\" in isolation.\n"
    "\n"
    "  In rare cases it makes sense to list a header in more than one\n"
    "  target if it could be considered conceptually a member of both.\n"
    "\n"
    "Examples\n"
    "\n"
    "  gn check out/Debug\n"
    "      Check everything.\n"
    "\n"
    "  gn check out/Default //foo:bar\n"
    "      Check only the files in the //foo:bar target.\n"
    "\n"
    "  gn check out/Default \"//foo/*\n"
    "      Check only the files in targets in the //foo directory tree.\n";

int RunCheck(const std::vector<std::string>& args) {
  if (args.size() != 1 && args.size() != 2) {
    Err(Location(), "You're holding it wrong.",
        "Usage: \"gn check <out_dir> [<target_label>]\"").PrintToStdout();
    return 1;
  }

  // Deliberately leaked to avoid expensive process teardown.
  Setup* setup = new Setup();
  if (!setup->DoSetup(args[0], false))
    return 1;
  if (!setup->Run())
    return 1;

  std::vector<const Target*> all_targets =
      setup->builder().GetAllResolvedTargets();

  bool filtered_by_build_config = false;
  std::vector<const Target*> targets_to_check;
  if (args.size() > 1) {
    // Compute the targets to check.
    std::vector<std::string> inputs(args.begin() + 1, args.end());
    UniqueVector<const Target*> target_matches;
    UniqueVector<const Config*> config_matches;
    UniqueVector<const Toolchain*> toolchain_matches;
    UniqueVector<SourceFile> file_matches;
    if (!ResolveFromCommandLineInput(setup, inputs, false,
                                     &target_matches, &config_matches,
                                     &toolchain_matches, &file_matches))
      return 1;

    if (target_matches.size() == 0) {
      OutputString("No matching targets.\n");
      return 1;
    }
    targets_to_check.insert(targets_to_check.begin(),
                            target_matches.begin(), target_matches.end());
  } else {
    // No argument means to check everything allowed by the filter in
    // the build config file.
    if (setup->check_patterns()) {
      FilterTargetsByPatterns(all_targets, *setup->check_patterns(),
                              &targets_to_check);
      filtered_by_build_config = targets_to_check.size() != all_targets.size();
    } else {
      // No global filter, check everything.
      targets_to_check = all_targets;
    }
  }

  const base::CommandLine* cmdline = base::CommandLine::ForCurrentProcess();
  bool force = cmdline->HasSwitch("force");

  if (!CheckPublicHeaders(&setup->build_settings(), all_targets,
                          targets_to_check, force))
    return 1;

  if (!base::CommandLine::ForCurrentProcess()->HasSwitch(switches::kQuiet)) {
    if (filtered_by_build_config) {
      // Tell the user about the implicit filtering since this is obscure.
      OutputString(base::StringPrintf(
          "%d targets out of %d checked based on the check_targets defined in"
          " \".gn\".\n",
          static_cast<int>(targets_to_check.size()),
          static_cast<int>(all_targets.size())));
    }
    OutputString("Header dependency check OK\n", DECORATION_GREEN);
  }
  return 0;
}

bool CheckPublicHeaders(const BuildSettings* build_settings,
                        const std::vector<const Target*>& all_targets,
                        const std::vector<const Target*>& to_check,
                        bool force_check) {
  ScopedTrace trace(TraceItem::TRACE_CHECK_HEADERS, "Check headers");

  scoped_refptr<HeaderChecker> header_checker(
      new HeaderChecker(build_settings, all_targets));

  std::vector<Err> header_errors;
  header_checker->Run(to_check, force_check, &header_errors);
  for (size_t i = 0; i < header_errors.size(); i++) {
    if (i > 0)
      OutputString("___________________\n", DECORATION_YELLOW);
    header_errors[i].PrintToStdout();
  }
  return header_errors.empty();
}

}  // namespace commands
