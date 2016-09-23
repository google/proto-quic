// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <iostream>

#include "base/command_line.h"
#include "tools/gn/args.h"
#include "tools/gn/commands.h"
#include "tools/gn/err.h"
#include "tools/gn/functions.h"
#include "tools/gn/input_conversion.h"
#include "tools/gn/label_pattern.h"
#include "tools/gn/parser.h"
#include "tools/gn/runtime_deps.h"
#include "tools/gn/setup.h"
#include "tools/gn/standard_out.h"
#include "tools/gn/string_utils.h"
#include "tools/gn/substitution_writer.h"
#include "tools/gn/switches.h"
#include "tools/gn/variables.h"

namespace commands {

namespace {

void PrintToplevelHelp() {
  OutputString("Commands (type \"gn help <command>\" for more details):\n");
  for (const auto& cmd : commands::GetCommands())
    PrintShortHelp(cmd.second.help_short);

  // Target declarations.
  OutputString("\nTarget declarations (type \"gn help <function>\" for more "
               "details):\n");
  for (const auto& func : functions::GetFunctions()) {
    if (func.second.is_target)
      PrintShortHelp(func.second.help_short);
  }

  // Functions.
  OutputString("\nBuildfile functions (type \"gn help <function>\" for more "
               "details):\n");
  for (const auto& func : functions::GetFunctions()) {
    if (!func.second.is_target)
      PrintShortHelp(func.second.help_short);
  }

  // Built-in variables.
  OutputString("\nBuilt-in predefined variables (type \"gn help <variable>\" "
               "for more details):\n");
  for (const auto& builtin : variables::GetBuiltinVariables())
    PrintShortHelp(builtin.second.help_short);

  // Target variables.
  OutputString("\nVariables you set in targets (type \"gn help <variable>\" "
               "for more details):\n");
  for (const auto& target : variables::GetTargetVariables())
    PrintShortHelp(target.second.help_short);

  OutputString("\nOther help topics:\n");
  PrintShortHelp("all: Print all the help at once");
  PrintShortHelp("buildargs: How build arguments work.");
  PrintShortHelp("dotfile: Info about the toplevel .gn file.");
  PrintShortHelp("grammar: Language and grammar for GN build files.");
  PrintShortHelp(
      "input_conversion: Processing input from exec_script and read_file.");
  PrintShortHelp("label_pattern: Matching more than one label.");
  PrintShortHelp("nogncheck: Annotating includes for checking.");
  PrintShortHelp("runtime_deps: How runtime dependency computation works.");
  PrintShortHelp("source_expansion: Map sources to outputs for scripts.");
  PrintShortHelp("switches: Show available command-line switches.");
}

void PrintSwitchHelp() {
  const base::CommandLine* cmdline = base::CommandLine::ForCurrentProcess();
  bool use_markdown = cmdline->HasSwitch(switches::kMarkdown);

  OutputString("Available global switches\n", DECORATION_YELLOW);
  OutputString(
      "  Do \"gn help --the_switch_you_want_help_on\" for more. Individual\n"
      "  commands may take command-specific switches not listed here. See the\n"
      "  help on your specific command for more.\n\n");

  if (use_markdown)
    OutputString("```\n\n", DECORATION_NONE);

  for (const auto& s : switches::GetSwitches())
    PrintShortHelp(s.second.short_help);

  if (use_markdown)
    OutputString("\n```\n", DECORATION_NONE);
}

void PrintAllHelp() {
  const base::CommandLine* cmdline = base::CommandLine::ForCurrentProcess();
  if (cmdline->HasSwitch(switches::kMarkdown)) {
    OutputString("# GN Reference\n\n");

    // TODO: https://code.google.com/p/gitiles/issues/detail?id=75
    // Gitiles crashes when rendering the table of contents, so we must omit
    // it until the bug is fixed.
    // OutputString("[TOC]\n\n");
    OutputString("*This page is automatically generated from* "
                 "`gn help --markdown all`.\n\n");
  } else {
    PrintToplevelHelp();
  }

  for (const auto& s : switches::GetSwitches())
    PrintLongHelp(s.second.long_help);

  for (const auto& c: commands::GetCommands())
    PrintLongHelp(c.second.help);

  for (const auto& f: functions::GetFunctions())
    PrintLongHelp(f.second.help);

  for (const auto& v: variables::GetBuiltinVariables())
    PrintLongHelp(v.second.help);

  for (const auto& v: variables::GetTargetVariables())
    PrintLongHelp(v.second.help);

  PrintLongHelp(kBuildArgs_Help);
  PrintLongHelp(kDotfile_Help);
  PrintLongHelp(kGrammar_Help);
  PrintLongHelp(kInputConversion_Help);
  PrintLongHelp(kLabelPattern_Help);
  PrintLongHelp(kNoGnCheck_Help);
  PrintLongHelp(kRuntimeDeps_Help);
  PrintLongHelp(kSourceExpansion_Help);
  PrintSwitchHelp();
}

// Prints help on the given switch. There should be no leading hyphens. Returns
// true if the switch was found and help was printed. False means the switch is
// unknown.
bool PrintHelpOnSwitch(const std::string& what) {
  const switches::SwitchInfoMap& all = switches::GetSwitches();
  switches::SwitchInfoMap::const_iterator found =
      all.find(base::StringPiece(what));
  if (found == all.end())
    return false;
  PrintLongHelp(found->second.long_help);
  return true;
}

}  // namespace

const char kHelp[] = "help";
const char kHelp_HelpShort[] =
    "help: Does what you think.";
const char kHelp_Help[] =
    "gn help <anything>\n"
    "\n"
    "  Yo dawg, I heard you like help on your help so I put help on the help\n"
    "  in the help.\n"
    "\n"
    "  You can also use \"all\" as the parameter to get all help at once.\n"
    "\n"
    "Switches\n"
    "\n"
    "  --markdown\n"
    "      Format output in markdown syntax.\n"
    "\n"
    "Example\n"
    "\n"
    "  gn help --markdown all\n"
    "      Dump all help to stdout in markdown format.\n";

int RunHelp(const std::vector<std::string>& args) {
  std::string what;
  if (args.size() == 0) {
    // If no argument is specified, check for switches to allow things like
    // "gn help --args" for help on the args switch.
    const base::CommandLine::SwitchMap& switches =
        base::CommandLine::ForCurrentProcess()->GetSwitches();
    if (switches.empty()) {
      // Still nothing, show help overview.
      PrintToplevelHelp();
      return 0;
    }

    // Switch help needs to be done separately. The CommandLine will strip the
    // switch separators so --args will come out as "args" which is then
    // ambiguous with the variable named "args".
    if (!PrintHelpOnSwitch(switches.begin()->first))
      PrintToplevelHelp();
    return 0;
  } else {
    what = args[0];
  }

  std::vector<base::StringPiece> all_help_topics;

  // Check commands.
  const commands::CommandInfoMap& command_map = commands::GetCommands();
  auto found_command = command_map.find(what);
  if (found_command != command_map.end()) {
    PrintLongHelp(found_command->second.help);
    return 0;
  }
  for (const auto& entry : command_map)
    all_help_topics.push_back(entry.first);

  // Check functions.
  const functions::FunctionInfoMap& function_map = functions::GetFunctions();
  auto found_function = function_map.find(what);
  if (found_function != function_map.end()) {
    PrintLongHelp(found_function->second.help);
    return 0;
  }
  for (const auto& entry : function_map)
    all_help_topics.push_back(entry.first);

  // Builtin variables.
  const variables::VariableInfoMap& builtin_vars =
      variables::GetBuiltinVariables();
  auto found_builtin_var = builtin_vars.find(what);
  if (found_builtin_var != builtin_vars.end()) {
    PrintLongHelp(found_builtin_var->second.help);
    return 0;
  }
  for (const auto& entry : builtin_vars)
    all_help_topics.push_back(entry.first);

  // Target variables.
  const variables::VariableInfoMap& target_vars =
      variables::GetTargetVariables();
  auto found_target_var = target_vars.find(what);
  if (found_target_var != target_vars.end()) {
    PrintLongHelp(found_target_var->second.help);
    return 0;
  }
  for (const auto& entry : target_vars)
    all_help_topics.push_back(entry.first);

  // Random other topics.
  std::map<std::string, void(*)()> random_topics;
  random_topics["all"] = PrintAllHelp;
  random_topics["buildargs"] = []() { PrintLongHelp(kBuildArgs_Help); };
  random_topics["dotfile"] = []() { PrintLongHelp(kDotfile_Help); };
  random_topics["grammar"] = []() { PrintLongHelp(kGrammar_Help); };
  random_topics["input_conversion"] = []() {
    PrintLongHelp(kInputConversion_Help);
  };
  random_topics["label_pattern"] = []() { PrintLongHelp(kLabelPattern_Help); };
  random_topics["nogncheck"] = []() { PrintLongHelp(kNoGnCheck_Help); };
  random_topics["runtime_deps"] = []() { PrintLongHelp(kRuntimeDeps_Help); };
  random_topics["source_expansion"] = []() {
    PrintLongHelp(kSourceExpansion_Help);
  };
  random_topics["switches"] = PrintSwitchHelp;
  auto found_random_topic = random_topics.find(what);
  if (found_random_topic != random_topics.end()) {
    found_random_topic->second();
    return 0;
  }
  for (const auto& entry : random_topics)
    all_help_topics.push_back(entry.first);

  // No help on this.
  Err(Location(), "No help on \"" + what + "\".").PrintToStdout();
  base::StringPiece suggestion = SpellcheckString(what, all_help_topics);
  if (suggestion.empty()) {
    OutputString("Run `gn help` for a list of available topics.\n",
                 DECORATION_NONE);
  } else {
    OutputString("Did you mean `gn help " + suggestion.as_string() + "`?\n",
                 DECORATION_NONE);
  }
  return 1;
}

}  // namespace commands
