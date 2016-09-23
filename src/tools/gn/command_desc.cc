// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>

#include <algorithm>
#include <set>
#include <sstream>

#include "base/command_line.h"
#include "base/json/json_writer.h"
#include "base/memory/ptr_util.h"
#include "base/strings/string_util.h"
#include "tools/gn/commands.h"
#include "tools/gn/config.h"
#include "tools/gn/desc_builder.h"
#include "tools/gn/setup.h"
#include "tools/gn/standard_out.h"
#include "tools/gn/switches.h"
#include "tools/gn/target.h"
#include "tools/gn/variables.h"

namespace commands {

namespace {

// Desc-specific command line switches.
const char kBlame[] = "blame";
const char kTree[] = "tree";
const char kAll[] = "all";

// Prints value with specified indentation level
void PrintValue(const base::Value* value, int indentLevel) {
  std::string indent(indentLevel * 2, ' ');
  const base::ListValue* list_value = nullptr;
  const base::DictionaryValue* dict_value = nullptr;
  std::string string_value;
  bool bool_value = false;
  if (value->GetAsList(&list_value)) {
    for (const auto& v : *list_value) {
      PrintValue(v.get(), indentLevel);
    }
  } else if (value->GetAsString(&string_value)) {
    OutputString(indent);
    OutputString(string_value);
    OutputString("\n");
  } else if (value->GetAsBoolean(&bool_value)) {
    OutputString(indent);
    OutputString(bool_value ? "true" : "false");
    OutputString("\n");
  } else if (value->GetAsDictionary(&dict_value)) {
    base::DictionaryValue::Iterator iter(*dict_value);
    while (!iter.IsAtEnd()) {
      OutputString(indent + iter.key() + "\n");
      PrintValue(&iter.value(), indentLevel + 1);
      iter.Advance();
    }
  } else if (value->IsType(base::Value::TYPE_NULL)) {
    OutputString(indent + "<null>\n");
  }
}

// Default handler for property
void DefaultHandler(const std::string& name, const base::Value* value) {
  OutputString("\n");
  OutputString(name);
  OutputString("\n");
  PrintValue(value, 1);
}

// Specific handler for properties that need different treatment

// Prints label and property value on one line, capitalizing the label.
void LabelHandler(std::string name, const base::Value* value) {
  name[0] = base::ToUpperASCII(name[0]);
  std::string string_value;
  if (value->GetAsString(&string_value)) {
    OutputString(name + ": ", DECORATION_YELLOW);
    OutputString(string_value + "\n");
  }
}

void VisibilityHandler(const std::string& name, const base::Value* value) {
  const base::ListValue* list;
  if (value->GetAsList(&list)) {
    if (list->empty()) {
      base::StringValue str("(no visibility)");
      DefaultHandler(name, &str);
    } else {
      DefaultHandler(name, value);
    }
  }
}

void PublicHandler(const std::string& name, const base::Value* value) {
  std::string p;
  if (value->GetAsString(&p)) {
    if (p == "*") {
      base::StringValue str("[All headers listed in the sources are public.]");
      DefaultHandler(name, &str);
      return;
    }
  }
  DefaultHandler(name, value);
}

void ConfigsHandler(const std::string& name, const base::Value* value) {
  bool tree = base::CommandLine::ForCurrentProcess()->HasSwitch(kTree);
  if (tree)
    DefaultHandler(name + " tree (in order applying)", value);
  else
    DefaultHandler(name + " (in order applying, try also --tree)", value);
}

void DepsHandler(const std::string& name, const base::Value* value) {
  bool tree = base::CommandLine::ForCurrentProcess()->HasSwitch(kTree);
  bool all = base::CommandLine::ForCurrentProcess()->HasSwitch(kTree);
  if (tree) {
    DefaultHandler("Dependency tree", value);
  } else {
    if (!all) {
      DefaultHandler(
          "Direct dependencies "
          "(try also \"--all\", \"--tree\", or even \"--all --tree\")",
          value);
    } else {
      DefaultHandler("All recursive dependencies", value);
    }
  }
}

// Outputs need special processing when output patterns are present.
void ProcessOutputs(base::DictionaryValue* target) {
  base::ListValue* patterns = nullptr;
  base::ListValue* outputs = nullptr;
  target->GetList("output_patterns", &patterns);
  target->GetList(variables::kOutputs, &outputs);

  if (outputs || patterns) {
    OutputString("\noutputs\n");
    int indent = 1;
    if (patterns) {
      OutputString("  Output patterns\n");
      indent = 2;
      PrintValue(patterns, indent);
      OutputString("\n  Resolved output file list\n");
    }
    if (outputs)
      PrintValue(outputs, indent);

    target->Remove("output_patterns", nullptr);
    target->Remove(variables::kOutputs, nullptr);
  }
}

bool PrintTarget(const Target* target,
                 const std::string& what,
                 bool single_target,
                 bool all,
                 bool tree,
                 bool blame) {
  std::unique_ptr<base::DictionaryValue> dict =
      DescBuilder::DescriptionForTarget(target, what, all, tree, blame);
  if (!what.empty() && dict->empty()) {
    OutputString("Don't know how to display \"" + what + "\" for \"" +
                 Target::GetStringForOutputType(target->output_type()) +
                 "\".\n");
    return false;
  }
  // Print single value, without any headers
  if (!what.empty() && dict->size() == 1 && single_target) {
    base::DictionaryValue::Iterator iter(*dict);
    PrintValue(&iter.value(), 0);
    return true;
  }

  OutputString("Target ", DECORATION_YELLOW);
  OutputString(target->label().GetUserVisibleName(false));
  OutputString("\n");

  std::unique_ptr<base::Value> v;
#define HANDLER(property, handler_name) \
  if (dict->Remove(property, &v)) {     \
    handler_name(property, v.get());    \
  }

  // Entries with DefaultHandler are present to enforce order
  HANDLER("type", LabelHandler);
  HANDLER("toolchain", LabelHandler);
  HANDLER(variables::kVisibility, VisibilityHandler);
  HANDLER(variables::kTestonly, DefaultHandler);
  HANDLER(variables::kCheckIncludes, DefaultHandler);
  HANDLER(variables::kAllowCircularIncludesFrom, DefaultHandler);
  HANDLER(variables::kSources, DefaultHandler);
  HANDLER(variables::kPublic, PublicHandler);
  HANDLER(variables::kInputs, DefaultHandler);
  HANDLER(variables::kConfigs, ConfigsHandler);
  HANDLER(variables::kPublicConfigs, ConfigsHandler);
  HANDLER(variables::kAllDependentConfigs, ConfigsHandler);
  HANDLER(variables::kScript, DefaultHandler);
  HANDLER(variables::kArgs, DefaultHandler);
  HANDLER(variables::kDepfile, DefaultHandler);
  ProcessOutputs(dict.get());
  HANDLER("bundle_data", DefaultHandler);
  HANDLER(variables::kArflags, DefaultHandler);
  HANDLER(variables::kAsmflags, DefaultHandler);
  HANDLER(variables::kCflags, DefaultHandler);
  HANDLER(variables::kCflagsC, DefaultHandler);
  HANDLER(variables::kCflagsCC, DefaultHandler);
  HANDLER(variables::kCflagsObjC, DefaultHandler);
  HANDLER(variables::kCflagsObjCC, DefaultHandler);
  HANDLER(variables::kDefines, DefaultHandler);
  HANDLER(variables::kIncludeDirs, DefaultHandler);
  HANDLER(variables::kLdflags, DefaultHandler);
  HANDLER(variables::kPrecompiledHeader, DefaultHandler);
  HANDLER(variables::kPrecompiledSource, DefaultHandler);
  HANDLER(variables::kDeps, DepsHandler);
  HANDLER(variables::kLibs, DefaultHandler);
  HANDLER(variables::kLibDirs, DefaultHandler);

#undef HANDLER

  // Process the rest (if any)
  base::DictionaryValue::Iterator iter(*dict);
  while (!iter.IsAtEnd()) {
    DefaultHandler(iter.key(), &iter.value());
    iter.Advance();
  }

  return true;
}

bool PrintConfig(const Config* config,
                 const std::string& what,
                 bool single_config) {
  std::unique_ptr<base::DictionaryValue> dict =
      DescBuilder::DescriptionForConfig(config, what);
  if (!what.empty() && dict->empty()) {
    OutputString("Don't know how to display \"" + what + "\" for a config.\n");
    return false;
  }
  // Print single value, without any headers
  if (!what.empty() && dict->size() == 1 && single_config) {
    base::DictionaryValue::Iterator iter(*dict);
    PrintValue(&iter.value(), 0);
    return true;
  }

  OutputString("Config: ", DECORATION_YELLOW);
  OutputString(config->label().GetUserVisibleName(false));
  OutputString("\n");

  std::unique_ptr<base::Value> v;
#define HANDLER(property, handler_name) \
  if (dict->Remove(property, &v)) {     \
    handler_name(property, v.get());    \
  }

  HANDLER("toolchain", LabelHandler);
  if (!config->configs().empty()) {
    OutputString(
        "(This is a composite config, the values below are after the\n"
        "expansion of the child configs.)\n");
  }
  HANDLER(variables::kArflags, DefaultHandler);
  HANDLER(variables::kAsmflags, DefaultHandler);
  HANDLER(variables::kCflags, DefaultHandler);
  HANDLER(variables::kCflagsC, DefaultHandler);
  HANDLER(variables::kCflagsCC, DefaultHandler);
  HANDLER(variables::kCflagsObjC, DefaultHandler);
  HANDLER(variables::kCflagsObjCC, DefaultHandler);
  HANDLER(variables::kDefines, DefaultHandler);
  HANDLER(variables::kIncludeDirs, DefaultHandler);
  HANDLER(variables::kLdflags, DefaultHandler);
  HANDLER(variables::kLibs, DefaultHandler);
  HANDLER(variables::kLibDirs, DefaultHandler);
  HANDLER(variables::kPrecompiledHeader, DefaultHandler);
  HANDLER(variables::kPrecompiledSource, DefaultHandler);

#undef HANDLER

  return true;
}

}  // namespace

// desc ------------------------------------------------------------------------

const char kDesc[] = "desc";
const char kDesc_HelpShort[] =
    "desc: Show lots of insightful information about a target or config.";
const char kDesc_Help[] =
    "gn desc <out_dir> <label or pattern> [<what to show>] [--blame] "
    "[--format=json]\n"
    "\n"
    "  Displays information about a given target or config. The build\n"
    "  build parameters will be taken for the build in the given <out_dir>.\n"
    "\n"
    "  The <label or pattern> can be a target label, a config label, or a\n"
    "  label pattern (see \"gn help label_pattern\"). A label pattern will\n"
    "  only match targets.\n"
    "\n"
    "Possibilities for <what to show>\n"
    "\n"
    "  (If unspecified an overall summary will be displayed.)\n"
    "\n"
    "  all_dependent_configs\n"
    "  allow_circular_includes_from\n"
    "  arflags [--blame]\n"
    "  args\n"
    "  cflags [--blame]\n"
    "  cflags_cc [--blame]\n"
    "  cflags_cxx [--blame]\n"
    "  check_includes\n"
    "  configs [--tree] (see below)\n"
    "  defines [--blame]\n"
    "  depfile\n"
    "  deps [--all] [--tree] (see below)\n"
    "  include_dirs [--blame]\n"
    "  inputs\n"
    "  ldflags [--blame]\n"
    "  lib_dirs\n"
    "  libs\n"
    "  outputs\n"
    "  public_configs\n"
    "  public\n"
    "  script\n"
    "  sources\n"
    "  testonly\n"
    "  visibility\n"
    "\n"
    "  runtime_deps\n"
    "      Compute all runtime deps for the given target. This is a\n"
    "      computed list and does not correspond to any GN variable, unlike\n"
    "      most other values here.\n"
    "\n"
    "      The output is a list of file names relative to the build\n"
    "      directory. See \"gn help runtime_deps\" for how this is computed.\n"
    "      This also works with \"--blame\" to see the source of the\n"
    "      dependency.\n"
    "\n"
    "Shared flags\n"
    "\n"
    ALL_TOOLCHAINS_SWITCH_HELP
    "\n"
    "  --format=json\n"
    "      Format the output as JSON instead of text.\n"
    "\n"
    "Target flags\n"
    "\n"
    "  --blame\n"
    "      Used with any value specified on a config, this will name\n"
    "      the config that cause that target to get the flag. This doesn't\n"
    "      currently work for libs and lib_dirs because those are inherited\n"
    "      and are more complicated to figure out the blame (patches\n"
    "      welcome).\n"
    "\n"
    "Configs\n"
    "\n"
    "  The \"configs\" section will list all configs that apply. For targets\n"
    "  this will include configs specified in the \"configs\" variable of\n"
    "  the target, and also configs pushed onto this target via public\n"
    "  or \"all dependent\" configs.\n"
    "\n"
    "  Configs can have child configs. Specifying --tree will show the\n"
    "  hierarchy.\n"
    "\n"
    "Printing outputs\n"
    "\n"
    "  The \"outputs\" section will list all outputs that apply, including\n"
    "  the outputs computed from the tool definition (eg for \"executable\",\n"
    "  \"static_library\", ... targets).\n"
    "\n"
    "Printing deps\n"
    "\n"
    "  Deps will include all public, private, and data deps (TODO this could\n"
    "  be clarified and enhanced) sorted in order applying. The following\n"
    "  may be used:\n"
    "\n"
    "  --all\n"
    "      Collects all recursive dependencies and prints a sorted flat list.\n"
    "      Also usable with --tree (see below).\n"
    "\n"
    TARGET_PRINTING_MODE_COMMAND_LINE_HELP
    "\n"
    TARGET_TESTONLY_FILTER_COMMAND_LINE_HELP
    "\n"
    "  --tree\n"
    "      Print a dependency tree. By default, duplicates will be elided\n"
    "      with \"...\" but when --all and -tree are used together, no\n"
    "      eliding will be performed.\n"
    "\n"
    "      The \"deps\", \"public_deps\", and \"data_deps\" will all be\n"
    "      included in the tree.\n"
    "\n"
    "      Tree output can not be used with the filtering or output flags:\n"
    "      --as, --type, --testonly.\n"
    "\n"
    TARGET_TYPE_FILTER_COMMAND_LINE_HELP
    "\n"
    "Note\n"
    "\n"
    "  This command will show the full name of directories and source files,\n"
    "  but when directories and source paths are written to the build file,\n"
    "  they will be adjusted to be relative to the build directory. So the\n"
    "  values for paths displayed by this command won't match (but should\n"
    "  mean the same thing).\n"
    "\n"
    "Examples\n"
    "\n"
    "  gn desc out/Debug //base:base\n"
    "      Summarizes the given target.\n"
    "\n"
    "  gn desc out/Foo :base_unittests deps --tree\n"
    "      Shows a dependency tree of the \"base_unittests\" project in\n"
    "      the current directory.\n"
    "\n"
    "  gn desc out/Debug //base defines --blame\n"
    "      Shows defines set for the //base:base target, annotated by where\n"
    "      each one was set from.\n";

int RunDesc(const std::vector<std::string>& args) {
  if (args.size() != 2 && args.size() != 3) {
    Err(Location(), "You're holding it wrong.",
        "Usage: \"gn desc <out_dir> <target_name> [<what to display>]\"")
        .PrintToStdout();
    return 1;
  }
  const base::CommandLine* cmdline = base::CommandLine::ForCurrentProcess();

  // Deliberately leaked to avoid expensive process teardown.
  Setup* setup = new Setup;
  setup->build_settings().set_check_for_bad_items(false);
  if (!setup->DoSetup(args[0], false))
    return 1;
  if (!setup->Run())
    return 1;

  // Resolve target(s) and config from inputs.
  UniqueVector<const Target*> target_matches;
  UniqueVector<const Config*> config_matches;
  UniqueVector<const Toolchain*> toolchain_matches;
  UniqueVector<SourceFile> file_matches;

  std::vector<std::string> target_list;
  target_list.push_back(args[1]);

  if (!ResolveFromCommandLineInput(
          setup, target_list, cmdline->HasSwitch(switches::kAllToolchains),
          &target_matches, &config_matches, &toolchain_matches, &file_matches))
    return 1;

  std::string what_to_print;
  if (args.size() == 3)
    what_to_print = args[2];

  bool json = cmdline->GetSwitchValueASCII("format") == "json";

  if (json) {
    // Convert all targets/configs to JSON, serialize and print them
    auto res = base::MakeUnique<base::DictionaryValue>();
    if (!target_matches.empty()) {
      for (const auto* target : target_matches) {
        res->Set(target->label().GetUserVisibleName(
                     target->settings()->default_toolchain_label()),
                 DescBuilder::DescriptionForTarget(
                     target, what_to_print, cmdline->HasSwitch(kAll),
                     cmdline->HasSwitch(kTree), cmdline->HasSwitch(kBlame)));
      }
    } else if (!config_matches.empty()) {
      for (const auto* config : config_matches) {
        res->Set(config->label().GetUserVisibleName(false),
                 DescBuilder::DescriptionForConfig(config, what_to_print));
      }
    }
    std::string s;
    base::JSONWriter::WriteWithOptions(
        *res.get(), base::JSONWriter::OPTIONS_PRETTY_PRINT, &s);
    OutputString(s);
  } else {
    // Regular (non-json) formatted output
    bool multiple_outputs = (target_matches.size() + config_matches.size()) > 1;

    bool printed_output = false;
    for (const Target* target : target_matches) {
      if (printed_output)
        OutputString("\n\n");
      printed_output = true;

      if (!PrintTarget(target, what_to_print, !multiple_outputs,
                       cmdline->HasSwitch(kAll), cmdline->HasSwitch(kTree),
                       cmdline->HasSwitch(kBlame)))
        return 1;
    }
    for (const Config* config : config_matches) {
      if (printed_output)
        OutputString("\n\n");
      printed_output = true;

      if (!PrintConfig(config, what_to_print, !multiple_outputs))
        return 1;
    }
  }

  return 0;
}

}  // namespace commands
