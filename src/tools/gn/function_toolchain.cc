// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <limits>
#include <utility>

#include "tools/gn/err.h"
#include "tools/gn/functions.h"
#include "tools/gn/label.h"
#include "tools/gn/label_ptr.h"
#include "tools/gn/parse_tree.h"
#include "tools/gn/scheduler.h"
#include "tools/gn/scope.h"
#include "tools/gn/settings.h"
#include "tools/gn/tool.h"
#include "tools/gn/toolchain.h"
#include "tools/gn/value_extractors.h"
#include "tools/gn/variables.h"

namespace functions {

namespace {

// This is just a unique value to take the address of to use as the key for
// the toolchain property on a scope.
const int kToolchainPropertyKey = 0;

bool ReadBool(Scope* scope,
              const char* var,
              Tool* tool,
              void (Tool::*set)(bool),
              Err* err) {
  const Value* v = scope->GetValue(var, true);
  if (!v)
    return true;  // Not present is fine.
  if (!v->VerifyTypeIs(Value::BOOLEAN, err))
    return false;

  (tool->*set)(v->boolean_value());
  return true;
}

// Reads the given string from the scope (if present) and puts the result into
// dest. If the value is not a string, sets the error and returns false.
bool ReadString(Scope* scope,
                const char* var,
                Tool* tool,
                void (Tool::*set)(std::string),
                Err* err) {
  const Value* v = scope->GetValue(var, true);
  if (!v)
    return true;  // Not present is fine.
  if (!v->VerifyTypeIs(Value::STRING, err))
    return false;

  (tool->*set)(v->string_value());
  return true;
}

// Reads the given label from the scope (if present) and puts the result into
// dest. If the value is not a label, sets the error and returns false.
bool ReadLabel(Scope* scope,
               const char* var,
               Tool* tool,
               const Label& current_toolchain,
               void (Tool::*set)(LabelPtrPair<Pool>),
               Err* err) {
  const Value* v = scope->GetValue(var, true);
  if (!v)
    return true;  // Not present is fine.

  Label label =
      Label::Resolve(scope->GetSourceDir(), current_toolchain, *v, err);
  if (err->has_error())
    return false;

  LabelPtrPair<Pool> pair(label);
  pair.origin = tool->defined_from();

  (tool->*set)(std::move(pair));
  return true;
}

// Calls the given validate function on each type in the list. On failure,
// sets the error, blame the value, and return false.
bool ValidateSubstitutionList(const std::vector<SubstitutionType>& list,
                              bool (*validate)(SubstitutionType),
                              const Value* origin,
                              Err* err) {
  for (const auto& cur_type : list) {
    if (!validate(cur_type)) {
      *err = Err(*origin, "Pattern not valid here.",
          "You used the pattern " + std::string(kSubstitutionNames[cur_type]) +
          " which is not valid\nfor this variable.");
      return false;
    }
  }
  return true;
}

bool ReadPattern(Scope* scope,
                 const char* name,
                 bool (*validate)(SubstitutionType),
                 Tool* tool,
                 void (Tool::*set)(SubstitutionPattern),
                 Err* err) {
  const Value* value = scope->GetValue(name, true);
  if (!value)
    return true;  // Not present is fine.
  if (!value->VerifyTypeIs(Value::STRING, err))
    return false;

  SubstitutionPattern pattern;
  if (!pattern.Parse(*value, err))
    return false;
  if (!ValidateSubstitutionList(pattern.required_types(), validate, value, err))
    return false;

  (tool->*set)(std::move(pattern));
  return true;
}

bool ReadPatternList(Scope* scope,
                     const char* name,
                     bool (*validate)(SubstitutionType),
                     Tool* tool,
                     void (Tool::*set)(SubstitutionList),
                     Err* err) {
  const Value* value = scope->GetValue(name, true);
  if (!value)
    return true;  // Not present is fine.
  if (!value->VerifyTypeIs(Value::LIST, err))
    return false;

  SubstitutionList list;
  if (!list.Parse(*value, err))
    return false;

  // Validate the right kinds of patterns are used.
  if (!ValidateSubstitutionList(list.required_types(), validate, value, err))
    return false;

  (tool->*set)(std::move(list));
  return true;
}

bool ReadOutputExtension(Scope* scope, Tool* tool, Err* err) {
  const Value* value = scope->GetValue("default_output_extension", true);
  if (!value)
    return true;  // Not present is fine.
  if (!value->VerifyTypeIs(Value::STRING, err))
    return false;

  if (value->string_value().empty())
    return true;  // Accept empty string.

  if (value->string_value()[0] != '.') {
    *err = Err(*value, "default_output_extension must begin with a '.'");
    return false;
  }

  tool->set_default_output_extension(value->string_value());
  return true;
}

bool ReadPrecompiledHeaderType(Scope* scope, Tool* tool, Err* err) {
  const Value* value = scope->GetValue("precompiled_header_type", true);
  if (!value)
    return true;  // Not present is fine.
  if (!value->VerifyTypeIs(Value::STRING, err))
    return false;

  if (value->string_value().empty())
    return true;  // Accept empty string, do nothing (default is "no PCH").

  if (value->string_value() == "gcc") {
    tool->set_precompiled_header_type(Tool::PCH_GCC);
    return true;
  } else if (value->string_value() == "msvc") {
    tool->set_precompiled_header_type(Tool::PCH_MSVC);
    return true;
  }
  *err = Err(*value, "Invalid precompiled_header_type",
             "Must either be empty, \"gcc\", or \"msvc\".");
  return false;
}

bool ReadDepsFormat(Scope* scope, Tool* tool, Err* err) {
  const Value* value = scope->GetValue("depsformat", true);
  if (!value)
    return true;  // Not present is fine.
  if (!value->VerifyTypeIs(Value::STRING, err))
    return false;

  if (value->string_value() == "gcc") {
    tool->set_depsformat(Tool::DEPS_GCC);
  } else if (value->string_value() == "msvc") {
    tool->set_depsformat(Tool::DEPS_MSVC);
  } else {
    *err = Err(*value, "Deps format must be \"gcc\" or \"msvc\".");
    return false;
  }
  return true;
}

bool IsCompilerTool(Toolchain::ToolType type) {
  return type == Toolchain::TYPE_CC ||
         type == Toolchain::TYPE_CXX ||
         type == Toolchain::TYPE_OBJC ||
         type == Toolchain::TYPE_OBJCXX ||
         type == Toolchain::TYPE_RC ||
         type == Toolchain::TYPE_ASM;
}

bool IsLinkerTool(Toolchain::ToolType type) {
  // "alink" is not counted as in the generic "linker" tool list.
  return type == Toolchain::TYPE_SOLINK ||
         type == Toolchain::TYPE_SOLINK_MODULE ||
         type == Toolchain::TYPE_LINK;
}

bool IsPatternInOutputList(const SubstitutionList& output_list,
                           const SubstitutionPattern& pattern) {
  for (const auto& cur : output_list.list()) {
    if (pattern.ranges().size() == cur.ranges().size() &&
        std::equal(pattern.ranges().begin(), pattern.ranges().end(),
                   cur.ranges().begin()))
      return true;
  }
  return false;
}


bool ValidateOutputs(const Tool* tool, Err* err) {
  if (tool->outputs().list().empty()) {
    *err = Err(tool->defined_from(),
               "\"outputs\" must be specified for this tool.");
    return false;
  }
  return true;
}

// Validates either link_output or depend_output. To generalize to either, pass
// the associated pattern, and the variable name that should appear in error
// messages.
bool ValidateLinkAndDependOutput(const Tool* tool,
                                 Toolchain::ToolType tool_type,
                                 const SubstitutionPattern& pattern,
                                 const char* variable_name,
                                 Err* err) {
  if (pattern.empty())
    return true;  // Empty is always OK.

  // It should only be specified for certain tool types.
  if (tool_type != Toolchain::TYPE_SOLINK &&
      tool_type != Toolchain::TYPE_SOLINK_MODULE) {
    *err = Err(tool->defined_from(),
        "This tool specifies a " + std::string(variable_name) + ".",
        "This is only valid for solink and solink_module tools.");
    return false;
  }

  if (!IsPatternInOutputList(tool->outputs(), pattern)) {
    *err = Err(tool->defined_from(), "This tool's link_output is bad.",
               "It must match one of the outputs.");
    return false;
  }

  return true;
}

bool ValidateRuntimeOutputs(const Tool* tool,
                            Toolchain::ToolType tool_type,
                            Err* err) {
  if (tool->runtime_outputs().list().empty())
    return true;  // Empty is always OK.

  if (!IsLinkerTool(tool_type)) {
    *err = Err(tool->defined_from(), "This tool specifies runtime_outputs.",
        "This is only valid for linker tools (alink doesn't count).");
    return false;
  }

  for (const SubstitutionPattern& pattern : tool->runtime_outputs().list()) {
    if (!IsPatternInOutputList(tool->outputs(), pattern)) {
      *err = Err(tool->defined_from(), "This tool's runtime_outputs is bad.",
                 "It must be a subset of the outputs. The bad one is:\n  " +
                  pattern.AsString());
      return false;
    }
  }
  return true;
}

}  // namespace

// toolchain -------------------------------------------------------------------

const char kToolchain[] = "toolchain";
const char kToolchain_HelpShort[] =
    "toolchain: Defines a toolchain.";
const char kToolchain_Help[] =
    "toolchain: Defines a toolchain.\n"
    "\n"
    "  A toolchain is a set of commands and build flags used to compile the\n"
    "  source code. You can have more than one toolchain in use at once in\n"
    "  a build.\n"
    "\n"
    "Functions and variables\n"
    "\n"
    "  tool()\n"
    "    The tool() function call specifies the commands commands to run for\n"
    "    a given step. See \"gn help tool\".\n"
    "\n"
    "  toolchain_args\n"
    "    Overrides for build arguments to pass to the toolchain when invoking\n"
    "    it. This is a variable of type \"scope\" where the variable names\n"
    "    correspond to variables in declare_args() blocks.\n"
    "\n"
    "    When you specify a target using an alternate toolchain, the master\n"
    "    build configuration file is re-interpreted in the context of that\n"
    "    toolchain. toolchain_args allows you to control the arguments\n"
    "    passed into this alternate invocation of the build.\n"
    "\n"
    "    Any default system arguments or arguments passed in via \"gn args\"\n"
    "    will also be passed to the alternate invocation unless explicitly\n"
    "    overridden by toolchain_args.\n"
    "\n"
    "    The toolchain_args will be ignored when the toolchain being defined\n"
    "    is the default. In this case, it's expected you want the default\n"
    "    argument values.\n"
    "\n"
    "    See also \"gn help buildargs\" for an overview of these arguments.\n"
    "\n"
    "  deps\n"
    "    Dependencies of this toolchain. These dependencies will be resolved\n"
    "    before any target in the toolchain is compiled. To avoid circular\n"
    "    dependencies these must be targets defined in another toolchain.\n"
    "\n"
    "    This is expressed as a list of targets, and generally these targets\n"
    "    will always specify a toolchain:\n"
    "      deps = [ \"//foo/bar:baz(//build/toolchain:bootstrap)\" ]\n"
    "\n"
    "    This concept is somewhat inefficient to express in Ninja (it\n"
    "    requires a lot of duplicate of rules) so should only be used when\n"
    "    absolutely necessary.\n"
    "\n"
    "Invoking targets in toolchains:\n"
    "\n"
    "  By default, when a target depends on another, there is an implicit\n"
    "  toolchain label that is inherited, so the dependee has the same one\n"
    "  as the dependent.\n"
    "\n"
    "  You can override this and refer to any other toolchain by explicitly\n"
    "  labeling the toolchain to use. For example:\n"
    "    data_deps = [ \"//plugins:mine(//toolchains:plugin_toolchain)\" ]\n"
    "  The string \"//build/toolchains:plugin_toolchain\" is a label that\n"
    "  identifies the toolchain declaration for compiling the sources.\n"
    "\n"
    "  To load a file in an alternate toolchain, GN does the following:\n"
    "\n"
    "   1. Loads the file with the toolchain definition in it (as determined\n"
    "      by the toolchain label).\n"
    "   2. Re-runs the master build configuration file, applying the\n"
    "      arguments specified by the toolchain_args section of the toolchain\n"
    "      definition.\n"
    "   3. Loads the destination build file in the context of the\n"
    "      configuration file in the previous step.\n"
    "\n"
    "Example\n"
    "\n"
    "  toolchain(\"plugin_toolchain\") {\n"
    "    tool(\"cc\") {\n"
    "      command = \"gcc {{source}}\"\n"
    "      ...\n"
    "    }\n"
    "\n"
    "    toolchain_args = {\n"
    "      is_plugin = true\n"
    "      is_32bit = true\n"
    "      is_64bit = false\n"
    "    }\n"
    "  }\n";

Value RunToolchain(Scope* scope,
                   const FunctionCallNode* function,
                   const std::vector<Value>& args,
                   BlockNode* block,
                   Err* err) {
  NonNestableBlock non_nestable(scope, function, "toolchain");
  if (!non_nestable.Enter(err))
    return Value();

  if (!EnsureNotProcessingImport(function, scope, err) ||
      !EnsureNotProcessingBuildConfig(function, scope, err))
    return Value();

  // Note that we don't want to use MakeLabelForScope since that will include
  // the toolchain name in the label, and toolchain labels don't themselves
  // have toolchain names.
  const SourceDir& input_dir = scope->GetSourceDir();
  Label label(input_dir, args[0].string_value());
  if (g_scheduler->verbose_logging())
    g_scheduler->Log("Defining toolchain", label.GetUserVisibleName(false));

  // This object will actually be copied into the one owned by the toolchain
  // manager, but that has to be done in the lock.
  std::unique_ptr<Toolchain> toolchain(new Toolchain(scope->settings(), label));
  toolchain->set_defined_from(function);
  toolchain->visibility().SetPublic();

  Scope block_scope(scope);
  block_scope.SetProperty(&kToolchainPropertyKey, toolchain.get());
  block->Execute(&block_scope, err);
  block_scope.SetProperty(&kToolchainPropertyKey, nullptr);
  if (err->has_error())
    return Value();

  // Read deps (if any).
  const Value* deps_value = block_scope.GetValue(variables::kDeps, true);
  if (deps_value) {
    ExtractListOfLabels(
        *deps_value, block_scope.GetSourceDir(),
        ToolchainLabelForScope(&block_scope), &toolchain->deps(), err);
    if (err->has_error())
      return Value();
  }

  // Read toolchain args (if any).
  const Value* toolchain_args = block_scope.GetValue("toolchain_args", true);
  if (toolchain_args) {
    if (!toolchain_args->VerifyTypeIs(Value::SCOPE, err))
      return Value();

    Scope::KeyValueMap values;
    toolchain_args->scope_value()->GetCurrentScopeValues(&values);
    toolchain->args() = values;
  }

  if (!block_scope.CheckForUnusedVars(err))
    return Value();

  // Save this toolchain.
  toolchain->ToolchainSetupComplete();
  Scope::ItemVector* collector = scope->GetItemCollector();
  if (!collector) {
    *err = Err(function, "Can't define a toolchain in this context.");
    return Value();
  }
  collector->push_back(toolchain.release());
  return Value();
}

// tool ------------------------------------------------------------------------

const char kTool[] = "tool";
const char kTool_HelpShort[] =
    "tool: Specify arguments to a toolchain tool.";
const char kTool_Help[] =
    "tool: Specify arguments to a toolchain tool.\n"
    "\n"
    "Usage:\n"
    "\n"
    "  tool(<tool type>) {\n"
    "    <tool variables...>\n"
    "  }\n"
    "\n"
    "Tool types\n"
    "\n"
    "    Compiler tools:\n"
    "      \"cc\": C compiler\n"
    "      \"cxx\": C++ compiler\n"
    "      \"objc\": Objective C compiler\n"
    "      \"objcxx\": Objective C++ compiler\n"
    "      \"rc\": Resource compiler (Windows .rc files)\n"
    "      \"asm\": Assembler\n"
    "\n"
    "    Linker tools:\n"
    "      \"alink\": Linker for static libraries (archives)\n"
    "      \"solink\": Linker for shared libraries\n"
    "      \"link\": Linker for executables\n"
    "\n"
    "    Other tools:\n"
    "      \"stamp\": Tool for creating stamp files\n"
    "      \"copy\": Tool to copy files.\n"
    "\n"
    "    Platform specific tools:\n"
    "      \"copy_bundle_data\": [iOS, OS X] Tool to copy files in a bundle.\n"
    "      \"compile_xcassets\": [iOS, OS X] Tool to compile asset catalogs.\n"
    "\n"
    "Tool variables\n"
    "\n"
    "    command  [string with substitutions]\n"
    "        Valid for: all tools (required)\n"
    "\n"
    "        The command to run.\n"
    "\n"
    "    default_output_dir  [string with substitutions]\n"
    "        Valid for: linker tools\n"
    "\n"
    "        Default directory name for the output file relative to the\n"
    "        root_build_dir. It can contain other substitution patterns.\n"
    "        This will be the default value for the {{output_dir}} expansion\n"
    "        (discussed below) but will be overridden by the \"output_dir\"\n"
    "        variable in a target, if one is specified.\n"
    "\n"
    "        GN doesn't do anything with this string other than pass it\n"
    "        along, potentially with target-specific overrides. It is the\n"
    "        tool's job to use the expansion so that the files will be in\n"
    "        the right place.\n"
    "\n"
    "    default_output_extension  [string]\n"
    "        Valid for: linker tools\n"
    "\n"
    "        Extension for the main output of a linkable tool. It includes\n"
    "        the leading dot. This will be the default value for the\n"
    "        {{output_extension}} expansion (discussed below) but will be\n"
    "        overridden by by the \"output extension\" variable in a target,\n"
    "        if one is specified. Empty string means no extension.\n"
    "\n"
    "        GN doesn't actually do anything with this extension other than\n"
    "        pass it along, potentially with target-specific overrides. One\n"
    "        would typically use the {{output_extension}} value in the\n"
    "        \"outputs\" to read this value.\n"
    "\n"
    "        Example: default_output_extension = \".exe\"\n"
    "\n"
    "    depfile  [string with substitutions]\n"
    "        Valid for: compiler tools (optional)\n"
    "\n"
    "        If the tool can write \".d\" files, this specifies the name of\n"
    "        the resulting file. These files are used to list header file\n"
    "        dependencies (or other implicit input dependencies) that are\n"
    "        discovered at build time. See also \"depsformat\".\n"
    "\n"
    "        Example: depfile = \"{{output}}.d\"\n"
    "\n"
    "    depsformat  [string]\n"
    "        Valid for: compiler tools (when depfile is specified)\n"
    "\n"
    "        Format for the deps outputs. This is either \"gcc\" or \"msvc\".\n"
    "        See the ninja documentation for \"deps\" for more information.\n"
    "\n"
    "        Example: depsformat = \"gcc\"\n"
    "\n"
    "    description  [string with substitutions, optional]\n"
    "        Valid for: all tools\n"
    "\n"
    "        What to print when the command is run.\n"
    "\n"
    "        Example: description = \"Compiling {{source}}\"\n"
    "\n"
    "    lib_switch  [string, optional, link tools only]\n"
    "    lib_dir_switch  [string, optional, link tools only]\n"
    "        Valid for: Linker tools except \"alink\"\n"
    "\n"
    "        These strings will be prepended to the libraries and library\n"
    "        search directories, respectively, because linkers differ on how\n"
    "        specify them. If you specified:\n"
    "          lib_switch = \"-l\"\n"
    "          lib_dir_switch = \"-L\"\n"
    "        then the \"{{libs}}\" expansion for [ \"freetype\", \"expat\"]\n"
    "        would be \"-lfreetype -lexpat\".\n"
    "\n"
    "    outputs  [list of strings with substitutions]\n"
    "        Valid for: Linker and compiler tools (required)\n"
    "\n"
    "        An array of names for the output files the tool produces. These\n"
    "        are relative to the build output directory. There must always be\n"
    "        at least one output file. There can be more than one output (a\n"
    "        linker might produce a library and an import library, for\n"
    "        example).\n"
    "\n"
    "        This array just declares to GN what files the tool will\n"
    "        produce. It is your responsibility to specify the tool command\n"
    "        that actually produces these files.\n"
    "\n"
    "        If you specify more than one output for shared library links,\n"
    "        you should consider setting link_output, depend_output, and\n"
    "        runtime_outputs.\n"
    "\n"
    "        Example for a compiler tool that produces .obj files:\n"
    "          outputs = [\n"
    "            \"{{source_out_dir}}/{{source_name_part}}.obj\"\n"
    "          ]\n"
    "\n"
    "        Example for a linker tool that produces a .dll and a .lib. The\n"
    "        use of {{target_output_name}}, {{output_extension}} and\n"
    "        {{output_dir}} allows the target to override these values.\n"
    "          outputs = [\n"
    "            \"{{output_dir}}/{{target_output_name}}"
                     "{{output_extension}}\",\n"
    "            \"{{output_dir}}/{{target_output_name}}.lib\",\n"
    "          ]\n"
    "\n"
    "    pool [label, optional]\n"
    "\n"
    "        Label of the pool to use for the tool. Pools are used to limit\n"
    "        the number of tasks that can execute concurrently during the\n"
    "        build.\n"
    "\n"
    "        See also \"gn help pool\".\n"
    "\n"
    "    link_output  [string with substitutions]\n"
    "    depend_output  [string with substitutions]\n"
    "        Valid for: \"solink\" only (optional)\n"
    "\n"
    "        These two files specify which of the outputs from the solink\n"
    "        tool should be used for linking and dependency tracking. These\n"
    "        should match entries in the \"outputs\". If unspecified, the\n"
    "        first item in the \"outputs\" array will be used for all. See\n"
    "        \"Separate linking and dependencies for shared libraries\"\n"
    "        below for more.\n"
    "\n"
    "        On Windows, where the tools produce a .dll shared library and\n"
    "        a .lib import library, you will want the first two to be the\n"
    "        import library and the third one to be the .dll file.\n"
    "        On Linux, if you're not doing the separate linking/dependency\n"
    "        optimization, all of these should be the .so output.\n"
    "\n"
    "    output_prefix  [string]\n"
    "        Valid for: Linker tools (optional)\n"
    "\n"
    "        Prefix to use for the output name. Defaults to empty. This\n"
    "        prefix will be prepended to the name of the target (or the\n"
    "        output_name if one is manually specified for it) if the prefix\n"
    "        is not already there. The result will show up in the\n"
    "        {{output_name}} substitution pattern.\n"
    "\n"
    "        Individual targets can opt-out of the output prefix by setting:\n"
    "          output_prefix_override = true\n"
    "        (see \"gn help output_prefix_override\").\n"
    "\n"
    "        This is typically used to prepend \"lib\" to libraries on\n"
    "        Posix systems:\n"
    "          output_prefix = \"lib\"\n"
    "\n"
    "    precompiled_header_type  [string]\n"
    "        Valid for: \"cc\", \"cxx\", \"objc\", \"objcxx\"\n"
    "\n"
    "        Type of precompiled headers. If undefined or the empty string,\n"
    "        precompiled headers will not be used for this tool. Otherwise\n"
    "        use \"gcc\" or \"msvc\".\n"
    "\n"
    "        For precompiled headers to be used for a given target, the\n"
    "        target (or a config applied to it) must also specify a\n"
    "        \"precompiled_header\" and, for \"msvc\"-style headers, a\n"
    "        \"precompiled_source\" value. If the type is \"gcc\", then both\n"
    "        \"precompiled_header\" and \"precompiled_source\" must resolve\n"
    "        to the same file, despite the different formats required for each."
    "\n"
    "        See \"gn help precompiled_header\" for more.\n"
    "\n"
    "    restat  [boolean]\n"
    "        Valid for: all tools (optional, defaults to false)\n"
    "\n"
    "        Requests that Ninja check the file timestamp after this tool has\n"
    "        run to determine if anything changed. Set this if your tool has\n"
    "        the ability to skip writing output if the output file has not\n"
    "        changed.\n"
    "\n"
    "        Normally, Ninja will assume that when a tool runs the output\n"
    "        be new and downstream dependents must be rebuild. When this is\n"
    "        set to trye, Ninja can skip rebuilding downstream dependents for\n"
    "        input changes that don't actually affect the output.\n"
    "\n"
    "        Example:\n"
    "          restat = true\n"
    "\n"
    "    rspfile  [string with substitutions]\n"
    "        Valid for: all tools (optional)\n"
    "\n"
    "        Name of the response file. If empty, no response file will be\n"
    "        used. See \"rspfile_content\".\n"
    "\n"
    "    rspfile_content  [string with substitutions]\n"
    "        Valid for: all tools (required when \"rspfile\" is specified)\n"
    "\n"
    "        The contents to be written to the response file. This may\n"
    "        include all or part of the command to send to the tool which\n"
    "        allows you to get around OS command-line length limits.\n"
    "\n"
    "        This example adds the inputs and libraries to a response file,\n"
    "        but passes the linker flags directly on the command line:\n"
    "          tool(\"link\") {\n"
    "            command = \"link -o {{output}} {{ldflags}} @{{output}}.rsp\"\n"
    "            rspfile = \"{{output}}.rsp\"\n"
    "            rspfile_content = \"{{inputs}} {{solibs}} {{libs}}\"\n"
    "          }\n"
    "\n"
    "    runtime_outputs  [string list with substitutions]\n"
    "        Valid for: linker tools\n"
    "\n"
    "        If specified, this list is the subset of the outputs that should\n"
    "        be added to runtime deps (see \"gn help runtime_deps\"). By\n"
    "        default (if runtime_outputs is empty or unspecified), it will be\n"
    "        the link_output.\n"
    "\n"
    "Expansions for tool variables\n"
    "\n"
    "  All paths are relative to the root build directory, which is the\n"
    "  current directory for running all tools. These expansions are\n"
    "  available to all tools:\n"
    "\n"
    "    {{label}}\n"
    "        The label of the current target. This is typically used in the\n"
    "        \"description\" field for link tools. The toolchain will be\n"
    "        omitted from the label for targets in the default toolchain, and\n"
    "        will be included for targets in other toolchains.\n"
    "\n"
    "    {{label_name}}\n"
    "        The short name of the label of the target. This is the part\n"
    "        after the colon. For \"//foo/bar:baz\" this will be \"baz\".\n"
    "        Unlike {{target_output_name}}, this is not affected by the\n"
    "        \"output_prefix\" in the tool or the \"output_name\" set\n"
    "        on the target.\n"
    "\n"
    "    {{output}}\n"
    "        The relative path and name of the output(s) of the current\n"
    "        build step. If there is more than one output, this will expand\n"
    "        to a list of all of them.\n"
    "        Example: \"out/base/my_file.o\"\n"
    "\n"
    "    {{target_gen_dir}}\n"
    "    {{target_out_dir}}\n"
    "        The directory of the generated file and output directories,\n"
    "        respectively, for the current target. There is no trailing\n"
    "        slash. See also {{output_dir}} for linker tools.\n"
    "        Example: \"out/base/test\"\n"
    "\n"
    "    {{target_output_name}}\n"
    "        The short name of the current target with no path information,\n"
    "        or the value of the \"output_name\" variable if one is specified\n"
    "        in the target. This will include the \"output_prefix\" if any.\n"
    "        See also {{label_name}}.\n"
    "        Example: \"libfoo\" for the target named \"foo\" and an\n"
    "        output prefix for the linker tool of \"lib\".\n"
    "\n"
    "  Compiler tools have the notion of a single input and a single output,\n"
    "  along with a set of compiler-specific flags. The following expansions\n"
    "  are available:\n"
    "\n"
    "    {{asmflags}}\n"
    "    {{cflags}}\n"
    "    {{cflags_c}}\n"
    "    {{cflags_cc}}\n"
    "    {{cflags_objc}}\n"
    "    {{cflags_objcc}}\n"
    "    {{defines}}\n"
    "    {{include_dirs}}\n"
    "        Strings correspond that to the processed flags/defines/include\n"
    "        directories specified for the target.\n"
    "        Example: \"--enable-foo --enable-bar\"\n"
    "\n"
    "        Defines will be prefixed by \"-D\" and include directories will\n"
    "        be prefixed by \"-I\" (these work with Posix tools as well as\n"
    "        Microsoft ones).\n"
    "\n"
    "    {{source}}\n"
    "        The relative path and name of the current input file.\n"
    "        Example: \"../../base/my_file.cc\"\n"
    "\n"
    "    {{source_file_part}}\n"
    "        The file part of the source including the extension (with no\n"
    "        directory information).\n"
    "        Example: \"foo.cc\"\n"
    "\n"
    "    {{source_name_part}}\n"
    "        The filename part of the source file with no directory or\n"
    "        extension.\n"
    "        Example: \"foo\"\n"
    "\n"
    "    {{source_gen_dir}}\n"
    "    {{source_out_dir}}\n"
    "        The directory in the generated file and output directories,\n"
    "        respectively, for the current input file. If the source file\n"
    "        is in the same directory as the target is declared in, they will\n"
    "        will be the same as the \"target\" versions above.\n"
    "        Example: \"gen/base/test\"\n"
    "\n"
    "  Linker tools have multiple inputs and (potentially) multiple outputs\n"
    "  The static library tool (\"alink\") is not considered a linker tool.\n"
    "  The following expansions are available:\n"
    "\n"
    "    {{inputs}}\n"
    "    {{inputs_newline}}\n"
    "        Expands to the inputs to the link step. This will be a list of\n"
    "        object files and static libraries.\n"
    "        Example: \"obj/foo.o obj/bar.o obj/somelibrary.a\"\n"
    "\n"
    "        The \"_newline\" version will separate the input files with\n"
    "        newlines instead of spaces. This is useful in response files:\n"
    "        some linkers can take a \"-filelist\" flag which expects newline\n"
    "        separated files, and some Microsoft tools have a fixed-sized\n"
    "        buffer for parsing each line of a response file.\n"
    "\n"
    "    {{ldflags}}\n"
    "        Expands to the processed set of ldflags and library search paths\n"
    "        specified for the target.\n"
    "        Example: \"-m64 -fPIC -pthread -L/usr/local/mylib\"\n"
    "\n"
    "    {{libs}}\n"
    "        Expands to the list of system libraries to link to. Each will\n"
    "        be prefixed by the \"lib_prefix\".\n"
    "\n"
    "        As a special case to support Mac, libraries with names ending in\n"
    "        \".framework\" will be added to the {{libs}} with \"-framework\"\n"
    "        preceeding it, and the lib prefix will be ignored.\n"
    "\n"
    "        Example: \"-lfoo -lbar\"\n"
    "\n"
    "    {{output_dir}}\n"
    "        The value of the \"output_dir\" variable in the target, or the\n"
    "        the value of the \"default_output_dir\" value in the tool if the\n"
    "        target does not override the output directory. This will be\n"
    "        relative to the root_build_dir and will not end in a slash.\n"
    "        Will be \".\" for output to the root_build_dir.\n"
    "\n"
    "        This is subtly different than {{target_out_dir}} which is\n"
    "        defined by GN based on the target's path and not overridable.\n"
    "        {{output_dir}} is for the final output, {{target_out_dir}} is\n"
    "        generally for object files and other outputs.\n"
    "\n"
    "        Usually {{output_dir}} would be defined in terms of either\n"
    "        {{target_out_dir}} or {{root_out_dir}}\n"
    "\n"
    "    {{output_extension}}\n"
    "        The value of the \"output_extension\" variable in the target,\n"
    "        or the value of the \"default_output_extension\" value in the\n"
    "        tool if the target does not specify an output extension.\n"
    "        Example: \".so\"\n"
    "\n"
    "    {{solibs}}\n"
    "        Extra libraries from shared library dependencide not specified\n"
    "        in the {{inputs}}. This is the list of link_output files from\n"
    "        shared libraries (if the solink tool specifies a \"link_output\"\n"
    "        variable separate from the \"depend_output\").\n"
    "\n"
    "        These should generally be treated the same as libs by your tool.\n"
    "        Example: \"libfoo.so libbar.so\"\n"
    "\n"
    "  The static library (\"alink\") tool allows {{arflags}} plus the common\n"
    "  tool substitutions.\n"
    "\n"
    "  The copy tool allows the common compiler/linker substitutions, plus\n"
    "  {{source}} which is the source of the copy. The stamp tool allows\n"
    "  only the common tool substitutions.\n"
    "\n"
    "  The copy_bundle_data and compile_xcassets tools only allows the common\n"
    "  tool substitutions. Both tools are required to create iOS/OS X bundles\n"
    "  and need only be defined on those platforms.\n"
    "\n"
    "  The copy_bundle_data tool will be called with one source and needs to\n"
    "  copy (optionally optimizing the data representation) to its output. It\n"
    "  may be called with a directory as input and it needs to be recursively\n"
    "  copied.\n"
    "\n"
    "  The compile_xcassets tool will be called with one or more source (each\n"
    "  an asset catalog) that needs to be compiled to a single output. The\n"
    "  following substitutions are avaiable:\n"
    "\n"
    "    {{inputs}}\n"
    "        Expands to the list of .xcassets to use as input to compile the\n"
    "        asset catalog.\n"
    "\n"
    "    {{bundle_product_type}}\n"
    "        Expands to the product_type of the bundle that will contain the\n"
    "        compiled asset catalog. Usually corresponds to the product_type\n"
    "        property of the corresponding create_bundle target.\n"
    "\n"
    "Separate linking and dependencies for shared libraries\n"
    "\n"
    "  Shared libraries are special in that not all changes to them require\n"
    "  that dependent targets be re-linked. If the shared library is changed\n"
    "  but no imports or exports are different, dependent code needn't be\n"
    "  relinked, which can speed up the build.\n"
    "\n"
    "  If your link step can output a list of exports from a shared library\n"
    "  and writes the file only if the new one is different, the timestamp of\n"
    "  this file can be used for triggering re-links, while the actual shared\n"
    "  library would be used for linking.\n"
    "\n"
    "  You will need to specify\n"
    "    restat = true\n"
    "  in the linker tool to make this work, so Ninja will detect if the\n"
    "  timestamp of the dependency file has changed after linking (otherwise\n"
    "  it will always assume that running a command updates the output):\n"
    "\n"
    "    tool(\"solink\") {\n"
    "      command = \"...\"\n"
    "      outputs = [\n"
    "        \"{{output_dir}}/{{target_output_name}}{{output_extension}}\",\n"
    "        \"{{output_dir}}/{{target_output_name}}"
                 "{{output_extension}}.TOC\",\n"
    "      ]\n"
    "      link_output =\n"
    "        \"{{output_dir}}/{{target_output_name}}{{output_extension}}\"\n"
    "      depend_output =\n"
    "        \"{{output_dir}}/{{target_output_name}}"
                 "{{output_extension}}.TOC\"\n"
    "      restat = true\n"
    "    }\n"
    "\n"
    "Example\n"
    "\n"
    "  toolchain(\"my_toolchain\") {\n"
    "    # Put these at the top to apply to all tools below.\n"
    "    lib_prefix = \"-l\"\n"
    "    lib_dir_prefix = \"-L\"\n"
    "\n"
    "    tool(\"cc\") {\n"
    "      command = \"gcc {{source}} -o {{output}}\"\n"
    "      outputs = [ \"{{source_out_dir}}/{{source_name_part}}.o\" ]\n"
    "      description = \"GCC {{source}}\"\n"
    "    }\n"
    "    tool(\"cxx\") {\n"
    "      command = \"g++ {{source}} -o {{output}}\"\n"
    "      outputs = [ \"{{source_out_dir}}/{{source_name_part}}.o\" ]\n"
    "      description = \"G++ {{source}}\"\n"
    "    }\n"
    "  }\n";

Value RunTool(Scope* scope,
              const FunctionCallNode* function,
              const std::vector<Value>& args,
              BlockNode* block,
              Err* err) {
  // Find the toolchain definition we're executing inside of. The toolchain
  // function will set a property pointing to it that we'll pick up.
  Toolchain* toolchain = reinterpret_cast<Toolchain*>(
      scope->GetProperty(&kToolchainPropertyKey, nullptr));
  if (!toolchain) {
    *err = Err(function->function(), "tool() called outside of toolchain().",
        "The tool() function can only be used inside a toolchain() "
        "definition.");
    return Value();
  }

  if (!EnsureSingleStringArg(function, args, err))
    return Value();
  const std::string& tool_name = args[0].string_value();
  Toolchain::ToolType tool_type = Toolchain::ToolNameToType(tool_name);
  if (tool_type == Toolchain::TYPE_NONE) {
    *err = Err(args[0], "Unknown tool type");
    return Value();
  }

  // Run the tool block.
  Scope block_scope(scope);
  block->Execute(&block_scope, err);
  if (err->has_error())
    return Value();

  // Figure out which validator to use for the substitution pattern for this
  // tool type. There are different validators for the "outputs" than for the
  // rest of the strings.
  bool (*subst_validator)(SubstitutionType) = nullptr;
  bool (*subst_output_validator)(SubstitutionType) = nullptr;
  if (IsCompilerTool(tool_type)) {
    subst_validator = &IsValidCompilerSubstitution;
    subst_output_validator = &IsValidCompilerOutputsSubstitution;
  } else if (IsLinkerTool(tool_type)) {
    subst_validator = &IsValidLinkerSubstitution;
    subst_output_validator = &IsValidLinkerOutputsSubstitution;
  } else if (tool_type == Toolchain::TYPE_ALINK) {
    subst_validator = &IsValidALinkSubstitution;
    // ALink uses the standard output file patterns as other linker tools.
    subst_output_validator = &IsValidLinkerOutputsSubstitution;
  } else if (tool_type == Toolchain::TYPE_COPY ||
             tool_type == Toolchain::TYPE_COPY_BUNDLE_DATA) {
    subst_validator = &IsValidCopySubstitution;
    subst_output_validator = &IsValidCopySubstitution;
  } else if (tool_type == Toolchain::TYPE_COMPILE_XCASSETS) {
    subst_validator = &IsValidCompileXCassetsSubstitution;
    subst_output_validator = &IsValidCompileXCassetsSubstitution;
  } else {
    subst_validator = &IsValidToolSubstitution;
    subst_output_validator = &IsValidToolSubstitution;
  }

  std::unique_ptr<Tool> tool(new Tool);
  tool->set_defined_from(function);

  if (!ReadPattern(&block_scope, "command", subst_validator, tool.get(),
                   &Tool::set_command, err) ||
      !ReadOutputExtension(&block_scope, tool.get(), err) ||
      !ReadPattern(&block_scope, "depfile", subst_validator, tool.get(),
                   &Tool::set_depfile, err) ||
      !ReadDepsFormat(&block_scope, tool.get(), err) ||
      !ReadPattern(&block_scope, "description", subst_validator, tool.get(),
                   &Tool::set_description, err) ||
      !ReadString(&block_scope, "lib_switch", tool.get(), &Tool::set_lib_switch,
                  err) ||
      !ReadString(&block_scope, "lib_dir_switch", tool.get(),
                  &Tool::set_lib_dir_switch, err) ||
      !ReadPattern(&block_scope, "link_output", subst_validator, tool.get(),
                   &Tool::set_link_output, err) ||
      !ReadPattern(&block_scope, "depend_output", subst_validator, tool.get(),
                   &Tool::set_depend_output, err) ||
      !ReadPatternList(&block_scope, "runtime_outputs", subst_validator,
                       tool.get(), &Tool::set_runtime_outputs, err) ||
      !ReadString(&block_scope, "output_prefix", tool.get(),
                  &Tool::set_output_prefix, err) ||
      !ReadPattern(&block_scope, "default_output_dir", subst_validator,
                   tool.get(), &Tool::set_default_output_dir, err) ||
      !ReadPrecompiledHeaderType(&block_scope, tool.get(), err) ||
      !ReadBool(&block_scope, "restat", tool.get(), &Tool::set_restat, err) ||
      !ReadPattern(&block_scope, "rspfile", subst_validator, tool.get(),
                   &Tool::set_rspfile, err) ||
      !ReadPattern(&block_scope, "rspfile_content", subst_validator, tool.get(),
                   &Tool::set_rspfile_content, err) ||
      !ReadLabel(&block_scope, "pool", tool.get(), toolchain->label(),
                 &Tool::set_pool, err)) {
    return Value();
  }

  if (tool_type != Toolchain::TYPE_COPY &&
      tool_type != Toolchain::TYPE_STAMP &&
      tool_type != Toolchain::TYPE_COPY_BUNDLE_DATA &&
      tool_type != Toolchain::TYPE_COMPILE_XCASSETS) {
    // All tools should have outputs, except the copy, stamp, copy_bundle_data
    // and compile_xcassets tools that generate their outputs internally.
    if (!ReadPatternList(&block_scope, "outputs", subst_output_validator,
                         tool.get(), &Tool::set_outputs, err) ||
        !ValidateOutputs(tool.get(), err))
      return Value();
  }
  if (!ValidateRuntimeOutputs(tool.get(), tool_type, err))
    return Value();

  // Validate link_output and depend_output.
  if (!ValidateLinkAndDependOutput(tool.get(), tool_type, tool->link_output(),
                                   "link_output", err))
    return Value();
  if (!ValidateLinkAndDependOutput(tool.get(), tool_type, tool->depend_output(),
                                   "depend_output", err))
    return Value();
  if ((!tool->link_output().empty() && tool->depend_output().empty()) ||
      (tool->link_output().empty() && !tool->depend_output().empty())) {
    *err = Err(function, "Both link_output and depend_output should either "
        "be specified or they should both be empty.");
    return Value();
  }

  // Make sure there weren't any vars set in this tool that were unused.
  if (!block_scope.CheckForUnusedVars(err))
    return Value();

  toolchain->SetTool(tool_type, std::move(tool));
  return Value();
}

}  // namespace functions
