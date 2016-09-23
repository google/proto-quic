// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/gn/err.h"
#include "tools/gn/functions.h"
#include "tools/gn/parse_tree.h"
#include "tools/gn/scope.h"

namespace functions {

const char kSetDefaults[] = "set_defaults";
const char kSetDefaults_HelpShort[] =
    "set_defaults: Set default values for a target type.";
const char kSetDefaults_Help[] =
    "set_defaults: Set default values for a target type.\n"
    "\n"
    "  set_defaults(<target_type_name>) { <values...> }\n"
    "\n"
    "  Sets the default values for a given target type. Whenever\n"
    "  target_type_name is seen in the future, the values specified in\n"
    "  set_default's block will be copied into the current scope.\n"
    "\n"
    "  When the target type is used, the variable copying is very strict.\n"
    "  If a variable with that name is already in scope, the build will fail\n"
    "  with an error.\n"
    "\n"
    "  set_defaults can be used for built-in target types (\"executable\",\n"
    "  \"shared_library\", etc.) and custom ones defined via the \"template\"\n"
    "  command. It can be called more than once and the most recent call in\n"
    "  any scope will apply, but there is no way to refer to the previous\n"
    "  defaults and modify them (each call to set_defaults must supply a\n"
    "  complete list of all defaults it wants). If you want to share\n"
    "  defaults, store them in a separate variable.\n"
    "\n"
    "Example\n"
    "\n"
    "  set_defaults(\"static_library\") {\n"
    "    configs = [ \"//tools/mything:settings\" ]\n"
    "  }\n"
    "\n"
    "  static_library(\"mylib\")\n"
    "    # The configs will be auto-populated as above. You can remove it if\n"
    "    # you don't want the default for a particular default:\n"
    "    configs -= \"//tools/mything:settings\"\n"
    "  }\n";

Value RunSetDefaults(Scope* scope,
                     const FunctionCallNode* function,
                     const std::vector<Value>& args,
                     BlockNode* block,
                     Err* err) {
  if (!EnsureSingleStringArg(function, args, err))
    return Value();
  const std::string& target_type(args[0].string_value());

  if (!block) {
    FillNeedsBlockError(function, err);
    return Value();
  }

  // Run the block for the rule invocation.
  Scope block_scope(scope);
  block->Execute(&block_scope, err);
  if (err->has_error())
    return Value();

  // Now copy the values set on the scope we made into the free-floating one
  // (with no containing scope) used to hold the target defaults.
  Scope* dest = scope->MakeTargetDefaults(target_type);
  block_scope.NonRecursiveMergeTo(dest, Scope::MergeOptions(), function,
                                  "<SHOULD NOT FAIL>", err);
  return Value();
}

}  // namespace functions
