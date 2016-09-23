// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/gn/functions.h"

#include "tools/gn/parse_tree.h"
#include "tools/gn/scope.h"
#include "tools/gn/template.h"
#include "tools/gn/value.h"

namespace functions {

const char kTemplate[] = "template";
const char kTemplate_HelpShort[] =
    "template: Define a template rule.";
const char kTemplate_Help[] =
    "template: Define a template rule.\n"
    "\n"
    "  A template defines a custom name that acts like a function. It\n"
    "  provides a way to add to the built-in target types.\n"
    "\n"
    "  The template() function is used to declare a template. To invoke the\n"
    "  template, just use the name of the template like any other target\n"
    "  type.\n"
    "\n"
    "  Often you will want to declare your template in a special file that\n"
    "  other files will import (see \"gn help import\") so your template\n"
    "  rule can be shared across build files.\n"
    "\n"
    "Variables and templates:\n"
    "\n"
    "  When you call template() it creates a closure around all variables\n"
    "  currently in scope with the code in the template block. When the\n"
    "  template is invoked, the closure will be executed.\n"
    "\n"
    "  When the template is invoked, the code in the caller is executed and\n"
    "  passed to the template code as an implicit \"invoker\" variable. The\n"
    "  template uses this to read state out of the invoking code.\n"
    "\n"
    "  One thing explicitly excluded from the closure is the \"current\n"
    "  directory\" against which relative file names are resolved. The\n"
    "  current directory will be that of the invoking code, since typically\n"
    "  that code specifies the file names. This means all files internal\n"
    "  to the template should use absolute names.\n"
    "\n"
    "  A template will typically forward some or all variables from the\n"
    "  invoking scope to a target that it defines. Often, such variables\n"
    "  might be optional. Use the pattern:\n"
    "\n"
    "    if (defined(invoker.deps)) {\n"
    "      deps = invoker.deps\n"
    "    }\n"
    "\n"
    "  The function forward_variables_from() provides a shortcut to forward\n"
    "  one or more or possibly all variables in this manner:\n"
    "\n"
    "    forward_variables_from(invoker, [\"deps\", \"public_deps\"])\n"
    "\n"
    "Target naming:\n"
    "\n"
    "  Your template should almost always define a built-in target with the\n"
    "  name the template invoker specified. For example, if you have an IDL\n"
    "  template and somebody does:\n"
    "    idl(\"foo\") {...\n"
    "  you will normally want this to expand to something defining a\n"
    "  source_set or static_library named \"foo\" (among other things you may\n"
    "  need). This way, when another target specifies a dependency on\n"
    "  \"foo\", the static_library or source_set will be linked.\n"
    "\n"
    "  It is also important that any other targets your template expands to\n"
    "  have globally unique names, or you will get collisions.\n"
    "\n"
    "  Access the invoking name in your template via the implicit\n"
    "  \"target_name\" variable. This should also be the basis for how other\n"
    "  targets that a template expands to ensure uniqueness.\n"
    "\n"
    "  A typical example would be a template that defines an action to\n"
    "  generate some source files, and a source_set to compile that source.\n"
    "  Your template would name the source_set \"target_name\" because\n"
    "  that's what you want external targets to depend on to link your code.\n"
    "  And you would name the action something like \"${target_name}_action\"\n"
    "  to make it unique. The source set would have a dependency on the\n"
    "  action to make it run.\n"
    "\n"
    "Example of defining a template:\n"
    "\n"
    "  template(\"my_idl\") {\n"
    "    # Be nice and help callers debug problems by checking that the\n"
    "    # variables the template requires are defined. This gives a nice\n"
    "    # message rather than giving the user an error about an\n"
    "    # undefined variable in the file defining the template\n"
    "    #\n"
    "    # You can also use defined() to give default values to variables\n"
    "    # unspecified by the invoker.\n"
    "    assert(defined(invoker.sources),\n"
    "           \"Need sources in $target_name listing the idl files.\")\n"
    "\n"
    "    # Name of the intermediate target that does the code gen. This must\n"
    "    # incorporate the target name so it's unique across template\n"
    "    # instantiations.\n"
    "    code_gen_target_name = target_name + \"_code_gen\"\n"
    "\n"
    "    # Intermediate target to convert IDL to C source. Note that the name\n"
    "    # is based on the name the invoker of the template specified. This\n"
    "    # way, each time the template is invoked we get a unique\n"
    "    # intermediate action name (since all target names are in the global\n"
    "    # scope).\n"
    "    action_foreach(code_gen_target_name) {\n"
    "      # Access the scope defined by the invoker via the implicit\n"
    "      # \"invoker\" variable.\n"
    "      sources = invoker.sources\n"
    "\n"
    "      # Note that we need an absolute path for our script file name.\n"
    "      # The current directory when executing this code will be that of\n"
    "      # the invoker (this is why we can use the \"sources\" directly\n"
    "      # above without having to rebase all of the paths). But if we need\n"
    "      # to reference a script relative to the template file, we'll need\n"
    "      # to use an absolute path instead.\n"
    "      script = \"//tools/idl/idl_code_generator.py\"\n"
    "\n"
    "      # Tell GN how to expand output names given the sources.\n"
    "      # See \"gn help source_expansion\" for more.\n"
    "      outputs = [ \"$target_gen_dir/{{source_name_part}}.cc\",\n"
    "                  \"$target_gen_dir/{{source_name_part}}.h\" ]\n"
    "    }\n"
    "\n"
    "    # Name the source set the same as the template invocation so\n"
    "    # instancing this template produces something that other targets\n"
    "    # can link to in their deps.\n"
    "    source_set(target_name) {\n"
    "      # Generates the list of sources, we get these from the\n"
    "      # action_foreach above.\n"
    "      sources = get_target_outputs(\":$code_gen_target_name\")\n"
    "\n"
    "      # This target depends on the files produced by the above code gen\n"
    "      # target.\n"
    "      deps = [ \":$code_gen_target_name\" ]\n"
    "    }\n"
    "  }\n"
    "\n"
    "Example of invoking the resulting template:\n"
    "\n"
    "  # This calls the template code above, defining target_name to be\n"
    "  # \"foo_idl_files\" and \"invoker\" to be the set of stuff defined in\n"
    "  # the curly brackets.\n"
    "  my_idl(\"foo_idl_files\") {\n"
    "    # Goes into the template as \"invoker.sources\".\n"
    "    sources = [ \"foo.idl\", \"bar.idl\" ]\n"
    "  }\n"
    "\n"
    "  # Here is a target that depends on our template.\n"
    "  executable(\"my_exe\") {\n"
    "    # Depend on the name we gave the template call above. Internally,\n"
    "    # this will produce a dependency from executable to the source_set\n"
    "    # inside the template (since it has this name), which will in turn\n"
    "    # depend on the code gen action.\n"
    "    deps = [ \":foo_idl_files\" ]\n"
    "  }\n";

Value RunTemplate(Scope* scope,
                  const FunctionCallNode* function,
                  const std::vector<Value>& args,
                  BlockNode* block,
                  Err* err) {
  // Of course you can have configs and targets in a template. But here, we're
  // not actually executing the block, only declaring it. Marking the template
  // declaration as non-nestable means that you can't put it inside a target,
  // for example.
  NonNestableBlock non_nestable(scope, function, "template");
  if (!non_nestable.Enter(err))
    return Value();

  // TODO(brettw) determine if the function is built-in and throw an error if
  // it is.
  if (args.size() != 1) {
    *err = Err(function->function(),
               "Need exactly one string arg to template.");
    return Value();
  }
  if (!args[0].VerifyTypeIs(Value::STRING, err))
    return Value();
  std::string template_name = args[0].string_value();

  const Template* existing_template = scope->GetTemplate(template_name);
  if (existing_template) {
    *err = Err(function, "Duplicate template definition.",
               "A template with this name was already defined.");
    err->AppendSubErr(Err(existing_template->GetDefinitionRange(),
                          "Previous definition."));
    return Value();
  }

  scope->AddTemplate(template_name, new Template(scope, function));

  // The template object above created a closure around the variables in the
  // current scope. The template code will execute in that context when it's
  // invoked. But this means that any variables defined above that are used
  // by the template won't get marked used just by defining the template. The
  // result can be spurious unused variable errors.
  //
  // The "right" thing to do would be to walk the syntax tree inside the
  // template, find all identifier references, and mark those variables used.
  // This is annoying and error-prone to implement and takes extra time to run
  // for this narrow use case.
  //
  // Templates are most often defined in .gni files which don't get
  // used-variable checking anyway, and this case is annoying enough that the
  // incremental value of unused variable checking isn't worth the
  // alternatives. So all values in scope before this template definition are
  // exempted from unused variable checking.
  scope->MarkAllUsed();

  return Value();
}

}  // namespace functions
