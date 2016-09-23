// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/gn/functions.h"
#include "tools/gn/parse_tree.h"
#include "tools/gn/scope.h"
#include "tools/gn/settings.h"
#include "tools/gn/substitution_list.h"
#include "tools/gn/substitution_writer.h"
#include "tools/gn/target.h"
#include "tools/gn/value_extractors.h"

namespace functions {

const char kProcessFileTemplate[] = "process_file_template";
const char kProcessFileTemplate_HelpShort[] =
    "process_file_template: Do template expansion over a list of files.";
const char kProcessFileTemplate_Help[] =
    "process_file_template: Do template expansion over a list of files.\n"
    "\n"
    "  process_file_template(source_list, template)\n"
    "\n"
    "  process_file_template applies a template list to a source file list,\n"
    "  returning the result of applying each template to each source. This is\n"
    "  typically used for computing output file names from input files.\n"
    "\n"
    "  In most cases, get_target_outputs() will give the same result with\n"
    "  shorter, more maintainable code. This function should only be used\n"
    "  when that function can't be used (like there's no target or the target\n"
    "  is defined in another build file).\n"
    "\n"
    "Arguments:\n"
    "\n"
    "  The source_list is a list of file names.\n"
    "\n"
    "  The template can be a string or a list. If it is a list, multiple\n"
    "  output strings are generated for each input.\n"
    "\n"
    "  The template should contain source expansions to which each name in\n"
    "  the source list is applied. See \"gn help source_expansion\".\n"
    "\n"
    "Example:\n"
    "\n"
    "  sources = [\n"
    "    \"foo.idl\",\n"
    "    \"bar.idl\",\n"
    "  ]\n"
    "  myoutputs = process_file_template(\n"
    "      sources,\n"
    "      [ \"$target_gen_dir/{{source_name_part}}.cc\",\n"
    "        \"$target_gen_dir/{{source_name_part}}.h\" ])\n"
    "\n"
    " The result in this case will be:\n"
    "    [ \"//out/Debug/foo.cc\"\n"
    "      \"//out/Debug/foo.h\"\n"
    "      \"//out/Debug/bar.cc\"\n"
    "      \"//out/Debug/bar.h\" ]\n";

Value RunProcessFileTemplate(Scope* scope,
                             const FunctionCallNode* function,
                             const std::vector<Value>& args,
                             Err* err) {
  if (args.size() != 2) {
    *err = Err(function->function(), "Expected two arguments");
    return Value();
  }

  // Source list.
  Target::FileList input_files;
  if (!ExtractListOfRelativeFiles(scope->settings()->build_settings(), args[0],
                                  scope->GetSourceDir(), &input_files, err))
    return Value();

  std::vector<std::string> result_files;
  SubstitutionList subst;

  // Template.
  const Value& template_arg = args[1];
  if (template_arg.type() == Value::STRING) {
    // Convert the string to a SubstitutionList with one pattern in it to
    // simplify the code below.
    std::vector<std::string> list;
    list.push_back(template_arg.string_value());
    if (!subst.Parse(list, template_arg.origin(), err))
      return Value();
  } else if (template_arg.type() == Value::LIST) {
    if (!subst.Parse(template_arg, err))
      return Value();
  } else {
    *err = Err(template_arg, "Not a string or a list.");
    return Value();
  }

  SubstitutionWriter::ApplyListToSourcesAsString(
      scope->settings(), subst, input_files, &result_files);

  // Convert the list of strings to the return Value.
  Value ret(function, Value::LIST);
  ret.list_value().reserve(result_files.size());
  for (const auto& file : result_files)
    ret.list_value().push_back(Value(function, file));

  return ret;
}

}  // namespace functions
