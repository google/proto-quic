// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/gn/functions.h"

#include "tools/gn/config_values_generator.h"
#include "tools/gn/err.h"
#include "tools/gn/parse_tree.h"
#include "tools/gn/scope.h"
#include "tools/gn/target_generator.h"
#include "tools/gn/template.h"
#include "tools/gn/value.h"
#include "tools/gn/variables.h"

#define DEPENDENT_CONFIG_VARS \
    "  Dependent configs: all_dependent_configs, public_configs\n"
#define DEPS_VARS \
    "  Deps: data_deps, deps, public_deps\n"
#define GENERAL_TARGET_VARS \
    "  General: check_includes, configs, data, inputs, output_name,\n" \
    "           output_extension, public, sources, testonly, visibility\n"

namespace functions {

namespace {

Value ExecuteGenericTarget(const char* target_type,
                           Scope* scope,
                           const FunctionCallNode* function,
                           const std::vector<Value>& args,
                           BlockNode* block,
                           Err* err) {
  NonNestableBlock non_nestable(scope, function, "target");
  if (!non_nestable.Enter(err))
    return Value();

  if (!EnsureNotProcessingImport(function, scope, err) ||
      !EnsureNotProcessingBuildConfig(function, scope, err))
    return Value();
  Scope block_scope(scope);
  if (!FillTargetBlockScope(scope, function, target_type, block,
                            args, &block_scope, err))
    return Value();

  block->Execute(&block_scope, err);
  if (err->has_error())
    return Value();

  TargetGenerator::GenerateTarget(&block_scope, function, args,
                                  target_type, err);
  if (err->has_error())
    return Value();

  block_scope.CheckForUnusedVars(err);
  return Value();
}

}  // namespace

// action ----------------------------------------------------------------------

// Common help paragraph on script runtime execution directories.
#define SCRIPT_EXECUTION_CONTEXT \
    "  The script will be executed with the given arguments with the current\n"\
    "  directory being that of the root build directory. If you pass files\n"\
    "  to your script, see \"gn help rebase_path\" for how to convert\n" \
    "  file names to be relative to the build directory (file names in the\n" \
    "  sources, outputs, and inputs will be all treated as relative to the\n" \
    "  current build file and converted as needed automatically).\n"

// Common help paragraph on script output directories.
#define SCRIPT_EXECUTION_OUTPUTS \
    "  All output files must be inside the output directory of the build.\n" \
    "  You would generally use |$target_out_dir| or |$target_gen_dir| to\n" \
    "  reference the output or generated intermediate file directories,\n" \
    "  respectively.\n"

#define ACTION_DEPS \
    "  The \"deps\" and \"public_deps\" for an action will always be\n" \
    "  completed before any part of the action is run so it can depend on\n" \
    "  the output of previous steps. The \"data_deps\" will be built if the\n" \
    "  action is built, but may not have completed before all steps of the\n" \
    "  action are started. This can give additional parallelism in the build\n"\
    "  for runtime-only dependencies.\n"

const char kAction[] = "action";
const char kAction_HelpShort[] =
    "action: Declare a target that runs a script a single time.";
const char kAction_Help[] =
    "action: Declare a target that runs a script a single time.\n"
    "\n"
    "  This target type allows you to run a script a single time to produce\n"
    "  one or more output files. If you want to run a script once for each of\n"
    "  a set of input files, see \"gn help action_foreach\".\n"
    "\n"
    "Inputs\n"
    "\n"
    "  In an action the \"sources\" and \"inputs\" are treated the same:\n"
    "  they're both input dependencies on script execution with no special\n"
    "  handling. If you want to pass the sources to your script, you must do\n"
    "  so explicitly by including them in the \"args\". Note also that this\n"
    "  means there is no special handling of paths since GN doesn't know\n"
    "  which of the args are paths and not. You will want to use\n"
    "  rebase_path() to convert paths to be relative to the root_build_dir.\n"
    "\n"
    "  You can dynamically write input dependencies (for incremental rebuilds\n"
    "  if an input file changes) by writing a depfile when the script is run\n"
    "  (see \"gn help depfile\"). This is more flexible than \"inputs\".\n"
    "\n"
    "  If the command line length is very long, you can use response files\n"
    "  to pass args to your script. See \"gn help response_file_contents\".\n"
    "\n"
    "  It is recommended you put inputs to your script in the \"sources\"\n"
    "  variable, and stuff like other Python files required to run your\n"
    "  script in the \"inputs\" variable.\n"
    "\n"
    ACTION_DEPS
    "\n"
    "Outputs\n"
    "\n"
    "  You should specify files created by your script by specifying them in\n"
    "  the \"outputs\".\n"
    "\n"
    SCRIPT_EXECUTION_CONTEXT
    "\n"
    "File name handling\n"
    "\n"
    SCRIPT_EXECUTION_OUTPUTS
    "\n"
    "Variables\n"
    "\n"
    "  args, console, data, data_deps, depfile, deps, inputs, outputs*,\n"
    "  response_file_contents, script*, sources\n"
    "  * = required\n"
    "\n"
    "Example\n"
    "\n"
    "  action(\"run_this_guy_once\") {\n"
    "    script = \"doprocessing.py\"\n"
    "    sources = [ \"my_configuration.txt\" ]\n"
    "    outputs = [ \"$target_gen_dir/insightful_output.txt\" ]\n"
    "\n"
    "    # Our script imports this Python file so we want to rebuild if it\n"
    "    # changes.\n"
    "    inputs = [ \"helper_library.py\" ]\n"
    "\n"
    "    # Note that we have to manually pass the sources to our script if\n"
    "    # the script needs them as inputs.\n"
    "    args = [ \"--out\", rebase_path(target_gen_dir, root_build_dir) ] +\n"
    "           rebase_path(sources, root_build_dir)\n"
    "  }\n";

Value RunAction(Scope* scope,
                const FunctionCallNode* function,
                const std::vector<Value>& args,
                BlockNode* block,
                Err* err) {
  return ExecuteGenericTarget(functions::kAction, scope, function, args,
                              block, err);
}

// action_foreach --------------------------------------------------------------

const char kActionForEach[] = "action_foreach";
const char kActionForEach_HelpShort[] =
    "action_foreach: Declare a target that runs a script over a set of files.";
const char kActionForEach_Help[] =
    "action_foreach: Declare a target that runs a script over a set of files.\n"
    "\n"
    "  This target type allows you to run a script once-per-file over a set\n"
    "  of sources. If you want to run a script once that takes many files as\n"
    "  input, see \"gn help action\".\n"
    "\n"
    "Inputs\n"
    "\n"
    "  The script will be run once per file in the \"sources\" variable. The\n"
    "  \"outputs\" variable should specify one or more files with a source\n"
    "  expansion pattern in it (see \"gn help source_expansion\"). The output\n"
    "  file(s) for each script invocation should be unique. Normally you\n"
    "  use \"{{source_name_part}}\" in each output file.\n"
    "\n"
    "  If your script takes additional data as input, such as a shared\n"
    "  configuration file or a Python module it uses, those files should be\n"
    "  listed in the \"inputs\" variable. These files are treated as\n"
    "  dependencies of each script invocation.\n"
    "\n"
    "  If the command line length is very long, you can use response files\n"
    "  to pass args to your script. See \"gn help response_file_contents\".\n"
    "\n"
    "  You can dynamically write input dependencies (for incremental rebuilds\n"
    "  if an input file changes) by writing a depfile when the script is run\n"
    "  (see \"gn help depfile\"). This is more flexible than \"inputs\".\n"
    "\n"
    ACTION_DEPS
    "\n"
    "Outputs\n"
    "\n"
    SCRIPT_EXECUTION_CONTEXT
    "\n"
    "File name handling\n"
    "\n"
    SCRIPT_EXECUTION_OUTPUTS
    "\n"
    "Variables\n"
    "\n"
    "  args, console, data, data_deps, depfile, deps, inputs, outputs*,\n"
    "  response_file_contents, script*, sources*\n"
    "  * = required\n"
    "\n"
    "Example\n"
    "\n"
    "  # Runs the script over each IDL file. The IDL script will generate\n"
    "  # both a .cc and a .h file for each input.\n"
    "  action_foreach(\"my_idl\") {\n"
    "    script = \"idl_processor.py\"\n"
    "    sources = [ \"foo.idl\", \"bar.idl\" ]\n"
    "\n"
    "    # Our script reads this file each time, so we need to list is as a\n"
    "    # dependency so we can rebuild if it changes.\n"
    "    inputs = [ \"my_configuration.txt\" ]\n"
    "\n"
    "    # Transformation from source file name to output file names.\n"
    "    outputs = [ \"$target_gen_dir/{{source_name_part}}.h\",\n"
    "                \"$target_gen_dir/{{source_name_part}}.cc\" ]\n"
    "\n"
    "    # Note that since \"args\" is opaque to GN, if you specify paths\n"
    "    # here, you will need to convert it to be relative to the build\n"
    "    # directory using \"rebase_path()\".\n"
    "    args = [\n"
    "      \"{{source}}\",\n"
    "      \"-o\",\n"
    "      rebase_path(relative_target_gen_dir, root_build_dir) +\n"
    "        \"/{{source_name_part}}.h\" ]\n"
    "  }\n"
    "\n";
Value RunActionForEach(Scope* scope,
                       const FunctionCallNode* function,
                       const std::vector<Value>& args,
                       BlockNode* block,
                       Err* err) {
  return ExecuteGenericTarget(functions::kActionForEach, scope, function, args,
                              block, err);
}

// bundle_data -----------------------------------------------------------------

const char kBundleData[] = "bundle_data";
const char kBundleData_HelpShort[] =
    "bundle_data: [iOS/OS X] Declare a target without output.";
const char kBundleData_Help[] =
    "bundle_data: [iOS/OS X] Declare a target without output.\n"
    "\n"
    "  This target type allows to declare data that is required at runtime.\n"
    "  It is used to inform \"create_bundle\" targets of the files to copy\n"
    "  into generated bundle, see \"gn help create_bundle\" for help.\n"
    "\n"
    "  The target must define a list of files as \"sources\" and a single\n"
    "  \"outputs\". If there are multiple files, source expansions must be\n"
    "  used to express the output. The output must reference a file inside\n"
    "  of {{bundle_root_dir}}.\n"
    "\n"
    "  This target can be used on all platforms though it is designed only to\n"
    "  generate iOS/OS X bundle. In cross-platform projects, it is advised to\n"
    "  put it behind iOS/Mac conditionals.\n"
    "\n"
    "  See \"gn help create_bundle\" for more information.\n"
    "\n"
    "Variables\n"
    "\n"
    "  sources*, outputs*, deps, data_deps, public_deps, visibility\n"
    "  * = required\n"
    "\n"
    "Examples\n"
    "\n"
    "  bundle_data(\"icudata\") {\n"
    "    sources = [ \"sources/data/in/icudtl.dat\" ]\n"
    "    outputs = [ \"{{bundle_resources_dir}}/{{source_file_part}}\" ]\n"
    "  }\n"
    "\n"
    "  bundle_data(\"base_unittests_bundle_data]\") {\n"
    "    sources = [ \"test/data\" ]\n"
    "    outputs = [\n"
    "      \"{{bundle_resources_dir}}/{{source_root_relative_dir}}/\" +\n"
    "          \"{{source_file_part}}\"\n"
    "    ]\n"
    "  }\n"
    "\n"
    "  bundle_data(\"material_typography_bundle_data\") {\n"
    "    sources = [\n"
    "      \"src/MaterialTypography.bundle/Roboto-Bold.ttf\",\n"
    "      \"src/MaterialTypography.bundle/Roboto-Italic.ttf\",\n"
    "      \"src/MaterialTypography.bundle/Roboto-Regular.ttf\",\n"
    "      \"src/MaterialTypography.bundle/Roboto-Thin.ttf\",\n"
    "    ]\n"
    "    outputs = [\n"
    "      \"{{bundle_resources_dir}}/MaterialTypography.bundle/\"\n"
    "          \"{{source_file_part}}\"\n"
    "    ]\n"
    "  }\n";

Value RunBundleData(Scope* scope,
                    const FunctionCallNode* function,
                    const std::vector<Value>& args,
                    BlockNode* block,
                    Err* err) {
  return ExecuteGenericTarget(functions::kBundleData, scope, function, args,
                              block, err);
}

// create_bundle ---------------------------------------------------------------

const char kCreateBundle[] = "create_bundle";
const char kCreateBundle_HelpShort[] =
    "create_bundle: [iOS/OS X] Build an OS X / iOS bundle.";
const char kCreateBundle_Help[] =
    "create_bundle: [iOS/OS X] Build an OS X / iOS bundle.\n"
    "\n"
    "  This target generates an iOS/OS X bundle (which is a directory with a\n"
    "  well-know structure). This target does not define any sources, instead\n"
    "  they are computed from all \"bundle_data\" target this one depends on\n"
    "  transitively (the recursion stops at \"create_bundle\" targets).\n"
    "\n"
    "  The \"bundle_*_dir\" properties must be defined. They will be used for\n"
    "  the expansion of {{bundle_*_dir}} rules in \"bundle_data\" outputs.\n"
    "\n"
    "  This target can be used on all platforms though it is designed only to\n"
    "  generate iOS/OS X bundle. In cross-platform projects, it is advised to\n"
    "  put it behind iOS/Mac conditionals.\n"
    "\n"
    "  If a create_bundle is specified as a data_deps for another target, the\n"
    "  bundle is considered a leaf, and its public and private dependencies\n"
    "  will not contribute to any data or data_deps. Required runtime\n"
    "  dependencies should be placed in the bundle. A create_bundle can\n"
    "  declare its own explicit data and data_deps, however.\n"
    "\n"
    "Code signing\n"
    "\n"
    "  Some bundle needs to be code signed as part of the build (on iOS all\n"
    "  application needs to be code signed to run on a device). The code\n"
    "  signature can be configured via the code_signing_script variable.\n"
    "\n"
    "  If set, code_signing_script is the path of a script that invoked after\n"
    "  all files have been moved into the bundle. The script must not change\n"
    "  any file in the bundle, but may add new files.\n"
    "\n"
    "  If code_signing_script is defined, then code_signing_outputs must also\n"
    "  be defined and non-empty to inform when the script needs to be re-run.\n"
    "  The code_signing_args will be passed as is to the script (so path have\n"
    "  to be rebased) and additional inputs may be listed with the variable\n"
    "  code_signing_sources.\n"
    "\n"
    "Variables\n"
    "\n"
    "  bundle_root_dir*, bundle_resources_dir*, bundle_executable_dir*,\n"
    "  bundle_plugins_dir*, bundle_deps_filter, deps, data_deps, public_deps,\n"
    "  visibility, product_type, code_signing_args, code_signing_script,\n"
    "  code_signing_sources, code_signing_outputs\n"
    "  * = required\n"
    "\n"
    "Example\n"
    "\n"
    "  # Defines a template to create an application. On most platform, this\n"
    "  # is just an alias for an \"executable\" target, but on iOS/OS X, it\n"
    "  # builds an application bundle.\n"
    "  template(\"app\") {\n"
    "    if (!is_ios && !is_mac) {\n"
    "      executable(target_name) {\n"
    "        forward_variables_from(invoker, \"*\")\n"
    "      }\n"
    "    } else {\n"
    "      app_name = target_name\n"
    "      gen_path = target_gen_dir\n"
    "\n"
    "      action(\"${app_name}_generate_info_plist\") {\n"
    "        script = [ \"//build/ios/ios_gen_plist.py\" ]\n"
    "        sources = [ \"templates/Info.plist\" ]\n"
    "        outputs = [ \"$gen_path/Info.plist\" ]\n"
    "        args = rebase_path(sources, root_build_dir) +\n"
    "               rebase_path(outputs, root_build_dir)\n"
    "      }\n"
    "\n"
    "      bundle_data(\"${app_name}_bundle_info_plist\") {\n"
    "        deps = [ \":${app_name}_generate_info_plist\" ]\n"
    "        sources = [ \"$gen_path/Info.plist\" ]\n"
    "        outputs = [ \"{{bundle_root_dir}}/Info.plist\" ]\n"
    "      }\n"
    "\n"
    "      executable(\"${app_name}_generate_executable\") {\n"
    "        forward_variables_from(invoker, \"*\", [\n"
    "                                               \"output_name\",\n"
    "                                               \"visibility\",\n"
    "                                             ])\n"
    "        output_name =\n"
    "            rebase_path(\"$gen_path/$app_name\", root_build_dir)\n"
    "      }\n"
    "\n"
    "      code_signing =\n"
    "          defined(invoker.code_signing) && invoker.code_signing\n"
    "\n"
    "      if (is_ios && !code_signing) {\n"
    "        bundle_data(\"${app_name}_bundle_executable\") {\n"
    "          deps = [ \":${app_name}_generate_executable\" ]\n"
    "          sources = [ \"$gen_path/$app_name\" ]\n"
    "          outputs = [ \"{{bundle_executable_dir}}/$app_name\" ]\n"
    "        }\n"
    "      }\n"
    "\n"
    "      create_bundle(\"${app_name}.app\") {\n"
    "        product_type = \"com.apple.product-type.application\"\n"
    "        if (is_ios) {\n"
    "          bundle_root_dir = \"${root_build_dir}/$target_name\"\n"
    "          bundle_resources_dir = bundle_root_dir\n"
    "          bundle_executable_dir = bundle_root_dir\n"
    "          bundle_plugins_dir = bundle_root_dir + \"/Plugins\"\n"
    "        } else {\n"
    "          bundle_root_dir = \"${root_build_dir}/target_name/Contents\"\n"
    "          bundle_resources_dir = bundle_root_dir + \"/Resources\"\n"
    "          bundle_executable_dir = bundle_root_dir + \"/MacOS\"\n"
    "          bundle_plugins_dir = bundle_root_dir + \"/Plugins\"\n"
    "        }\n"
    "        deps = [ \":${app_name}_bundle_info_plist\" ]\n"
    "        if (is_ios && code_signing) {\n"
    "          deps += [ \":${app_name}_generate_executable\" ]\n"
    "          code_signing_script = \"//build/config/ios/codesign.py\"\n"
    "          code_signing_sources = [\n"
    "            invoker.entitlements_path,\n"
    "            \"$target_gen_dir/$app_name\",\n"
    "          ]\n"
    "          code_signing_outputs = [\n"
    "            \"$bundle_root_dir/$app_name\",\n"
    "            \"$bundle_root_dir/_CodeSignature/CodeResources\",\n"
    "            \"$bundle_root_dir/embedded.mobileprovision\",\n"
    "            \"$target_gen_dir/$app_name.xcent\",\n"
    "          ]\n"
    "          code_signing_args = [\n"
    "            \"-i=\" + ios_code_signing_identity,\n"
    "            \"-b=\" + rebase_path(\n"
    "                \"$target_gen_dir/$app_name\", root_build_dir),\n"
    "            \"-e=\" + rebase_path(\n"
    "                invoker.entitlements_path, root_build_dir),\n"
    "            \"-e=\" + rebase_path(\n"
    "                \"$target_gen_dir/$app_name.xcent\", root_build_dir),\n"
    "            rebase_path(bundle_root_dir, root_build_dir),\n"
    "          ]\n"
    "        } else {\n"
    "          deps += [ \":${app_name}_bundle_executable\" ]\n"
    "        }\n"
    "      }\n"
    "    }\n"
    "  }\n";

Value RunCreateBundle(Scope* scope,
                      const FunctionCallNode* function,
                      const std::vector<Value>& args,
                      BlockNode* block,
                      Err* err) {
  return ExecuteGenericTarget(functions::kCreateBundle, scope, function, args,
                              block, err);
}

// copy ------------------------------------------------------------------------

const char kCopy[] = "copy";
const char kCopy_HelpShort[] =
    "copy: Declare a target that copies files.";
const char kCopy_Help[] =
    "copy: Declare a target that copies files.\n"
    "\n"
    "File name handling\n"
    "\n"
    "  All output files must be inside the output directory of the build.\n"
    "  You would generally use |$target_out_dir| or |$target_gen_dir| to\n"
    "  reference the output or generated intermediate file directories,\n"
    "  respectively.\n"
    "\n"
    "  Both \"sources\" and \"outputs\" must be specified. Sources can "
    "include\n"
    "  as many files as you want, but there can only be one item in the\n"
    "  outputs list (plural is used for the name for consistency with\n"
    "  other target types).\n"
    "\n"
    "  If there is more than one source file, your output name should specify\n"
    "  a mapping from each source file to an output file name using source\n"
    "  expansion (see \"gn help source_expansion\"). The placeholders will\n"
    "  look like \"{{source_name_part}}\", for example.\n"
    "\n"
    "Examples\n"
    "\n"
    "  # Write a rule that copies a checked-in DLL to the output directory.\n"
    "  copy(\"mydll\") {\n"
    "    sources = [ \"mydll.dll\" ]\n"
    "    outputs = [ \"$target_out_dir/mydll.dll\" ]\n"
    "  }\n"
    "\n"
    "  # Write a rule to copy several files to the target generated files\n"
    "  # directory.\n"
    "  copy(\"myfiles\") {\n"
    "    sources = [ \"data1.dat\", \"data2.dat\", \"data3.dat\" ]\n"
    "\n"
    "    # Use source expansion to generate output files with the\n"
    "    # corresponding file names in the gen dir. This will just copy each\n"
    "    # file.\n"
    "    outputs = [ \"$target_gen_dir/{{source_file_part}}\" ]\n"
    "  }\n";

Value RunCopy(const FunctionCallNode* function,
              const std::vector<Value>& args,
              Scope* scope,
              Err* err) {
  if (!EnsureNotProcessingImport(function, scope, err) ||
      !EnsureNotProcessingBuildConfig(function, scope, err))
    return Value();
  TargetGenerator::GenerateTarget(scope, function, args, functions::kCopy, err);
  return Value();
}

// executable ------------------------------------------------------------------

const char kExecutable[] = "executable";
const char kExecutable_HelpShort[] =
    "executable: Declare an executable target.";
const char kExecutable_Help[] =
    "executable: Declare an executable target.\n"
    "\n"
    "Variables\n"
    "\n"
    CONFIG_VALUES_VARS_HELP
    DEPS_VARS
    DEPENDENT_CONFIG_VARS
    GENERAL_TARGET_VARS;

Value RunExecutable(Scope* scope,
                    const FunctionCallNode* function,
                    const std::vector<Value>& args,
                    BlockNode* block,
                    Err* err) {
  return ExecuteGenericTarget(functions::kExecutable, scope, function, args,
                              block, err);
}

// group -----------------------------------------------------------------------

const char kGroup[] = "group";
const char kGroup_HelpShort[] =
    "group: Declare a named group of targets.";
const char kGroup_Help[] =
    "group: Declare a named group of targets.\n"
    "\n"
    "  This target type allows you to create meta-targets that just collect a\n"
    "  set of dependencies into one named target. Groups can additionally\n"
    "  specify configs that apply to their dependents.\n"
    "\n"
    "  Depending on a group is exactly like depending directly on that\n"
    "  group's deps. \n"
    "\n"
    "Variables\n"
    "\n"
    DEPS_VARS
    DEPENDENT_CONFIG_VARS
    "\n"
    "Example\n"
    "\n"
    "  group(\"all\") {\n"
    "    deps = [\n"
    "      \"//project:runner\",\n"
    "      \"//project:unit_tests\",\n"
    "    ]\n"
    "  }\n";

Value RunGroup(Scope* scope,
               const FunctionCallNode* function,
               const std::vector<Value>& args,
               BlockNode* block,
               Err* err) {
  return ExecuteGenericTarget(functions::kGroup, scope, function, args,
                              block, err);
}

// loadable_module -------------------------------------------------------------

const char kLoadableModule[] = "loadable_module";
const char kLoadableModule_HelpShort[] =
    "loadable_module: Declare a loadable module target.";
const char kLoadableModule_Help[] =
    "loadable_module: Declare a loadable module target.\n"
    "\n"
    "  This target type allows you to create an object file that is (and can\n"
    "  only be) loaded and unloaded at runtime.\n"
    "\n"
    "  A loadable module will be specified on the linker line for targets\n"
    "  listing the loadable module in its \"deps\". If you don't want this\n"
    "  (if you don't need to dynamically load the library at runtime), then\n"
    "  you should use a \"shared_library\" target type instead.\n"
    "\n"
    "Variables\n"
    "\n"
    CONFIG_VALUES_VARS_HELP
    DEPS_VARS
    DEPENDENT_CONFIG_VARS
    GENERAL_TARGET_VARS;

Value RunLoadableModule(Scope* scope,
                       const FunctionCallNode* function,
                       const std::vector<Value>& args,
                       BlockNode* block,
                       Err* err) {
  return ExecuteGenericTarget(functions::kLoadableModule, scope, function, args,
                              block, err);
}

// shared_library --------------------------------------------------------------

const char kSharedLibrary[] = "shared_library";
const char kSharedLibrary_HelpShort[] =
    "shared_library: Declare a shared library target.";
const char kSharedLibrary_Help[] =
    "shared_library: Declare a shared library target.\n"
    "\n"
    "  A shared library will be specified on the linker line for targets\n"
    "  listing the shared library in its \"deps\". If you don't want this\n"
    "  (say you dynamically load the library at runtime), then you should\n"
    "  depend on the shared library via \"data_deps\" or, on Darwin\n"
    "  platforms, use a \"loadable_module\" target type instead.\n"
    "\n"
    "Variables\n"
    "\n"
    CONFIG_VALUES_VARS_HELP
    DEPS_VARS
    DEPENDENT_CONFIG_VARS
    GENERAL_TARGET_VARS;

Value RunSharedLibrary(Scope* scope,
                       const FunctionCallNode* function,
                       const std::vector<Value>& args,
                       BlockNode* block,
                       Err* err) {
  return ExecuteGenericTarget(functions::kSharedLibrary, scope, function, args,
                              block, err);
}

// source_set ------------------------------------------------------------------

extern const char kSourceSet[] = "source_set";
extern const char kSourceSet_HelpShort[] =
    "source_set: Declare a source set target.";
extern const char kSourceSet_Help[] =
    "source_set: Declare a source set target.\n"
    "\n"
    "  A source set is a collection of sources that get compiled, but are not\n"
    "  linked to produce any kind of library. Instead, the resulting object\n"
    "  files are implicitly added to the linker line of all targets that\n"
    "  depend on the source set.\n"
    "\n"
    "  In most cases, a source set will behave like a static library, except\n"
    "  no actual library file will be produced. This will make the build go\n"
    "  a little faster by skipping creation of a large static library, while\n"
    "  maintaining the organizational benefits of focused build targets.\n"
    "\n"
    "  The main difference between a source set and a static library is\n"
    "  around handling of exported symbols. Most linkers assume declaring\n"
    "  a function exported means exported from the static library. The linker\n"
    "  can then do dead code elimination to delete code not reachable from\n"
    "  exported functions.\n"
    "\n"
    "  A source set will not do this code elimination since there is no link\n"
    "  step. This allows you to link many sources sets into a shared library\n"
    "  and have the \"exported symbol\" notation indicate \"export from the\n"
    "  final shared library and not from the intermediate targets.\" There is\n"
    "  no way to express this concept when linking multiple static libraries\n"
    "  into a shared library.\n"
    "\n"
    "Variables\n"
    "\n"
    CONFIG_VALUES_VARS_HELP
    DEPS_VARS
    DEPENDENT_CONFIG_VARS
    GENERAL_TARGET_VARS;

Value RunSourceSet(Scope* scope,
                   const FunctionCallNode* function,
                   const std::vector<Value>& args,
                   BlockNode* block,
                   Err* err) {
  return ExecuteGenericTarget(functions::kSourceSet, scope, function, args,
                              block, err);
}

// static_library --------------------------------------------------------------

const char kStaticLibrary[] = "static_library";
const char kStaticLibrary_HelpShort[] =
    "static_library: Declare a static library target.";
const char kStaticLibrary_Help[] =
    "static_library: Declare a static library target.\n"
    "\n"
    "  Make a \".a\" / \".lib\" file.\n"
    "\n"
    "  If you only need the static library for intermediate results in the\n"
    "  build, you should consider a source_set instead since it will skip\n"
    "  the (potentially slow) step of creating the intermediate library file.\n"
    "\n"
    "Variables\n"
    "\n"
    "complete_static_lib\n"
    CONFIG_VALUES_VARS_HELP
    DEPS_VARS
    DEPENDENT_CONFIG_VARS
    GENERAL_TARGET_VARS;

Value RunStaticLibrary(Scope* scope,
                       const FunctionCallNode* function,
                       const std::vector<Value>& args,
                       BlockNode* block,
                       Err* err) {
  return ExecuteGenericTarget(functions::kStaticLibrary, scope, function, args,
                              block, err);
}

// target ---------------------------------------------------------------------

const char kTarget[] = "target";
const char kTarget_HelpShort[] =
    "target: Declare an target with the given programmatic type.";
const char kTarget_Help[] =
    "target: Declare an target with the given programmatic type.\n"
    "\n"
    "  target(target_type_string, target_name_string) { ... }\n"
    "\n"
    "  The target() function is a way to invoke a built-in target or template\n"
    "  with a type determined at runtime. This is useful for cases where the\n"
    "  type of a target might not be known statically.\n"
    "\n"
    "  Only templates and built-in target functions are supported for the\n"
    "  target_type_string parameter. Arbitrary functions, configs, and\n"
    "  toolchains are not supported.\n"
    "\n"
    "  The call:\n"
    "    target(\"source_set\", \"doom_melon\") {\n"
    "  Is equivalent to:\n"
    "    source_set(\"doom_melon\") {\n"
    "\n"
    "Example\n"
    "\n"
    "  if (foo_build_as_shared) {\n"
    "    my_type = \"shared_library\"\n"
    "  } else {\n"
    "    my_type = \"source_set\"\n"
    "  }\n"
    "\n"
    "  target(my_type, \"foo\") {\n"
    "    ...\n"
    "  }\n";
Value RunTarget(Scope* scope,
                const FunctionCallNode* function,
                const std::vector<Value>& args,
                BlockNode* block,
                Err* err) {
  if (args.size() != 2) {
    *err = Err(function, "Expected two arguments.", "Try \"gn help target\".");
    return Value();
  }

  // The first argument must be a string (the target type). Don't type-check
  // the second argument since the target-specific function will do that.
  if (!args[0].VerifyTypeIs(Value::STRING, err))
    return Value();
  const std::string& target_type = args[0].string_value();

  // The rest of the args are passed to the function.
  std::vector<Value> sub_args(args.begin() + 1, args.end());

  // Run a template if it is one.
  const Template* templ = scope->GetTemplate(target_type);
  if (templ)
    return templ->Invoke(scope, function, target_type, sub_args, block, err);

  // Otherwise, assume the target is a built-in target type.
  return ExecuteGenericTarget(target_type.c_str(), scope, function, sub_args,
                              block, err);
}

}  // namespace functions
