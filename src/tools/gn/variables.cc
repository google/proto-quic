// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/gn/variables.h"

namespace variables {

// Built-in variables ----------------------------------------------------------

const char kHostCpu[] = "host_cpu";
const char kHostCpu_HelpShort[] =
    "host_cpu: [string] The processor architecture that GN is running on.";
const char kHostCpu_Help[] =
    "host_cpu: The processor architecture that GN is running on.\n"
    "\n"
    "  This is value is exposed so that cross-compile toolchains can\n"
    "  access the host architecture when needed.\n"
    "\n"
    "  The value should generally be considered read-only, but it can be\n"
    "  overriden in order to handle unusual cases where there might\n"
    "  be multiple plausible values for the host architecture (e.g., if\n"
    "  you can do either 32-bit or 64-bit builds). The value is not used\n"
    "  internally by GN for any purpose.\n"
    "\n"
    "Some possible values:\n"
    "  - \"x64\"\n"
    "  - \"x86\"\n";

const char kHostOs[] = "host_os";
const char kHostOs_HelpShort[] =
    "host_os: [string] The operating system that GN is running on.";
const char kHostOs_Help[] =
    "host_os: [string] The operating system that GN is running on.\n"
    "\n"
    "  This value is exposed so that cross-compiles can access the host\n"
    "  build system's settings.\n"
    "\n"
    "  This value should generally be treated as read-only. It, however,\n"
    "  is not used internally by GN for any purpose.\n"
    "\n"
    "Some possible values:\n"
    "  - \"linux\"\n"
    "  - \"mac\"\n"
    "  - \"win\"\n";

const char kInvoker[] = "invoker";
const char kInvoker_HelpShort[] =
    "invoker: [string] The invoking scope inside a template.";
const char kInvoker_Help[] =
    "invoker: [string] The invoking scope inside a template.\n"
    "\n"
    "  Inside a template invocation, this variable refers to the scope of\n"
    "  the invoker of the template. Outside of template invocations, this\n"
    "  variable is undefined.\n"
    "\n"
    "  All of the variables defined inside the template invocation are\n"
    "  accessible as members of the \"invoker\" scope. This is the way that\n"
    "  templates read values set by the callers.\n"
    "\n"
    "  This is often used with \"defined\" to see if a value is set on the\n"
    "  invoking scope.\n"
    "\n"
    "  See \"gn help template\" for more examples.\n"
    "\n"
    "Example\n"
    "\n"
    "  template(\"my_template\") {\n"
    "    print(invoker.sources)       # Prints [ \"a.cc\", \"b.cc\" ]\n"
    "    print(defined(invoker.foo))  # Prints false.\n"
    "    print(defined(invoker.bar))  # Prints true.\n"
    "  }\n"
    "\n"
    "  my_template(\"doom_melon\") {\n"
    "    sources = [ \"a.cc\", \"b.cc\" ]\n"
    "    bar = 123\n"
    "  }\n";

const char kTargetCpu[] = "target_cpu";
const char kTargetCpu_HelpShort[] =
    "target_cpu: [string] The desired cpu architecture for the build.";
const char kTargetCpu_Help[] =
    "target_cpu: The desired cpu architecture for the build.\n"
    "\n"
    "  This value should be used to indicate the desired architecture for\n"
    "  the primary objects of the build. It will match the cpu architecture\n"
    "  of the default toolchain, but not necessarily the current toolchain.\n"
    "\n"
    "  In many cases, this is the same as \"host_cpu\", but in the case\n"
    "  of cross-compiles, this can be set to something different. This\n"
    "  value is different from \"current_cpu\" in that it does not change\n"
    "  based on the current toolchain. When writing rules, \"current_cpu\"\n"
    "  should be used rather than \"target_cpu\" most of the time.\n"
    "\n"
    "  This value is not used internally by GN for any purpose, so it\n"
    "  may be set to whatever value is needed for the build.\n"
    "  GN defaults this value to the empty string (\"\") and the\n"
    "  configuration files should set it to an appropriate value\n"
    "  (e.g., setting it to the value of \"host_cpu\") if it is not\n"
    "  overridden on the command line or in the args.gn file.\n"
    "\n"
    "  Where practical, use one of the following list of common values:\n"
    "\n"
    "Possible values:\n"
    "  - \"x86\"\n"
    "  - \"x64\"\n"
    "  - \"arm\"\n"
    "  - \"arm64\"\n"
    "  - \"mipsel\"\n";

const char kTargetName[] = "target_name";
const char kTargetName_HelpShort[] =
    "target_name: [string] The name of the current target.";
const char kTargetName_Help[] =
    "target_name: [string] The name of the current target.\n"
    "\n"
    "  Inside a target or template invocation, this variable refers to the\n"
    "  name given to the target or template invocation. Outside of these,\n"
    "  this variable is undefined.\n"
    "\n"
    "  This is most often used in template definitions to name targets\n"
    "  defined in the template based on the name of the invocation. This\n"
    "  is necessary both to ensure generated targets have unique names and\n"
    "  to generate a target with the exact name of the invocation that\n"
    "  other targets can depend on.\n"
    "\n"
    "  Be aware that this value will always reflect the innermost scope. So\n"
    "  when defining a target inside a template, target_name will refer to\n"
    "  the target rather than the template invocation. To get the name of the\n"
    "  template invocation in this case, you should save target_name to a\n"
    "  temporary variable outside of any target definitions.\n"
    "\n"
    "  See \"gn help template\" for more examples.\n"
    "\n"
    "Example\n"
    "\n"
    "  executable(\"doom_melon\") {\n"
    "    print(target_name)    # Prints \"doom_melon\".\n"
    "  }\n"
    "\n"
    "  template(\"my_template\") {\n"
    "    print(target_name)    # Prints \"space_ray\" when invoked below.\n"
    "\n"
    "    executable(target_name + \"_impl\") {\n"
    "      print(target_name)  # Prints \"space_ray_impl\".\n"
    "    }\n"
    "  }\n"
    "\n"
    "  my_template(\"space_ray\") {\n"
    "  }\n";

const char kTargetOs[] = "target_os";
const char kTargetOs_HelpShort[] =
    "target_os: [string] The desired operating system for the build.";
const char kTargetOs_Help[] =
    "target_os: The desired operating system for the build.\n"
    "\n"
    "  This value should be used to indicate the desired operating system\n"
    "  for the primary object(s) of the build. It will match the OS of\n"
    "  the default toolchain.\n"
    "\n"
    "  In many cases, this is the same as \"host_os\", but in the case of\n"
    "  cross-compiles, it may be different. This variable differs from\n"
    "  \"current_os\" in that it can be referenced from inside any\n"
    "  toolchain and will always return the initial value.\n"
    "\n"
    "  This should be set to the most specific value possible. So,\n"
    "  \"android\" or \"chromeos\" should be used instead of \"linux\"\n"
    "  where applicable, even though Android and ChromeOS are both Linux\n"
    "  variants. This can mean that one needs to write\n"
    "\n"
    "      if (target_os == \"android\" || target_os == \"linux\") {\n"
    "          # ...\n"
    "      }\n"
    "\n"
    "  and so forth.\n"
    "\n"
    "  This value is not used internally by GN for any purpose, so it\n"
    "  may be set to whatever value is needed for the build.\n"
    "  GN defaults this value to the empty string (\"\") and the\n"
    "  configuration files should set it to an appropriate value\n"
    "  (e.g., setting it to the value of \"host_os\") if it is not\n"
    "  set via the command line or in the args.gn file.\n"
    "\n"
    "  Where practical, use one of the following list of common values:\n"
    "\n"
    "Possible values:\n"
    "  - \"android\"\n"
    "  - \"chromeos\"\n"
    "  - \"ios\"\n"
    "  - \"linux\"\n"
    "  - \"nacl\"\n"
    "  - \"mac\"\n"
    "  - \"win\"\n";

const char kCurrentCpu[] = "current_cpu";
const char kCurrentCpu_HelpShort[] =
    "current_cpu: [string] The processor architecture of the current "
        "toolchain.";
const char kCurrentCpu_Help[] =
    "current_cpu: The processor architecture of the current toolchain.\n"
    "\n"
    "  The build configuration usually sets this value based on the value\n"
    "  of \"host_cpu\" (see \"gn help host_cpu\") and then threads\n"
    "  this through the toolchain definitions to ensure that it always\n"
    "  reflects the appropriate value.\n"
    "\n"
    "  This value is not used internally by GN for any purpose. It is\n"
    "  set it to the empty string (\"\") by default but is declared so\n"
    "  that it can be overridden on the command line if so desired.\n"
    "\n"
    "  See \"gn help target_cpu\" for a list of common values returned.\n";

const char kCurrentOs[] = "current_os";
const char kCurrentOs_HelpShort[] =
    "current_os: [string] The operating system of the current toolchain.";
const char kCurrentOs_Help[] =
    "current_os: The operating system of the current toolchain.\n"
    "\n"
    "  The build configuration usually sets this value based on the value\n"
    "  of \"target_os\" (see \"gn help target_os\"), and then threads this\n"
    "  through the toolchain definitions to ensure that it always reflects\n"
    "  the appropriate value.\n"
    "\n"
    "  This value is not used internally by GN for any purpose. It is\n"
    "  set it to the empty string (\"\") by default but is declared so\n"
    "  that it can be overridden on the command line if so desired.\n"
    "\n"
    "  See \"gn help target_os\" for a list of common values returned.\n";

const char kCurrentToolchain[] = "current_toolchain";
const char kCurrentToolchain_HelpShort[] =
    "current_toolchain: [string] Label of the current toolchain.";
const char kCurrentToolchain_Help[] =
    "current_toolchain: Label of the current toolchain.\n"
    "\n"
    "  A fully-qualified label representing the current toolchain. You can\n"
    "  use this to make toolchain-related decisions in the build. See also\n"
    "  \"default_toolchain\".\n"
    "\n"
    "Example\n"
    "\n"
    "  if (current_toolchain == \"//build:64_bit_toolchain\") {\n"
    "    executable(\"output_thats_64_bit_only\") {\n"
    "      ...\n";

const char kDefaultToolchain[] = "default_toolchain";
const char kDefaultToolchain_HelpShort[] =
    "default_toolchain: [string] Label of the default toolchain.";
const char kDefaultToolchain_Help[] =
    "default_toolchain: [string] Label of the default toolchain.\n"
    "\n"
    "  A fully-qualified label representing the default toolchain, which may\n"
    "  not necessarily be the current one (see \"current_toolchain\").\n";

const char kPythonPath[] = "python_path";
const char kPythonPath_HelpShort[] =
    "python_path: [string] Absolute path of Python.";
const char kPythonPath_Help[] =
    "python_path: Absolute path of Python.\n"
    "\n"
    "  Normally used in toolchain definitions if running some command\n"
    "  requires Python. You will normally not need this when invoking scripts\n"
    "  since GN automatically finds it for you.\n";

const char kRootBuildDir[] = "root_build_dir";
const char kRootBuildDir_HelpShort[] =
  "root_build_dir: [string] Directory where build commands are run.";
const char kRootBuildDir_Help[] =
  "root_build_dir: [string] Directory where build commands are run.\n"
  "\n"
  "  This is the root build output directory which will be the current\n"
  "  directory when executing all compilers and scripts.\n"
  "\n"
  "  Most often this is used with rebase_path (see \"gn help rebase_path\")\n"
  "  to convert arguments to be relative to a script's current directory.\n";

const char kRootGenDir[] = "root_gen_dir";
const char kRootGenDir_HelpShort[] =
    "root_gen_dir: [string] Directory for the toolchain's generated files.";
const char kRootGenDir_Help[] =
    "root_gen_dir: Directory for the toolchain's generated files.\n"
    "\n"
    "  Absolute path to the root of the generated output directory tree for\n"
    "  the current toolchain. An example would be \"//out/Debug/gen\" for the\n"
    "  default toolchain, or \"//out/Debug/arm/gen\" for the \"arm\"\n"
    "  toolchain.\n"
    "\n"
    "  This is primarily useful for setting up include paths for generated\n"
    "  files. If you are passing this to a script, you will want to pass it\n"
    "  through rebase_path() (see \"gn help rebase_path\") to convert it\n"
    "  to be relative to the build directory.\n"
    "\n"
    "  See also \"target_gen_dir\" which is usually a better location for\n"
    "  generated files. It will be inside the root generated dir.\n";

const char kRootOutDir[] = "root_out_dir";
const char kRootOutDir_HelpShort[] =
    "root_out_dir: [string] Root directory for toolchain output files.";
const char kRootOutDir_Help[] =
    "root_out_dir: [string] Root directory for toolchain output files.\n"
    "\n"
    "  Absolute path to the root of the output directory tree for the current\n"
    "  toolchain. It will not have a trailing slash.\n"
    "\n"
    "  For the default toolchain this will be the same as the root_build_dir.\n"
    "  An example would be \"//out/Debug\" for the default toolchain, or\n"
    "  \"//out/Debug/arm\" for the \"arm\" toolchain.\n"
    "\n"
    "  This is primarily useful for setting up script calls. If you are\n"
    "  passing this to a script, you will want to pass it through\n"
    "  rebase_path() (see \"gn help rebase_path\") to convert it\n"
    "  to be relative to the build directory.\n"
    "\n"
    "  See also \"target_out_dir\" which is usually a better location for\n"
    "  output files. It will be inside the root output dir.\n"
    "\n"
    "Example\n"
    "\n"
    "  action(\"myscript\") {\n"
    "    # Pass the output dir to the script.\n"
    "    args = [ \"-o\", rebase_path(root_out_dir, root_build_dir) ]\n"
    "  }\n";

const char kTargetGenDir[] = "target_gen_dir";
const char kTargetGenDir_HelpShort[] =
    "target_gen_dir: [string] Directory for a target's generated files.";
const char kTargetGenDir_Help[] =
    "target_gen_dir: Directory for a target's generated files.\n"
    "\n"
    "  Absolute path to the target's generated file directory. This will be\n"
    "  the \"root_gen_dir\" followed by the relative path to the current\n"
    "  build file. If your file is in \"//tools/doom_melon\" then\n"
    "  target_gen_dir would be \"//out/Debug/gen/tools/doom_melon\". It will\n"
    "  not have a trailing slash.\n"
    "\n"
    "  This is primarily useful for setting up include paths for generated\n"
    "  files. If you are passing this to a script, you will want to pass it\n"
    "  through rebase_path() (see \"gn help rebase_path\") to convert it\n"
    "  to be relative to the build directory.\n"
    "\n"
    "  See also \"gn help root_gen_dir\".\n"
    "\n"
    "Example\n"
    "\n"
    "  action(\"myscript\") {\n"
    "    # Pass the generated output dir to the script.\n"
    "    args = [ \"-o\", rebase_path(target_gen_dir, root_build_dir) ]"
    "\n"
    "  }\n";

const char kTargetOutDir[] = "target_out_dir";
const char kTargetOutDir_HelpShort[] =
    "target_out_dir: [string] Directory for target output files.";
const char kTargetOutDir_Help[] =
    "target_out_dir: [string] Directory for target output files.\n"
    "\n"
    "  Absolute path to the target's generated file directory. If your\n"
    "  current target is in \"//tools/doom_melon\" then this value might be\n"
    "  \"//out/Debug/obj/tools/doom_melon\". It will not have a trailing\n"
    "  slash.\n"
    "\n"
    "  This is primarily useful for setting up arguments for calling\n"
    "  scripts. If you are passing this to a script, you will want to pass it\n"
    "  through rebase_path() (see \"gn help rebase_path\") to convert it\n"
    "  to be relative to the build directory.\n"
    "\n"
    "  See also \"gn help root_out_dir\".\n"
    "\n"
    "Example\n"
    "\n"
    "  action(\"myscript\") {\n"
    "    # Pass the output dir to the script.\n"
    "    args = [ \"-o\", rebase_path(target_out_dir, root_build_dir) ]"
    "\n"
    "  }\n";

// Target variables ------------------------------------------------------------

#define COMMON_ORDERING_HELP \
    "\n" \
    "Ordering of flags and values\n" \
    "\n" \
    "  1. Those set on the current target (not in a config).\n" \
    "  2. Those set on the \"configs\" on the target in order that the\n" \
    "     configs appear in the list.\n" \
    "  3. Those set on the \"all_dependent_configs\" on the target in order\n" \
    "     that the configs appear in the list.\n" \
    "  4. Those set on the \"public_configs\" on the target in order that\n" \
    "     those configs appear in the list.\n" \
    "  5. all_dependent_configs pulled from dependencies, in the order of\n" \
    "     the \"deps\" list. This is done recursively. If a config appears\n" \
    "     more than once, only the first occurance will be used.\n" \
    "  6. public_configs pulled from dependencies, in the order of the\n" \
    "     \"deps\" list. If a dependency is public, they will be applied\n" \
    "     recursively.\n"

const char kAllDependentConfigs[] = "all_dependent_configs";
const char kAllDependentConfigs_HelpShort[] =
    "all_dependent_configs: [label list] Configs to be forced on dependents.";
const char kAllDependentConfigs_Help[] =
    "all_dependent_configs: Configs to be forced on dependents.\n"
    "\n"
    "  A list of config labels.\n"
    "\n"
    "  All targets depending on this one, and recursively, all targets\n"
    "  depending on those, will have the configs listed in this variable\n"
    "  added to them. These configs will also apply to the current target.\n"
    "\n"
    "  This addition happens in a second phase once a target and all of its\n"
    "  dependencies have been resolved. Therefore, a target will not see\n"
    "  these force-added configs in their \"configs\" variable while the\n"
    "  script is running, and then can not be removed. As a result, this\n"
    "  capability should generally only be used to add defines and include\n"
    "  directories necessary to compile a target's headers.\n"
    "\n"
    "  See also \"public_configs\".\n"
    COMMON_ORDERING_HELP;

const char kAllowCircularIncludesFrom[] = "allow_circular_includes_from";
const char kAllowCircularIncludesFrom_HelpShort[] =
    "allow_circular_includes_from: [label list] Permit includes from deps.";
const char kAllowCircularIncludesFrom_Help[] =
    "allow_circular_includes_from: Permit includes from deps.\n"
    "\n"
    "  A list of target labels. Must be a subset of the target's \"deps\".\n"
    "  These targets will be permitted to include headers from the current\n"
    "  target despite the dependency going in the opposite direction.\n"
    "\n"
    "  When you use this, both targets must be included in a final binary\n"
    "  for it to link. To keep linker errors from happening, it is good\n"
    "  practice to have all external dependencies depend only on one of\n"
    "  the two targets, and to set the visibility on the other to enforce\n"
    "  this. Thus the targets will always be linked together in any output.\n"
    "\n"
    "Details\n"
    "\n"
    "  Normally, for a file in target A to include a file from target B,\n"
    "  A must list B as a dependency. This invariant is enforced by the\n"
    "  \"gn check\" command (and the --check flag to \"gn gen\" -- see\n"
    "  \"gn help check\").\n"
    "\n"
    "  Sometimes, two targets might be the same unit for linking purposes\n"
    "  (two source sets or static libraries that would always be linked\n"
    "  together in a final executable or shared library) and they each\n"
    "  include headers from the other: you want A to be able to include B's\n"
    "  headers, and B to include A's headers. This is not an ideal situation\n"
    "  but is sometimes unavoidable.\n"
    "\n"
    "  This list, if specified, lists which of the dependencies of the\n"
    "  current target can include header files from the current target.\n"
    "  That is, if A depends on B, B can only include headers from A if it is\n"
    "  in A's allow_circular_includes_from list. Normally includes must\n"
    "  follow the direction of dependencies, this flag allows them to go\n"
    "  in the opposite direction.\n"
    "\n"
    "Danger\n"
    "\n"
    "  In the above example, A's headers are likely to include headers from\n"
    "  A's dependencies. Those dependencies may have public_configs that\n"
    "  apply flags, defines, and include paths that make those headers work\n"
    "  properly.\n"
    "\n"
    "  With allow_circular_includes_from, B can include A's headers, and\n"
    "  transitively from A's dependencies, without having the dependencies\n"
    "  that would bring in the public_configs those headers need. The result\n"
    "  may be errors or inconsistent builds.\n"
    "\n"
    "  So when you use allow_circular_includes_from, make sure that any\n"
    "  compiler settings, flags, and include directories are the same between\n"
    "  both targets (consider putting such things in a shared config they can\n"
    "  both reference). Make sure the dependencies are also the same (you\n"
    "  might consider a group to collect such dependencies they both\n"
    "  depend on).\n"
    "\n"
    "Example\n"
    "\n"
    "  source_set(\"a\") {\n"
    "    deps = [ \":b\", \":a_b_shared_deps\" ]\n"
    "    allow_circular_includes_from = [ \":b\" ]\n"
    "    ...\n"
    "  }\n"
    "\n"
    "  source_set(\"b\") {\n"
    "    deps = [ \":a_b_shared_deps\" ]\n"
    "    # Sources here can include headers from a despite lack of deps.\n"
    "    ...\n"
    "  }\n"
    "\n"
    "  group(\"a_b_shared_deps\") {\n"
    "    public_deps = [ \":c\" ]\n"
    "  }\n";

const char kArflags[] = "arflags";
const char kArflags_HelpShort[] =
    "arflags: [string list] Arguments passed to static_library archiver.";
const char kArflags_Help[] =
    "arflags: Arguments passed to static_library archiver.\n"
    "\n"
    "  A list of flags passed to the archive/lib command that creates static\n"
    "  libraries.\n"
    "\n"
    "  arflags are NOT pushed to dependents, so applying arflags to source\n"
    "  sets or any other target type will be a no-op. As with ldflags,\n"
    "  you could put the arflags in a config and set that as a public or\n"
    "  \"all dependent\" config, but that will likely not be what you want.\n"
    "  If you have a chain of static libraries dependent on each other,\n"
    "  this can cause the flags to propagate up to other static libraries.\n"
    "  Due to the nature of how arflags are typically used, you will normally\n"
    "  want to apply them directly on static_library targets themselves.\n"
    COMMON_ORDERING_HELP;

const char kArgs[] = "args";
const char kArgs_HelpShort[] =
    "args: [string list] Arguments passed to an action.";
const char kArgs_Help[] =
    "args: Arguments passed to an action.\n"
    "\n"
    "  For action and action_foreach targets, args is the list of arguments\n"
    "  to pass to the script. Typically you would use source expansion (see\n"
    "  \"gn help source_expansion\") to insert the source file names.\n"
    "\n"
    "  See also \"gn help action\" and \"gn help action_foreach\".\n";

const char kAssertNoDeps[] = "assert_no_deps";
const char kAssertNoDeps_HelpShort[] =
    "assert_no_deps: [label pattern list] Ensure no deps on these targets.";
const char kAssertNoDeps_Help[] =
    "assert_no_deps: Ensure no deps on these targets.\n"
    "\n"
    "  A list of label patterns.\n"
    "\n"
    "  This list is a list of patterns that must not match any of the\n"
    "  transitive dependencies of the target. These include all public,\n"
    "  private, and data dependencies, and cross shared library boundaries.\n"
    "  This allows you to express that undesirable code isn't accidentally\n"
    "  added to downstream dependencies in a way that might otherwise be\n"
    "  difficult to notice.\n"
    "\n"
    "  Checking does not cross executable boundaries. If a target depends on\n"
    "  an executable, it's assumed that the executable is a tool that is\n"
    "  producing part of the build rather than something that is linked and\n"
    "  distributed. This allows assert_no_deps to express what is distributed\n"
    "  in the final target rather than depend on the internal build steps\n"
    "  (which may include non-distributable code).\n"
    "\n"
    "  See \"gn help label_pattern\" for the format of the entries in the\n"
    "  list. These patterns allow blacklisting individual targets or whole\n"
    "  directory hierarchies.\n"
    "\n"
    "  Sometimes it is desirable to enforce that many targets have no\n"
    "  dependencies on a target or set of targets. One efficient way to\n"
    "  express this is to create a group with the assert_no_deps rule on\n"
    "  it, and make that group depend on all targets you want to apply that\n"
    "  assertion to.\n"
    "\n"
    "Example\n"
    "\n"
    "  executable(\"doom_melon\") {\n"
    "    deps = [ \"//foo:bar\" ]\n"
    "    ...\n"
    "    assert_no_deps = [\n"
    "      \"//evil/*\",  # Don't link any code from the evil directory.\n"
    "      \"//foo:test_support\",  # This target is also disallowed.\n"
    "    ]\n"
    "  }\n";

const char kBundleRootDir[] = "bundle_root_dir";
const char kBundleRootDir_HelpShort[] =
    "bundle_root_dir: Expansion of {{bundle_root_dir}} in create_bundle.";
const char kBundleRootDir_Help[] =
    "bundle_root_dir: Expansion of {{bundle_root_dir}} in create_bundle.\n"
    "\n"
    "  A string corresponding to a path in root_build_dir.\n"
    "\n"
    "  This string is used by the \"create_bundle\" target to expand the\n"
    "  {{bundle_root_dir}} of the \"bundle_data\" target it depends on.\n"
    "  This must correspond to a path under root_build_dir.\n"
    "\n"
    "Example\n"
    "\n"
    "  bundle_data(\"info_plist\") {\n"
    "    sources = [ \"Info.plist\" ]\n"
    "    outputs = [ \"{{bundle_root_dir}}/Info.plist\" ]\n"
    "  }\n"
    "\n"
    "  create_bundle(\"doom_melon.app\") {\n"
    "    deps = [ \":info_plist\" ]\n"
    "    bundle_root_dir = root_build_dir + \"/doom_melon.app/Contents\"\n"
    "    bundle_resources_dir = bundle_root_dir + \"/Resources\"\n"
    "    bundle_executable_dir = bundle_root_dir + \"/MacOS\"\n"
    "    bundle_plugins_dir = bundle_root_dir + \"/PlugIns\"\n"
    "  }\n";

const char kBundleResourcesDir[] = "bundle_resources_dir";
const char kBundleResourcesDir_HelpShort[] =
    "bundle_resources_dir: "
        "Expansion of {{bundle_resources_dir}} in create_bundle.";
const char kBundleResourcesDir_Help[] =
    "bundle_resources_dir: "
        "Expansion of {{bundle_resources_dir}} in create_bundle.\n"
    "\n"
    "  A string corresponding to a path in $root_build_dir.\n"
    "\n"
    "  This string is used by the \"create_bundle\" target to expand the\n"
    "  {{bundle_resources_dir}} of the \"bundle_data\" target it depends on.\n"
    "  This must correspond to a path under \"bundle_root_dir\".\n"
    "\n"
    "  See \"gn help bundle_root_dir\" for examples.\n";

const char kBundleDepsFilter[] = "bundle_deps_filter";
const char kBundleDepsFilter_HelpShort[] =
    "bundle_deps_filter: [label list] A list of labels that are filtered out.";
const char kBundleDepsFilter_Help[] =
    "bundle_deps_filter: [label list] A list of labels that are filtered out.\n"
    "\n"
    "  A list of target labels.\n"
    "\n"
    "  This list contains target label patterns that should be filtered out\n"
    "  when creating the bundle. Any target matching one of those label will\n"
    "  be removed from the dependencies of the create_bundle target.\n"
    "\n"
    "  This is mostly useful when creating application extension bundle as\n"
    "  the application extension has access to runtime resources from the\n"
    "  application bundle and thus do not require a second copy.\n"
    "\n"
    "  See \"gn help create_bundle\" for more information.\n"
    "\n"
    "Example\n"
    "\n"
    "  create_bundle(\"today_extension\") {\n"
    "    deps = [\n"
    "      \"//base\"\n"
    "    ]\n"
    "    bundle_root_dir = \"$root_out_dir/today_extension.appex\"\n"
    "    bundle_deps_filter = [\n"
    "      # The extension uses //base but does not use any function calling\n"
    "      # into third_party/icu and thus does not need the icudtl.dat file.\n"
    "      \"//third_party/icu:icudata\",\n"
    "    ]\n"
    "  }\n";

const char kBundleExecutableDir[] = "bundle_executable_dir";
const char kBundleExecutableDir_HelpShort[] =
    "bundle_executable_dir: "
        "Expansion of {{bundle_executable_dir}} in create_bundle";
const char kBundleExecutableDir_Help[] =
    "bundle_executable_dir: "
        "Expansion of {{bundle_executable_dir}} in create_bundle.\n"
    "\n"
    "  A string corresponding to a path in $root_build_dir.\n"
    "\n"
    "  This string is used by the \"create_bundle\" target to expand the\n"
    "  {{bundle_executable_dir}} of the \"bundle_data\" target it depends on.\n"
    "  This must correspond to a path under \"bundle_root_dir\".\n"
    "\n"
    "  See \"gn help bundle_root_dir\" for examples.\n";

const char kBundlePlugInsDir[] = "bundle_plugins_dir";
const char kBundlePlugInsDir_HelpShort[] =
    "bundle_plugins_dir: "
        "Expansion of {{bundle_plugins_dir}} in create_bundle.";
const char kBundlePlugInsDir_Help[] =
    "bundle_plugins_dir: "
        "Expansion of {{bundle_plugins_dir}} in create_bundle.\n"
    "\n"
    "  A string corresponding to a path in $root_build_dir.\n"
    "\n"
    "  This string is used by the \"create_bundle\" target to expand the\n"
    "  {{bundle_plugins_dir}} of the \"bundle_data\" target it depends on.\n"
    "  This must correspond to a path under \"bundle_root_dir\".\n"
    "\n"
    "  See \"gn help bundle_root_dir\" for examples.\n";

const char kCflags[] = "cflags";
const char kCflags_HelpShort[] =
    "cflags: [string list] Flags passed to all C compiler variants.";
const char kCommonCflagsHelp[] =
    "cflags*: Flags passed to the C compiler.\n"
    "\n"
    "  A list of strings.\n"
    "\n"
    "  \"cflags\" are passed to all invocations of the C, C++, Objective C,\n"
    "  and Objective C++ compilers.\n"
    "\n"
    "  To target one of these variants individually, use \"cflags_c\",\n"
    "  \"cflags_cc\", \"cflags_objc\", and \"cflags_objcc\",\n"
    "  respectively. These variant-specific versions of cflags* will be\n"
    "  appended on the compiler command line after \"cflags\".\n"
    "\n"
    "  See also \"asmflags\" for flags for assembly-language files.\n"
    COMMON_ORDERING_HELP;
const char* kCflags_Help = kCommonCflagsHelp;

const char kAsmflags[] = "asmflags";
const char kAsmflags_HelpShort[] =
    "asmflags: [string list] Flags passed to the assembler.";
const char* kAsmflags_Help =
    "asmflags: Flags passed to the assembler.\n"
    "\n"
    "  A list of strings.\n"
    "\n"
    "  \"asmflags\" are passed to any invocation of a tool that takes an\n"
    "  .asm or .S file as input.\n"
    COMMON_ORDERING_HELP;

const char kCflagsC[] = "cflags_c";
const char kCflagsC_HelpShort[] =
    "cflags_c: [string list] Flags passed to the C compiler.";
const char* kCflagsC_Help = kCommonCflagsHelp;

const char kCflagsCC[] = "cflags_cc";
const char kCflagsCC_HelpShort[] =
    "cflags_cc: [string list] Flags passed to the C++ compiler.";
const char* kCflagsCC_Help = kCommonCflagsHelp;

const char kCflagsObjC[] = "cflags_objc";
const char kCflagsObjC_HelpShort[] =
    "cflags_objc: [string list] Flags passed to the Objective C compiler.";
const char* kCflagsObjC_Help = kCommonCflagsHelp;

const char kCflagsObjCC[] = "cflags_objcc";
const char kCflagsObjCC_HelpShort[] =
    "cflags_objcc: [string list] Flags passed to the Objective C++ compiler.";
const char* kCflagsObjCC_Help = kCommonCflagsHelp;

const char kCheckIncludes[] = "check_includes";
const char kCheckIncludes_HelpShort[] =
    "check_includes: [boolean] Controls whether a target's files are checked.";
const char kCheckIncludes_Help[] =
    "check_includes: [boolean] Controls whether a target's files are checked.\n"
    "\n"
    "  When true (the default), the \"gn check\" command (as well as\n"
    "  \"gn gen\" with the --check flag) will check this target's sources\n"
    "  and headers for proper dependencies.\n"
    "\n"
    "  When false, the files in this target will be skipped by default.\n"
    "  This does not affect other targets that depend on the current target,\n"
    "  it just skips checking the includes of the current target's files.\n"
    "\n"
    "  If there are a few conditionally included headers that trip up\n"
    "  checking, you can exclude headers individually by annotating them with\n"
    "  \"nogncheck\" (see \"gn help nogncheck\").\n"
    "\n"
    "  The topic \"gn help check\" has general information on how checking\n"
    "  works and advice on how to pass a check in problematic cases.\n"
    "\n"
    "Example\n"
    "\n"
    "  source_set(\"busted_includes\") {\n"
    "    # This target's includes are messed up, exclude it from checking.\n"
    "    check_includes = false\n"
    "    ...\n"
    "  }\n";

const char kCodeSigningArgs[] = "code_signing_args";
const char kCodeSigningArgs_HelpShort[] =
    "code_signing_args: [string list] Arguments passed to code signing script.";
const char kCodeSigningArgs_Help[] =
    "code_signing_args: [string list] Arguments passed to code signing "
        "script.\n"
    "\n"
    "  For create_bundle targets, code_signing_args is the list of arguments\n"
    "  to pass to the code signing script. Typically you would use source\n"
    "  expansion (see \"gn help source_expansion\") to insert the source file\n"
    "  names.\n"
    "\n"
    "  See also \"gn help create_bundle\".\n";

const char kCodeSigningScript[] = "code_signing_script";
const char kCodeSigningScript_HelpShort[] =
    "code_signing_script: [file name] Script for code signing.";
const char kCodeSigningScript_Help[] =
    "code_signing_script: [file name] Script for code signing."
    "\n"
    "  An absolute or buildfile-relative file name of a Python script to run\n"
    "  for a create_bundle target to perform code signing step.\n"
    "\n"
    "  See also \"gn help create_bundle\".\n";

const char kCodeSigningSources[] = "code_signing_sources";
const char kCodeSigningSources_HelpShort[] =
    "code_signing_sources: [file list] Sources for code signing step.";
const char kCodeSigningSources_Help[] =
    "code_signing_sources: [file list] Sources for code signing step.\n"
    "\n"
    "  A list of files used as input for code signing script step of a\n"
    "  create_bundle target. Non-absolute paths will be resolved relative to\n"
    "  the current build file.\n"
    "\n"
    "  See also \"gn help create_bundle\".\n";

const char kCodeSigningOutputs[] = "code_signing_outputs";
const char kCodeSigningOutputs_HelpShort[] =
    "code_signing_outputs: [file list] Output files for code signing step.";
const char kCodeSigningOutputs_Help[] =
    "code_signing_outputs: [file list] Output files for code signing step.\n"
    "\n"
    "  Outputs from the code signing step of a create_bundle target. Must\n"
    "  refer to files in the build directory.\n"
    "\n"
    "  See also \"gn help create_bundle\".\n";

const char kCompleteStaticLib[] = "complete_static_lib";
const char kCompleteStaticLib_HelpShort[] =
    "complete_static_lib: [boolean] Links all deps into a static library.";
const char kCompleteStaticLib_Help[] =
    "complete_static_lib: [boolean] Links all deps into a static library.\n"
    "\n"
    "  A static library normally doesn't include code from dependencies, but\n"
    "  instead forwards the static libraries and source sets in its deps up\n"
    "  the dependency chain until a linkable target (an executable or shared\n"
    "  library) is reached. The final linkable target only links each static\n"
    "  library once, even if it appears more than once in its dependency\n"
    "  graph.\n"
    "\n"
    "  In some cases the static library might be the final desired output.\n"
    "  For example, you may be producing a static library for distribution to\n"
    "  third parties. In this case, the static library should include code\n"
    "  for all dependencies in one complete package. However, complete static\n"
    "  libraries themselves are never linked into other complete static\n"
    "  libraries. All complete static libraries are for distribution and\n"
    "  linking them in would cause code duplication in this case. If the\n"
    "  static library is not for distribution, it should not be complete.\n"
    "\n"
    "  GN treats non-complete static libraries as source sets when they are\n"
    "  linked into complete static libraries. This is done because some tools\n"
    "  like AR do not handle dependent static libraries properly. This makes\n"
    "  it easier to write \"alink\" rules.\n"
    "\n"
    "  In rare cases it makes sense to list a header in more than one\n"
    "  target if it could be considered conceptually a member of both.\n"
    "  libraries.\n"
    "\n"
    "Example\n"
    "\n"
    "  static_library(\"foo\") {\n"
    "    complete_static_lib = true\n"
    "    deps = [ \"bar\" ]\n"
    "  }\n";

const char kConfigs[] = "configs";
const char kConfigs_HelpShort[] =
    "configs: [label list] Configs applying to this target or config.";
const char kConfigs_Help[] =
    "configs: Configs applying to this target or config.\n"
    "\n"
    "  A list of config labels.\n"
    "\n"
    "Configs on a target\n"
    "\n"
    "  When used on a target, the include_dirs, defines, etc. in each config\n"
    "  are appended in the order they appear to the compile command for each\n"
    "  file in the target. They will appear after the include_dirs, defines,\n"
    "  etc. that the target sets directly.\n"
    "\n"
    "  Since configs apply after the values set on a target, directly setting\n"
    "  a compiler flag will prepend it to the command line. If you want to\n"
    "  append a flag instead, you can put that flag in a one-off config and\n"
    "  append that config to the target's configs list.\n"
    "\n"
    "  The build configuration script will generally set up the default\n"
    "  configs applying to a given target type (see \"set_defaults\").\n"
    "  When a target is being defined, it can add to or remove from this\n"
    "  list.\n"
    "\n"
    "Configs on a config\n"
    "\n"
    "  It is possible to create composite configs by specifying configs on a\n"
    "  config. One might do this to forward values, or to factor out blocks\n"
    "  of settings from very large configs into more manageable named chunks.\n"
    "\n"
    "  In this case, the composite config is expanded to be the concatenation\n"
    "  of its own values, and in order, the values from its sub-configs\n"
    "  *before* anything else happens. This has some ramifications:\n"
    "\n"
    "   - A target has no visibility into a config's sub-configs. Target\n"
    "     code only sees the name of the composite config. It can't remove\n"
    "     sub-configs or opt in to only parts of it. The composite config may\n"
    "     not even be defined before the target is.\n"
    "\n"
    "   - You can get duplication of values if a config is listed twice, say,\n"
    "     on a target and in a sub-config that also applies. In other cases,\n"
    "     the configs applying to a target are de-duped. It's expected that\n"
    "     if a config is listed as a sub-config that it is only used in that\n"
    "     context. (Note that it's possible to fix this and de-dupe, but it's\n"
    "     not normally relevant and complicates the implementation.)\n"
    COMMON_ORDERING_HELP
    "\n"
    "Example\n"
    "\n"
    "  # Configs on a target.\n"
    "  source_set(\"foo\") {\n"
    "    # Don't use the default RTTI config that BUILDCONFIG applied to us.\n"
    "    configs -= [ \"//build:no_rtti\" ]\n"
    "\n"
    "    # Add some of our own settings.\n"
    "    configs += [ \":mysettings\" ]\n"
    "  }\n"
    "\n"
    "  # Create a default_optimization config that forwards to one of a set\n"
    "  # of more specialized configs depending on build flags. This pattern\n"
    "  # is useful because it allows a target to opt in to either a default\n"
    "  # set, or a more specific set, while avoid duplicating the settings in\n"
    "  # two places.\n"
    "  config(\"super_optimization\") {\n"
    "    cflags = [ ... ]\n"
    "  }\n"
    "  config(\"default_optimization\") {\n"
    "    if (optimize_everything) {\n"
    "      configs = [ \":super_optimization\" ]\n"
    "    } else {\n"
    "      configs = [ \":no_optimization\" ]\n"
    "    }\n"
    "  }\n";

const char kConsole[] = "console";
const char kConsole_HelpShort[] =
    "console: [boolean] Run this action in the console pool.";
const char kConsole_Help[] =
    "console: Run this action in the console pool.\n"
    "\n"
    "  Boolean. Defaults to false.\n"
    "\n"
    "  Actions marked \"console = true\" will be run in the built-in ninja\n"
    "  \"console\" pool. They will have access to real stdin and stdout, and\n"
    "  output will not be buffered by ninja. This can be useful for\n"
    "  long-running actions with progress logs, or actions that require user \n"
    "  input.\n"
    "\n"
    "  Only one console pool target can run at any one time in Ninja. Refer\n"
    "  to the Ninja documentation on the console pool for more info.\n"
    "\n"
    "Example\n"
    "\n"
    "  action(\"long_action_with_progress_logs\") {\n"
    "    console = true\n"
    "  }\n";

const char kData[] = "data";
const char kData_HelpShort[] =
    "data: [file list] Runtime data file dependencies.";
const char kData_Help[] =
    "data: Runtime data file dependencies.\n"
    "\n"
    "  Lists files or directories required to run the given target. These are\n"
    "  typically data files or directories of data files. The paths are\n"
    "  interpreted as being relative to the current build file. Since these\n"
    "  are runtime dependencies, they do not affect which targets are built\n"
    "  or when. To declare input files to a script, use \"inputs\".\n"
    "\n"
    "  Appearing in the \"data\" section does not imply any special handling\n"
    "  such as copying them to the output directory. This is just used for\n"
    "  declaring runtime dependencies. Runtime dependencies can be queried\n"
    "  using the \"runtime_deps\" category of \"gn desc\" or written during\n"
    "  build generation via \"--runtime-deps-list-file\".\n"
    "\n"
    "  GN doesn't require data files to exist at build-time. So actions that\n"
    "  produce files that are in turn runtime dependencies can list those\n"
    "  generated files both in the \"outputs\" list as well as the \"data\"\n"
    "  list.\n"
    "\n"
    "  By convention, directories are listed with a trailing slash:\n"
    "    data = [ \"test/data/\" ]\n"
    "  However, no verification is done on these so GN doesn't enforce this.\n"
    "  The paths are just rebased and passed along when requested.\n"
    "\n"
    "  Note: On iOS and OS X, create_bundle targets will not be recursed\n"
    "  into when gathering data. See \"gn help create_bundle\" for details.\n"
    "\n"
    "  See \"gn help runtime_deps\" for how these are used.\n";

const char kDataDeps[] = "data_deps";
const char kDataDeps_HelpShort[] =
    "data_deps: [label list] Non-linked dependencies.";
const char kDataDeps_Help[] =
    "data_deps: Non-linked dependencies.\n"
    "\n"
    "  A list of target labels.\n"
    "\n"
    "  Specifies dependencies of a target that are not actually linked into\n"
    "  the current target. Such dependencies will be built and will be\n"
    "  available at runtime.\n"
    "\n"
    "  This is normally used for things like plugins or helper programs that\n"
    "  a target needs at runtime.\n"
    "\n"
    "  Note: On iOS and OS X, create_bundle targets will not be recursed\n"
    "  into when gathering data_deps. See \"gn help create_bundle\" for\n"
    "  details.\n"
    "\n"
    "  See also \"gn help deps\" and \"gn help data\".\n"
    "\n"
    "Example\n"
    "\n"
    "  executable(\"foo\") {\n"
    "    deps = [ \"//base\" ]\n"
    "    data_deps = [ \"//plugins:my_runtime_plugin\" ]\n"
    "  }\n";

const char kDefines[] = "defines";
const char kDefines_HelpShort[] =
    "defines: [string list] C preprocessor defines.";
const char kDefines_Help[] =
    "defines: C preprocessor defines.\n"
    "\n"
    "  A list of strings\n"
    "\n"
    "  These strings will be passed to the C/C++ compiler as #defines. The\n"
    "  strings may or may not include an \"=\" to assign a value.\n"
    COMMON_ORDERING_HELP
    "\n"
    "Example\n"
    "\n"
    "  defines = [ \"AWESOME_FEATURE\", \"LOG_LEVEL=3\" ]\n";

const char kDepfile[] = "depfile";
const char kDepfile_HelpShort[] =
    "depfile: [string] File name for input dependencies for actions.";
const char kDepfile_Help[] =
    "depfile: [string] File name for input dependencies for actions.\n"
    "\n"
    "  If nonempty, this string specifies that the current action or\n"
    "  action_foreach target will generate the given \".d\" file containing\n"
    "  the dependencies of the input. Empty or unset means that the script\n"
    "  doesn't generate the files.\n"
    "\n"
    "  A depfile should be used only when a target depends on files that are\n"
    "  not already specified by a target's inputs and sources. Likewise,\n"
    "  depfiles should specify only those dependencies not already included\n"
    "  in sources or inputs.\n"
    "\n"
    "  The .d file should go in the target output directory. If you have more\n"
    "  than one source file that the script is being run over, you can use\n"
    "  the output file expansions described in \"gn help action_foreach\" to\n"
    "  name the .d file according to the input."
    "\n"
    "  The format is that of a Makefile and all paths must be relative to the\n"
    "  root build directory. Only one output may be listed and it must match\n"
    "  the first output of the action.\n"
    "\n"
    "  Although depfiles are created by an action, they should not be listed\n"
    "  in the action's \"outputs\" unless another target will use the file as\n"
    "  an input.\n"
    "\n"
    "Example\n"
    "\n"
    "  action_foreach(\"myscript_target\") {\n"
    "    script = \"myscript.py\"\n"
    "    sources = [ ... ]\n"
    "\n"
    "    # Locate the depfile in the output directory named like the\n"
    "    # inputs but with a \".d\" appended.\n"
    "    depfile = \"$relative_target_output_dir/{{source_name}}.d\"\n"
    "\n"
    "    # Say our script uses \"-o <d file>\" to indicate the depfile.\n"
    "    args = [ \"{{source}}\", \"-o\", depfile ]\n"
    "  }\n";

const char kDeps[] = "deps";
const char kDeps_HelpShort[] =
    "deps: [label list] Private linked dependencies.";
const char kDeps_Help[] =
    "deps: Private linked dependencies.\n"
    "\n"
    "  A list of target labels.\n"
    "\n"
    "  Specifies private dependencies of a target. Private dependencies are\n"
    "  propagated up the dependency tree and linked to dependant targets, but\n"
    "  do not grant the ability to include headers from the dependency.\n"
    "  Public configs are not forwarded.\n"
    "\n"
    "Details of dependency propagation\n"
    "\n"
    "  Source sets, shared libraries, and non-complete static libraries\n"
    "  will be propagated up the dependency tree across groups, non-complete\n"
    "  static libraries and source sets.\n"
    "\n"
    "  Executables, shared libraries, and complete static libraries will\n"
    "  link all propagated targets and stop propagation. Actions and copy\n"
    "  steps also stop propagation, allowing them to take a library as an\n"
    "  input but not force dependants to link to it.\n"
    "\n"
    "  Propagation of all_dependent_configs and public_configs happens\n"
    "  independently of target type. all_dependent_configs are always\n"
    "  propagated across all types of targets, and public_configs\n"
    "  are always propagated across public deps of all types of targets.\n"
    "\n"
    "  Data dependencies are propagated differently. See\n"
    "  \"gn help data_deps\" and \"gn help runtime_deps\".\n"
    "\n"
    "  See also \"public_deps\".\n";

const char kIncludeDirs[] = "include_dirs";
const char kIncludeDirs_HelpShort[] =
    "include_dirs: [directory list] Additional include directories.";
const char kIncludeDirs_Help[] =
    "include_dirs: Additional include directories.\n"
    "\n"
    "  A list of source directories.\n"
    "\n"
    "  The directories in this list will be added to the include path for\n"
    "  the files in the affected target.\n"
    COMMON_ORDERING_HELP
    "\n"
    "Example\n"
    "\n"
    "  include_dirs = [ \"src/include\", \"//third_party/foo\" ]\n";

const char kInputs[] = "inputs";
const char kInputs_HelpShort[] =
    "inputs: [file list] Additional compile-time dependencies.";
const char kInputs_Help[] =
    "inputs: Additional compile-time dependencies.\n"
    "\n"
    "  Inputs are compile-time dependencies of the current target. This means\n"
    "  that all inputs must be available before compiling any of the sources\n"
    "  or executing any actions.\n"
    "\n"
    "  Inputs are typically only used for action and action_foreach targets.\n"
    "\n"
    "Inputs for actions\n"
    "\n"
    "  For action and action_foreach targets, inputs should be the inputs to\n"
    "  script that don't vary. These should be all .py files that the script\n"
    "  uses via imports (the main script itself will be an implicit dependency"
                                                                            "\n"
    "  of the action so need not be listed).\n"
    "\n"
    "  For action targets, inputs and sources are treated the same, but from\n"
    "  a style perspective, it's recommended to follow the same rule as\n"
    "  action_foreach and put helper files in the inputs, and the data used\n"
    "  by the script (if any) in sources.\n"
    "\n"
    "  Note that another way to declare input dependencies from an action\n"
    "  is to have the action write a depfile (see \"gn help depfile\"). This\n"
    "  allows the script to dynamically write input dependencies, that might\n"
    "  not be known until actually executing the script. This is more\n"
    "  efficient than doing processing while running GN to determine the\n"
    "  inputs, and is easier to keep in-sync than hardcoding the list.\n"
    "\n"
    "Script input gotchas\n"
    "\n"
    "  It may be tempting to write a script that enumerates all files in a\n"
    "  directory as inputs. Don't do this! Even if you specify all the files\n"
    "  in the inputs or sources in the GN target (or worse, enumerate the\n"
    "  files in an exec_script call when running GN, which will be slow), the\n"
    "  dependencies will be broken.\n"
    "\n"
    "  The problem happens if a file is ever removed because the inputs are\n"
    "  not listed on the command line to the script. Because the script\n"
    "  hasn't changed and all inputs are up to date, the script will not\n"
    "  re-run and you will get a stale build. Instead, either list all\n"
    "  inputs on the command line to the script, or if there are many, create\n"
    "  a separate list file that the script reads. As long as this file is\n"
    "  listed in the inputs, the build will detect when it has changed in any\n"
    "  way and the action will re-run.\n"
    "\n"
    "Inputs for binary targets\n"
    "\n"
    "  Any input dependencies will be resolved before compiling any sources.\n"
    "  Normally, all actions that a target depends on will be run before any\n"
    "  files in a target are compiled. So if you depend on generated headers,\n"
    "  you do not typically need to list them in the inputs section.\n"
    "\n"
    "  Inputs for binary targets will be treated as implicit dependencies,\n"
    "  meaning that changes in any of the inputs will force all sources in\n"
    "  the target to be recompiled. If an input only applies to a subset of\n"
    "  source files, you may want to split those into a separate target to\n"
    "  avoid unnecessary recompiles.\n"
    "\n"
    "Example\n"
    "\n"
    "  action(\"myscript\") {\n"
    "    script = \"domything.py\"\n"
    "    inputs = [ \"input.data\" ]\n"
    "  }\n";

const char kLdflags[] = "ldflags";
const char kLdflags_HelpShort[] =
    "ldflags: [string list] Flags passed to the linker.";
const char kLdflags_Help[] =
    "ldflags: Flags passed to the linker.\n"
    "\n"
    "  A list of strings.\n"
    "\n"
    "  These flags are passed on the command-line to the linker and generally\n"
    "  specify various linking options. Most targets will not need these and\n"
    "  will use \"libs\" and \"lib_dirs\" instead.\n"
    "\n"
    "  ldflags are NOT pushed to dependents, so applying ldflags to source\n"
    "  sets or static libraries will be a no-op. If you want to apply ldflags\n"
    "  to dependent targets, put them in a config and set it in the\n"
    "  all_dependent_configs or public_configs.\n"
    COMMON_ORDERING_HELP;

#define COMMON_LIB_INHERITANCE_HELP \
    "\n" \
    "  libs and lib_dirs work differently than other flags in two respects.\n" \
    "  First, then are inherited across static library boundaries until a\n" \
    "  shared library or executable target is reached. Second, they are\n" \
    "  uniquified so each one is only passed once (the first instance of it\n" \
    "  will be the one used).\n"

#define LIBS_AND_LIB_DIRS_ORDERING_HELP \
    "\n" \
    "  For \"libs\" and \"lib_dirs\" only, the values propagated from\n" \
    "  dependencies (as described above) are applied last assuming they\n" \
    "  are not already in the list.\n"

const char kLibDirs[] = "lib_dirs";
const char kLibDirs_HelpShort[] =
    "lib_dirs: [directory list] Additional library directories.";
const char kLibDirs_Help[] =
    "lib_dirs: Additional library directories.\n"
    "\n"
    "  A list of directories.\n"
    "\n"
    "  Specifies additional directories passed to the linker for searching\n"
    "  for the required libraries. If an item is not an absolute path, it\n"
    "  will be treated as being relative to the current build file.\n"
    COMMON_LIB_INHERITANCE_HELP
    COMMON_ORDERING_HELP
    LIBS_AND_LIB_DIRS_ORDERING_HELP
    "\n"
    "Example\n"
    "\n"
    "  lib_dirs = [ \"/usr/lib/foo\", \"lib/doom_melon\" ]\n";

const char kLibs[] = "libs";
const char kLibs_HelpShort[] =
    "libs: [string list] Additional libraries to link.";
const char kLibs_Help[] =
    "libs: Additional libraries to link.\n"
    "\n"
    "  A list of library names or library paths.\n"
    "\n"
    "  These libraries will be linked into the final binary (executable or\n"
    "  shared library) containing the current target.\n"
    COMMON_LIB_INHERITANCE_HELP
    "\n"
    "Types of libs\n"
    "\n"
    "  There are several different things that can be expressed in libs:\n"
    "\n"
    "  File paths\n"
    "      Values containing '/' will be treated as references to files in\n"
    "      the checkout. They will be rebased to be relative to the build\n"
    "      directory and specified in the \"libs\" for linker tools. This\n"
    "      facility should be used for libraries that are checked in to the\n"
    "      version control. For libraries that are generated by the build,\n"
    "      use normal GN deps to link them.\n"
    "\n"
    "  System libraries\n"
    "      Values not containing '/' will be treated as system library names.\n"
    "      These will be passed unmodified to the linker and prefixed with\n"
    "      the \"lib_prefix\" attribute of the linker tool. Generally you\n"
    "      would set the \"lib_dirs\" so the given library is found. Your\n"
    "      BUILD.gn file should not specify the switch (like \"-l\"): this\n"
    "      will be encoded in the \"lib_prefix\" of the tool.\n"
    "\n"
    "  Apple frameworks\n"
    "      System libraries ending in \".framework\" will be special-cased:\n"
    "      the switch \"-framework\" will be prepended instead of the\n"
    "      lib_prefix, and the \".framework\" suffix will be trimmed. This is\n"
    "      to support the way Mac links framework dependencies.\n"
    COMMON_ORDERING_HELP
    LIBS_AND_LIB_DIRS_ORDERING_HELP
    "\n"
    "Examples\n"
    "\n"
    "  On Windows:\n"
    "    libs = [ \"ctl3d.lib\" ]\n"
    "\n"
    "  On Linux:\n"
    "    libs = [ \"ld\" ]\n";

const char kOutputExtension[] = "output_extension";
const char kOutputExtension_HelpShort[] =
    "output_extension: [string] Value to use for the output's file extension.";
const char kOutputExtension_Help[] =
    "output_extension: Value to use for the output's file extension.\n"
    "\n"
    "  Normally the file extension for a target is based on the target\n"
    "  type and the operating system, but in rare cases you will need to\n"
    "  override the name (for example to use \"libfreetype.so.6\" instead\n"
    "  of libfreetype.so on Linux).\n"
    "\n"
    "  This value should not include a leading dot. If undefined, the default\n"
    "  specified on the tool will be used. If set to the empty string, no\n"
    "  output extension will be used.\n"
    "\n"
    "  The output_extension will be used to set the \"{{output_extension}}\"\n"
    "  expansion which the linker tool will generally use to specify the\n"
    "  output file name. See \"gn help tool\".\n"
    "\n"
    "Example\n"
    "\n"
    "  shared_library(\"freetype\") {\n"
    "    if (is_linux) {\n"
    "      # Call the output \"libfreetype.so.6\"\n"
    "      output_extension = \"so.6\"\n"
    "    }\n"
    "    ...\n"
    "  }\n"
    "\n"
    "  # On Windows, generate a \"mysettings.cpl\" control panel applet.\n"
    "  # Control panel applets are actually special shared libraries.\n"
    "  if (is_win) {\n"
    "    shared_library(\"mysettings\") {\n"
    "      output_extension = \"cpl\"\n"
    "      ...\n"
    "    }\n"
    "  }\n";

const char kOutputDir[] = "output_dir";
const char kOutputDir_HelpShort[] =
    "output_dir: [directory] Directory to put output file in.";
const char kOutputDir_Help[] =
    "output_dir: [directory] Directory to put output file in.\n"
    "\n"
    "  For library and executable targets, overrides the directory for the\n"
    "  final output. This must be in the root_build_dir or a child thereof.\n"
    "\n"
    "  This should generally be in the root_out_dir or a subdirectory thereof\n"
    "  (the root_out_dir will be the same as the root_build_dir for the\n"
    "  default toolchain, and will be a subdirectory for other toolchains).\n"
    "  Not putting the output in a subdirectory of root_out_dir can result\n"
    "  in collisions between different toolchains, so you will need to take\n"
    "  steps to ensure that your target is only present in one toolchain.\n"
    "\n"
    "  Normally the toolchain specifies the output directory for libraries\n"
    "  and executables (see \"gn help tool\"). You will have to consult that\n"
    "  for the default location. The default location will be used if\n"
    "  output_dir is undefined or empty.\n"
    "\n"
    "Example\n"
    "\n"
    "  shared_library(\"doom_melon\") {\n"
    "    output_dir = \"$root_out_dir/plugin_libs\"\n"
    "    ...\n"
    "  }\n";

const char kOutputName[] = "output_name";
const char kOutputName_HelpShort[] =
    "output_name: [string] Name for the output file other than the default.";
const char kOutputName_Help[] =
    "output_name: Define a name for the output file other than the default.\n"
    "\n"
    "  Normally the output name of a target will be based on the target name,\n"
    "  so the target \"//foo/bar:bar_unittests\" will generate an output\n"
    "  file such as \"bar_unittests.exe\" (using Windows as an example).\n"
    "\n"
    "  Sometimes you will want an alternate name to avoid collisions or\n"
    "  if the internal name isn't appropriate for public distribution.\n"
    "\n"
    "  The output name should have no extension or prefixes, these will be\n"
    "  added using the default system rules. For example, on Linux an output\n"
    "  name of \"foo\" will produce a shared library \"libfoo.so\". There\n"
    "  is no way to override the output prefix of a linker tool on a per-\n"
    "  target basis. If you need more flexibility, create a copy target\n"
    "  to produce the file you want.\n"
    "\n"
    "  This variable is valid for all binary output target types.\n"
    "\n"
    "Example\n"
    "\n"
    "  static_library(\"doom_melon\") {\n"
    "    output_name = \"fluffy_bunny\"\n"
    "  }\n";

const char kOutputPrefixOverride[] = "output_prefix_override";
const char kOutputPrefixOverride_HelpShort[] =
    "output_prefix_override: [boolean] Don't use prefix for output name.";
const char kOutputPrefixOverride_Help[] =
    "output_prefix_override: Don't use prefix for output name.\n"
    "\n"
    "  A boolean that overrides the output prefix for a target. Defaults to\n"
    "  false.\n"
    "\n"
    "  Some systems use prefixes for the names of the final target output\n"
    "  file. The normal example is \"libfoo.so\" on Linux for a target\n"
    "  named \"foo\".\n"
    "\n"
    "  The output prefix for a given target type is specified on the linker\n"
    "  tool (see \"gn help tool\"). Sometimes this prefix is undesired.\n"
    "\n"
    "  See also \"gn help output_extension\".\n"
    "\n"
    "Example\n"
    "\n"
    "  shared_library(\"doom_melon\") {\n"
    "    # Normally this will produce \"libdoom_melon.so\" on Linux, setting\n"
    "    # Setting this flag will produce \"doom_melon.so\".\n"
    "    output_prefix_override = true\n"
    "    ...\n"
    "  }\n";

const char kOutputs[] = "outputs";
const char kOutputs_HelpShort[] =
    "outputs: [file list] Output files for actions and copy targets.";
const char kOutputs_Help[] =
    "outputs: Output files for actions and copy targets.\n"
    "\n"
    "  Outputs is valid for \"copy\", \"action\", and \"action_foreach\"\n"
    "  target types and indicates the resulting files. Outputs must always\n"
    "  refer to files in the build directory.\n"
    "\n"
    "  copy\n"
    "    Copy targets should have exactly one entry in the outputs list. If\n"
    "    there is exactly one source, this can be a literal file name or a\n"
    "    source expansion. If there is more than one source, this must\n"
    "    contain a source expansion to map a single input name to a single\n"
    "    output name. See \"gn help copy\".\n"
    "\n"
    "  action_foreach\n"
    "    Action_foreach targets must always use source expansions to map\n"
    "    input files to output files. There can be more than one output,\n"
    "    which means that each invocation of the script will produce a set of\n"
    "    files (presumably based on the name of the input file). See\n"
    "    \"gn help action_foreach\".\n"
    "\n"
    "  action\n"
    "    Action targets (excluding action_foreach) must list literal output\n"
    "    file(s) with no source expansions. See \"gn help action\".\n";

const char kPrecompiledHeader[] = "precompiled_header";
const char kPrecompiledHeader_HelpShort[] =
    "precompiled_header: [string] Header file to precompile.";
const char kPrecompiledHeader_Help[] =
    "precompiled_header: [string] Header file to precompile.\n"
    "\n"
    "  Precompiled headers will be used when a target specifies this\n"
    "  value, or a config applying to this target specifies this value.\n"
    "  In addition, the tool corresponding to the source files must also\n"
    "  specify precompiled headers (see \"gn help tool\"). The tool\n"
    "  will also specify what type of precompiled headers to use.\n"
    "\n"
    "  The precompiled header/source variables can be specified on a target\n"
    "  or a config, but must be the same for all configs applying to a given\n"
    "  target since a target can only have one precompiled header.\n"
    "\n"
    "MSVC precompiled headers\n"
    "\n"
    "  When using MSVC-style precompiled headers, the \"precompiled_header\"\n"
    "  value is a string corresponding to the header. This is NOT a path\n"
    "  to a file that GN recognises, but rather the exact string that appears\n"
    "  in quotes after an #include line in source code. The compiler will\n"
    "  match this string against includes or forced includes (/FI).\n"
    "\n"
    "  MSVC also requires a source file to compile the header with. This must\n"
    "  be specified by the \"precompiled_source\" value. In contrast to the\n"
    "  header value, this IS a GN-style file name, and tells GN which source\n"
    "  file to compile to make the .pch file used for subsequent compiles.\n"
    "\n"
    "  If you use both C and C++ sources, the precompiled header and source\n"
    "  file will be compiled using both tools. You will want to make sure\n"
    "  to wrap C++ includes in __cplusplus #ifdefs so the file will compile\n"
    "  in C mode.\n"
    "\n"
    "  For example, if the toolchain specifies MSVC headers:\n"
    "\n"
    "    toolchain(\"vc_x64\") {\n"
    "      ...\n"
    "      tool(\"cxx\") {\n"
    "        precompiled_header_type = \"msvc\"\n"
    "        ...\n"
    "\n"
    "  You might make a config like this:\n"
    "\n"
    "    config(\"use_precompiled_headers\") {\n"
    "      precompiled_header = \"build/precompile.h\"\n"
    "      precompiled_source = \"//build/precompile.cc\"\n"
    "\n"
    "      # Either your source files should #include \"build/precompile.h\"\n"
    "      # first, or you can do this to force-include the header.\n"
    "      cflags = [ \"/FI$precompiled_header\" ]\n"
    "    }\n"
    "\n"
    "  And then define a target that uses the config:\n"
    "\n"
    "    executable(\"doom_melon\") {\n"
    "      configs += [ \":use_precompiled_headers\" ]\n"
    "      ...\n"
    "\n";

const char kPrecompiledSource[] = "precompiled_source";
const char kPrecompiledSource_HelpShort[] =
    "precompiled_source: [file name] Source file to precompile.";
const char kPrecompiledSource_Help[] =
    "precompiled_source: [file name] Source file to precompile.\n"
    "\n"
    "  The source file that goes along with the precompiled_header when\n"
    "  using \"msvc\"-style precompiled headers. It will be implicitly added\n"
    "  to the sources of the target. See \"gn help precompiled_header\".\n";

const char kProductType[] = "product_type";
const char kProductType_HelpShort[] =
    "product_type: [string] Product type for Xcode projects.";
const char kProductType_Help[] =
    "product_type: Product type for Xcode projects.\n"
    "\n"
    "  Correspond to the type of the product of a create_bundle target. Only\n"
    "  meaningful to Xcode (used as part of the Xcode project generation).\n"
    "\n"
    "  When generating Xcode project files, only create_bundle target with\n"
    "  a non-empty product_type will have a corresponding target in Xcode\n"
    "  project.\n";

const char kPublic[] = "public";
const char kPublic_HelpShort[] =
    "public: [file list] Declare public header files for a target.";
const char kPublic_Help[] =
    "public: Declare public header files for a target.\n"
    "\n"
    "  A list of files that other targets can include. These permissions are\n"
    "  checked via the \"check\" command (see \"gn help check\").\n"
    "\n"
    "  If no public files are declared, other targets (assuming they have\n"
    "  visibility to depend on this target can include any file in the\n"
    "  sources list. If this variable is defined on a target, dependent\n"
    "  targets may only include files on this whitelist.\n"
    "\n"
    "  Header file permissions are also subject to visibility. A target\n"
    "  must be visible to another target to include any files from it at all\n"
    "  and the public headers indicate which subset of those files are\n"
    "  permitted. See \"gn help visibility\" for more.\n"
    "\n"
    "  Public files are inherited through the dependency tree. So if there is\n"
    "  a dependency A -> B -> C, then A can include C's public headers.\n"
    "  However, the same is NOT true of visibility, so unless A is in C's\n"
    "  visibility list, the include will be rejected.\n"
    "\n"
    "  GN only knows about files declared in the \"sources\" and \"public\"\n"
    "  sections of targets. If a file is included that is not known to the\n"
    "  build, it will be allowed.\n"
    "\n"
    "Examples\n"
    "\n"
    "  These exact files are public:\n"
    "    public = [ \"foo.h\", \"bar.h\" ]\n"
    "\n"
    "  No files are public (no targets may include headers from this one):\n"
    "    public = []\n";

const char kPublicConfigs[] = "public_configs";
const char kPublicConfigs_HelpShort[] =
    "public_configs: [label list] Configs applied to dependents.";
const char kPublicConfigs_Help[] =
    "public_configs: Configs to be applied on dependents.\n"
    "\n"
    "  A list of config labels.\n"
    "\n"
    "  Targets directly depending on this one will have the configs listed in\n"
    "  this variable added to them. These configs will also apply to the\n"
    "  current target.\n"
    "\n"
    "  This addition happens in a second phase once a target and all of its\n"
    "  dependencies have been resolved. Therefore, a target will not see\n"
    "  these force-added configs in their \"configs\" variable while the\n"
    "  script is running, and then can not be removed. As a result, this\n"
    "  capability should generally only be used to add defines and include\n"
    "  directories necessary to compile a target's headers.\n"
    "\n"
    "  See also \"all_dependent_configs\".\n"
    COMMON_ORDERING_HELP;

const char kPublicDeps[] = "public_deps";
const char kPublicDeps_HelpShort[] =
    "public_deps: [label list] Declare public dependencies.";
const char kPublicDeps_Help[] =
    "public_deps: Declare public dependencies.\n"
    "\n"
    "  Public dependencies are like private dependencies (see\n"
    "  \"gn help deps\") but additionally express that the current target\n"
    "  exposes the listed deps as part of its public API.\n"
    "\n"
    "  This has several ramifications:\n"
    "\n"
    "    - public_configs that are part of the dependency are forwarded\n"
    "      to direct dependents.\n"
    "\n"
    "    - Public headers in the dependency are usable by dependents\n"
    "      (includes do not require a direct dependency or visibility).\n"
    "\n"
    "    - If the current target is a shared library, other shared libraries\n"
    "      that it publicly depends on (directly or indirectly) are\n"
    "      propagated up the dependency tree to dependents for linking.\n"
    "\n"
    "Discussion\n"
    "\n"
    "  Say you have three targets: A -> B -> C. C's visibility may allow\n"
    "  B to depend on it but not A. Normally, this would prevent A from\n"
    "  including any headers from C, and C's public_configs would apply\n"
    "  only to B.\n"
    "\n"
    "  If B lists C in its public_deps instead of regular deps, A will now\n"
    "  inherit C's public_configs and the ability to include C's public\n"
    "  headers.\n"
    "\n"
    "  Generally if you are writing a target B and you include C's headers\n"
    "  as part of B's public headers, or targets depending on B should\n"
    "  consider B and C to be part of a unit, you should use public_deps\n"
    "  instead of deps.\n"
    "\n"
    "Example\n"
    "\n"
    "  # This target can include files from \"c\" but not from\n"
    "  # \"super_secret_implementation_details\".\n"
    "  executable(\"a\") {\n"
    "    deps = [ \":b\" ]\n"
    "  }\n"
    "\n"
    "  shared_library(\"b\") {\n"
    "    deps = [ \":super_secret_implementation_details\" ]\n"
    "    public_deps = [ \":c\" ]\n"
    "  }\n";

const char kResponseFileContents[] = "response_file_contents";
const char kResponseFileContents_HelpShort[] =
    "response_file_contents: [string list] Contents of .rsp file for actions.";
const char kResponseFileContents_Help[] =
    "response_file_contents: Contents of a response file for actions.\n"
    "\n"
    "  Sometimes the arguments passed to a script can be too long for the\n"
    "  system's command-line capabilities. This is especially the case on\n"
    "  Windows where the maximum command-line length is less than 8K. A\n"
    "  response file allows you to pass an unlimited amount of data to a\n"
    "  script in a temporary file for an action or action_foreach target.\n"
    "\n"
    "  If the response_file_contents variable is defined and non-empty, the\n"
    "  list will be treated as script args (including possibly substitution\n"
    "  patterns) that will be written to a temporary file at build time.\n"
    "  The name of the temporary file will be substituted for\n"
    "  \"{{response_file_name}}\" in the script args.\n"
    "\n"
    "  The response file contents will always be quoted and escaped\n"
    "  according to Unix shell rules. To parse the response file, the Python\n"
    "  script should use \"shlex.split(file_contents)\".\n"
    "\n"
    "Example\n"
    "\n"
    "  action(\"process_lots_of_files\") {\n"
    "    script = \"process.py\",\n"
    "    inputs = [ ... huge list of files ... ]\n"
    "\n"
    "    # Write all the inputs to a response file for the script. Also,\n"
    "    # make the paths relative to the script working directory.\n"
    "    response_file_contents = rebase_path(inputs, root_build_dir)\n"
    "\n"
    "    # The script expects the name of the response file in --file-list.\n"
    "    args = [\n"
    "      \"--enable-foo\",\n"
    "      \"--file-list={{response_file_name}}\",\n"
    "    ]\n"
    "  }\n";

const char kScript[] = "script";
const char kScript_HelpShort[] =
    "script: [file name] Script file for actions.";
const char kScript_Help[] =
    "script: Script file for actions.\n"
    "\n"
    "  An absolute or buildfile-relative file name of a Python script to run\n"
    "  for a action and action_foreach targets (see \"gn help action\" and\n"
    "  \"gn help action_foreach\").\n";

const char kSources[] = "sources";
const char kSources_HelpShort[] =
    "sources: [file list] Source files for a target.";
const char kSources_Help[] =
    "sources: Source files for a target\n"
    "\n"
    "  A list of files. Non-absolute paths will be resolved relative to the\n"
    "  current build file.\n"
    "\n"
    "Sources for binary targets\n"
    "\n"
    "  For binary targets (source sets, executables, and libraries), the\n"
    "  known file types will be compiled with the associated tools. Unknown\n"
    "  file types and headers will be skipped. However, you should still\n"
    "  list all C/C+ header files so GN knows about the existance of those\n"
    "  files for the purposes of include checking.\n"
    "\n"
    "  As a special case, a file ending in \".def\" will be treated as a\n"
    "  Windows module definition file. It will be appended to the link\n"
    "  line with a preceeding \"/DEF:\" string. There must be at most one\n"
    "  .def file in a target and they do not cross dependency boundaries\n"
    "  (so specifying a .def file in a static library or source set will have\n"
    "  no effect on the executable or shared library they're linked into).\n"
    "\n"
    "Sources for non-binary targets\n"
    "\n"
    "  action_foreach\n"
    "    The sources are the set of files that the script will be executed\n"
    "    over. The script will run once per file.\n"
    "\n"
    "  action\n"
    "    The sources will be treated the same as inputs. See "
         "\"gn help inputs\"\n"
    "    for more information and usage advice.\n"
    "\n"
    "  copy\n"
    "    The source are the source files to copy.\n";

const char kTestonly[] = "testonly";
const char kTestonly_HelpShort[] =
    "testonly: [boolean] Declares a target must only be used for testing.";
const char kTestonly_Help[] =
    "testonly: Declares a target must only be used for testing.\n"
    "\n"
    "  Boolean. Defaults to false.\n"
    "\n"
    "  When a target is marked \"testonly = true\", it must only be depended\n"
    "  on by other test-only targets. Otherwise, GN will issue an error\n"
    "  that the depenedency is not allowed.\n"
    "\n"
    "  This feature is intended to prevent accidentally shipping test code\n"
    "  in a final product.\n"
    "\n"
    "Example\n"
    "\n"
    "  source_set(\"test_support\") {\n"
    "    testonly = true\n"
    "    ...\n"
    "  }\n";

const char kVisibility[] = "visibility";
const char kVisibility_HelpShort[] =
    "visibility: [label list] A list of labels that can depend on a target.";
const char kVisibility_Help[] =
    "visibility: A list of labels that can depend on a target.\n"
    "\n"
    "  A list of labels and label patterns that define which targets can\n"
    "  depend on the current one. These permissions are checked via the\n"
    "  \"check\" command (see \"gn help check\").\n"
    "\n"
    "  If visibility is not defined, it defaults to public (\"*\").\n"
    "\n"
    "  If visibility is defined, only the targets with labels that match it\n"
    "  can depend on the current target. The empty list means no targets\n"
    "  can depend on the current target.\n"
    "\n"
    "  Tip: Often you will want the same visibility for all targets in a\n"
    "  BUILD file. In this case you can just put the definition at the top,\n"
    "  outside of any target, and the targets will inherit that scope and see\n"
    "  the definition.\n"
    "\n"
    "Patterns\n"
    "\n"
    "  See \"gn help label_pattern\" for more details on what types of\n"
    "  patterns are supported. If a toolchain is specified, only targets\n"
    "  in that toolchain will be matched. If a toolchain is not specified on\n"
    "  a pattern, targets in all toolchains will be matched.\n"
    "\n"
    "Examples\n"
    "\n"
    "  Only targets in the current buildfile (\"private\"):\n"
    "    visibility = [ \":*\" ]\n"
    "\n"
    "  No targets (used for targets that should be leaf nodes):\n"
    "    visibility = []\n"
    "\n"
    "  Any target (\"public\", the default):\n"
    "    visibility = [ \"*\" ]\n"
    "\n"
    "  All targets in the current directory and any subdirectory:\n"
    "    visibility = [ \"./*\" ]\n"
    "\n"
    "  Any target in \"//bar/BUILD.gn\":\n"
    "    visibility = [ \"//bar:*\" ]\n"
    "\n"
    "  Any target in \"//bar/\" or any subdirectory thereof:\n"
    "    visibility = [ \"//bar/*\" ]\n"
    "\n"
    "  Just these specific targets:\n"
    "    visibility = [ \":mything\", \"//foo:something_else\" ]\n"
    "\n"
    "  Any target in the current directory and any subdirectory thereof, plus\n"
    "  any targets in \"//bar/\" and any subdirectory thereof.\n"
    "    visibility = [ \"./*\", \"//bar/*\" ]\n";

const char kWriteRuntimeDeps[] = "write_runtime_deps";
const char kWriteRuntimeDeps_HelpShort[] =
    "write_runtime_deps: Writes the target's runtime_deps to the given path.";
const char kWriteRuntimeDeps_Help[] =
    "write_runtime_deps: Writes the target's runtime_deps to the given path.\n"
    "\n"
    "  Does not synchronously write the file, but rather schedules it\n"
    "  to be written at the end of generation.\n"
    "\n"
    "  If the file exists and the contents are identical to that being\n"
    "  written, the file will not be updated. This will prevent unnecessary\n"
    "  rebuilds of targets that depend on this file.\n"
    "\n"
    "  Path must be within the output directory.\n"
    "\n"
    "  See \"gn help runtime_deps\" for how the runtime dependencies are\n"
    "  computed.\n"
    "\n"
    "  The format of this file will list one file per line with no escaping.\n"
    "  The files will be relative to the root_build_dir. The first line of\n"
    "  the file will be the main output file of the target itself. The file\n"
    "  contents will be the same as requesting the runtime deps be written on\n"
    "  the command line (see \"gn help --runtime-deps-list-file\").\n";

// -----------------------------------------------------------------------------

VariableInfo::VariableInfo()
    : help_short(""),
      help("") {
}

VariableInfo::VariableInfo(const char* in_help_short, const char* in_help)
    : help_short(in_help_short),
      help(in_help) {
}

#define INSERT_VARIABLE(var) \
    info_map[k##var] = VariableInfo(k##var##_HelpShort, k##var##_Help);

const VariableInfoMap& GetBuiltinVariables() {
  static VariableInfoMap info_map;
  if (info_map.empty()) {
    INSERT_VARIABLE(CurrentCpu)
    INSERT_VARIABLE(CurrentOs)
    INSERT_VARIABLE(CurrentToolchain)
    INSERT_VARIABLE(DefaultToolchain)
    INSERT_VARIABLE(HostCpu)
    INSERT_VARIABLE(HostOs)
    INSERT_VARIABLE(Invoker)
    INSERT_VARIABLE(PythonPath)
    INSERT_VARIABLE(RootBuildDir)
    INSERT_VARIABLE(RootGenDir)
    INSERT_VARIABLE(RootOutDir)
    INSERT_VARIABLE(TargetCpu)
    INSERT_VARIABLE(TargetOs)
    INSERT_VARIABLE(TargetGenDir)
    INSERT_VARIABLE(TargetName)
    INSERT_VARIABLE(TargetOutDir)
  }
  return info_map;
}

const VariableInfoMap& GetTargetVariables() {
  static VariableInfoMap info_map;
  if (info_map.empty()) {
    INSERT_VARIABLE(AllDependentConfigs)
    INSERT_VARIABLE(AllowCircularIncludesFrom)
    INSERT_VARIABLE(Arflags)
    INSERT_VARIABLE(Args)
    INSERT_VARIABLE(Asmflags)
    INSERT_VARIABLE(AssertNoDeps)
    INSERT_VARIABLE(BundleRootDir)
    INSERT_VARIABLE(BundleResourcesDir)
    INSERT_VARIABLE(BundleDepsFilter)
    INSERT_VARIABLE(BundleExecutableDir)
    INSERT_VARIABLE(BundlePlugInsDir)
    INSERT_VARIABLE(Cflags)
    INSERT_VARIABLE(CflagsC)
    INSERT_VARIABLE(CflagsCC)
    INSERT_VARIABLE(CflagsObjC)
    INSERT_VARIABLE(CflagsObjCC)
    INSERT_VARIABLE(CheckIncludes)
    INSERT_VARIABLE(CodeSigningArgs)
    INSERT_VARIABLE(CodeSigningScript)
    INSERT_VARIABLE(CodeSigningSources)
    INSERT_VARIABLE(CodeSigningOutputs)
    INSERT_VARIABLE(CompleteStaticLib)
    INSERT_VARIABLE(Configs)
    INSERT_VARIABLE(Console)
    INSERT_VARIABLE(Data)
    INSERT_VARIABLE(DataDeps)
    INSERT_VARIABLE(Defines)
    INSERT_VARIABLE(Depfile)
    INSERT_VARIABLE(Deps)
    INSERT_VARIABLE(IncludeDirs)
    INSERT_VARIABLE(Inputs)
    INSERT_VARIABLE(Ldflags)
    INSERT_VARIABLE(Libs)
    INSERT_VARIABLE(LibDirs)
    INSERT_VARIABLE(OutputDir)
    INSERT_VARIABLE(OutputExtension)
    INSERT_VARIABLE(OutputName)
    INSERT_VARIABLE(OutputPrefixOverride)
    INSERT_VARIABLE(Outputs)
    INSERT_VARIABLE(PrecompiledHeader)
    INSERT_VARIABLE(PrecompiledSource)
    INSERT_VARIABLE(ProductType)
    INSERT_VARIABLE(Public)
    INSERT_VARIABLE(PublicConfigs)
    INSERT_VARIABLE(PublicDeps)
    INSERT_VARIABLE(ResponseFileContents)
    INSERT_VARIABLE(Script)
    INSERT_VARIABLE(Sources)
    INSERT_VARIABLE(Testonly)
    INSERT_VARIABLE(Visibility)
    INSERT_VARIABLE(WriteRuntimeDeps)
  }
  return info_map;
}

#undef INSERT_VARIABLE

}  // namespace variables
