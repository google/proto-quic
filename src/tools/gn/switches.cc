// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/gn/switches.h"

namespace switches {

const char kArgs[] = "args";
const char kArgs_HelpShort[] =
    "--args: Specifies build arguments overrides.";
const char kArgs_Help[] =
    "--args: Specifies build arguments overrides.\n"
    "\n"
    "  See \"gn help buildargs\" for an overview of how build arguments work.\n"
    "\n"
    "  Most operations take a build directory. The build arguments are taken\n"
    "  from the previous build done in that directory. If a command specifies\n"
    "  --args, it will override the previous arguments stored in the build\n"
    "  directory, and use the specified ones.\n"
    "\n"
    "  The args specified will be saved to the build directory for subsequent\n"
    "  commands. Specifying --args=\"\" will clear all build arguments.\n"
    "\n"
    "Formatting\n"
    "\n"
    "  The value of the switch is interpreted in GN syntax. For typical usage\n"
    "  of string arguments, you will need to be careful about escaping of\n"
    "  quotes.\n"
    "\n"
    "Examples\n"
    "\n"
    "  gn gen out/Default --args=\"foo=\\\"bar\\\"\"\n"
    "\n"
    "  gn gen out/Default --args='foo=\"bar\" enable=true blah=7'\n"
    "\n"
    "  gn check out/Default --args=\"\"\n"
    "    Clears existing build args from the directory.\n"
    "\n"
    "  gn desc out/Default --args=\"some_list=[1, false, \\\"foo\\\"]\"\n";

#define COLOR_HELP_LONG \
    "--[no]color: Forces colored output on or off.\n"\
    "\n"\
    "  Normally GN will try to detect whether it is outputting to a terminal\n"\
    "  and will enable or disable color accordingly. Use of these switches\n"\
    "  will override the default.\n"\
    "\n"\
    "Examples\n"\
    "\n"\
    "  gn gen out/Default --color\n"\
    "\n"\
    "  gn gen out/Default --nocolor\n"
const char kColor[] = "color";
const char kColor_HelpShort[] =
    "--color: Force colored output.";
const char kColor_Help[] = COLOR_HELP_LONG;

const char kDotfile[] = "dotfile";
const char kDotfile_HelpShort[] =
    "--dotfile: Override the name of the \".gn\" file.";
const char kDotfile_Help[] =
    "--dotfile: Override the name of the \".gn\" file.\n"
    "\n"
    "  Normally GN loads the \".gn\"file  from the source root for some basic\n"
    "  configuration (see \"gn help dotfile\"). This flag allows you to\n"
    "  use a different file.\n"
    "\n"
    "  Note that this interacts with \"--root\" in a possibly incorrect way.\n"
    "  It would be nice to test the edge cases and document or fix.\n";

const char kFailOnUnusedArgs[] = "fail-on-unused-args";
const char kFailOnUnusedArgs_HelpShort[] =
    "--fail-on-unused-args: Treat unused build args as fatal errors.";
const char kFailOnUnusedArgs_Help[] =
    "--fail-on-unused-args: Treat unused build args as fatal errors.\n"
    "\n"
    "  If you set a value in a build's \"gn args\" and never use it in the\n"
    "  build (in a declare_args() block), GN will normally print an error\n"
    "  but not fail the build.\n"
    "\n"
    "  In many cases engineers would use build args to enable or disable\n"
    "  features that would sometimes get removed. It would by annoying to\n"
    "  block work for typically benign problems. In Chrome in particular,\n"
    "  flags might be configured for build bots in a separate infrastructure\n"
    "  repository, or a declare_args block might be changed in a third party\n"
    "  repository. Treating these errors as blocking forced complex multi-\n"
    "  way patches to land what would otherwise be simple changes.\n"
    "\n"
    "  In some cases, such concerns are not as important, and a mismatch\n"
    "  in build flags between the invoker of the build and the build files\n"
    "  represents a critical mismatch that should be immediately fixed. Such\n"
    "  users can set this flag to force GN to fail in that case.\n";

const char kMarkdown[] = "markdown";
const char kMarkdown_HelpShort[] =
    "--markdown: Write help output in the Markdown format.";
const char kMarkdown_Help[] =
    "--markdown: Write help output in the Markdown format.\n";

const char kNoColor[] = "nocolor";
const char kNoColor_HelpShort[] =
    "--nocolor: Force non-colored output.";
const char kNoColor_Help[] = COLOR_HELP_LONG;

const char kScriptExecutable[] = "script-executable";
const char kScriptExecutable_HelpShort[] =
    "--script-executable: Set the executable used to execute scripts.";
const char kScriptExecutable_Help[] =
    "--script-executable: Set the executable used to execute scripts.\n"
    "\n"
    "  By default GN searches the PATH for Python to execute scripts in\n"
    "  action targets and exec_script calls. This flag allows the\n"
    "  specification of a specific Python executable or potentially\n"
    "  a different language interpreter.\n";

const char kQuiet[] = "q";
const char kQuiet_HelpShort[] =
    "-q: Quiet mode. Don't print output on success.";
const char kQuiet_Help[] =
    "-q: Quiet mode. Don't print output on success.\n"
    "\n"
    "  This is useful when running as a part of another script.\n";

const char kRoot[] = "root";
const char kRoot_HelpShort[] =
    "--root: Explicitly specify source root.";
const char kRoot_Help[] =
    "--root: Explicitly specify source root.\n"
    "\n"
    "  Normally GN will look up in the directory tree from the current\n"
    "  directory to find a \".gn\" file. The source root directory specifies\n"
    "  the meaning of \"//\" beginning with paths, and the BUILD.gn file\n"
    "  in that directory will be the first thing loaded.\n"
    "\n"
    "  Specifying --root allows GN to do builds in a specific directory\n"
    "  regardless of the current directory.\n"
    "\n"
    "Examples\n"
    "\n"
    "  gn gen //out/Default --root=/home/baracko/src\n"
    "\n"
    "  gn desc //out/Default --root=\"C:\\Users\\BObama\\My Documents\\foo\"\n";

const char kRuntimeDepsListFile[] = "runtime-deps-list-file";
const char kRuntimeDepsListFile_HelpShort[] =
    "--runtime-deps-list-file: Save runtime dependencies for targets in file.";
const char kRuntimeDepsListFile_Help[] =
    "--runtime-deps-list-file: Save runtime dependencies for targets in file.\n"
    "\n"
    "  --runtime-deps-list-file=<filename>\n"
    "\n"
    "  Where <filename> is a text file consisting of the labels, one per\n"
    "  line, of the targets for which runtime dependencies are desired.\n"
    "\n"
    "  See \"gn help runtime_deps\" for a description of how runtime\n"
    "  dependencies are computed.\n"
    "\n"
    "Runtime deps output file\n"
    "\n"
    "  For each target requested, GN will write a separate runtime dependency\n"
    "  file. The runtime dependency file will be in the output directory\n"
    "  alongside the output file of the target, with a \".runtime_deps\"\n"
    "  extension. For example, if the target \"//foo:bar\" is listed in the\n"
    "  input file, and that target produces an output file \"bar.so\", GN\n"
    "  will create a file \"bar.so.runtime_deps\" in the build directory.\n"
    "\n"
    "  If a source set, action, copy, or group is listed, the runtime deps\n"
    "  file will correspond to the .stamp file corresponding to that target.\n"
    "  This is probably not useful; the use-case for this feature is\n"
    "  generally executable targets.\n"
    "\n"
    "  The runtime dependency file will list one file per line, with no\n"
    "  escaping. The files will be relative to the root_build_dir. The first\n"
    "  line of the file will be the main output file of the target itself\n"
    "  (in the above example, \"bar.so\").\n";

const char kThreads[] = "threads";
const char kThreads_HelpShort[] =
    "--threads: Specify number of worker threads.";
const char kThreads_Help[] =
    "--threads: Specify number of worker threads.\n"
    "\n"
    "  GN runs many threads to load and run build files. This can make\n"
    "  debugging challenging. Or you may want to experiment with different\n"
    "  values to see how it affects performance.\n"
    "\n"
    "  The parameter is the number of worker threads. This does not count the\n"
    "  main thread (so there are always at least two).\n"
    "\n"
    "Examples\n"
    "\n"
    "  gen gen out/Default --threads=1\n";

const char kTime[] = "time";
const char kTime_HelpShort[] =
    "--time: Outputs a summary of how long everything took.";
const char kTime_Help[] =
    "--time: Outputs a summary of how long everything took.\n"
    "\n"
    "  Hopefully self-explanatory.\n"
    "\n"
    "Examples\n"
    "\n"
    "  gn gen out/Default --time\n";

const char kTracelog[] = "tracelog";
const char kTracelog_HelpShort[] =
    "--tracelog: Writes a Chrome-compatible trace log to the given file.";
const char kTracelog_Help[] =
    "--tracelog: Writes a Chrome-compatible trace log to the given file.\n"
    "\n"
    "  The trace log will show file loads, executions, scripts, and writes.\n"
    "  This allows performance analysis of the generation step.\n"
    "\n"
    "  To view the trace, open Chrome and navigate to \"chrome://tracing/\",\n"
    "  then press \"Load\" and specify the file you passed to this parameter.\n"
    "\n"
    "Examples\n"
    "\n"
    "  gn gen out/Default --tracelog=mytrace.trace\n";

const char kVerbose[] = "v";
const char kVerbose_HelpShort[] =
    "-v: Verbose logging.";
const char kVerbose_Help[] =
    "-v: Verbose logging.\n"
    "\n"
    "  This will spew logging events to the console for debugging issues.\n"
    "  Good luck!\n";

const char kVersion[] = "version";
const char kVersion_HelpShort[] =
    "--version: Prints the GN version number and exits.";
// It's impossible to see this since gn_main prints the version and exits
// immediately if this switch is used.
const char kVersion_Help[] = "";

const char kAllToolchains[] = "all-toolchains";

// -----------------------------------------------------------------------------

SwitchInfo::SwitchInfo()
    : short_help(""),
      long_help("") {
}

SwitchInfo::SwitchInfo(const char* short_help, const char* long_help)
    : short_help(short_help),
      long_help(long_help) {
}

#define INSERT_VARIABLE(var) \
    info_map[k##var] = SwitchInfo(k##var##_HelpShort, k##var##_Help);

const SwitchInfoMap& GetSwitches() {
  static SwitchInfoMap info_map;
  if (info_map.empty()) {
    INSERT_VARIABLE(Args)
    INSERT_VARIABLE(Color)
    INSERT_VARIABLE(Dotfile)
    INSERT_VARIABLE(FailOnUnusedArgs)
    INSERT_VARIABLE(Markdown)
    INSERT_VARIABLE(NoColor)
    INSERT_VARIABLE(Root)
    INSERT_VARIABLE(Quiet)
    INSERT_VARIABLE(RuntimeDepsListFile)
    INSERT_VARIABLE(ScriptExecutable)
    INSERT_VARIABLE(Threads)
    INSERT_VARIABLE(Time)
    INSERT_VARIABLE(Tracelog)
    INSERT_VARIABLE(Verbose)
    INSERT_VARIABLE(Version)
  }
  return info_map;
}

#undef INSERT_VARIABLE

}  // namespace switches
