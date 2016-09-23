// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/gn/ninja_build_writer.h"

#include <stddef.h>

#include <fstream>
#include <map>
#include <sstream>

#include "base/command_line.h"
#include "base/files/file_util.h"
#include "base/path_service.h"
#include "base/process/process_handle.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "build/build_config.h"
#include "tools/gn/build_settings.h"
#include "tools/gn/builder.h"
#include "tools/gn/err.h"
#include "tools/gn/escape.h"
#include "tools/gn/filesystem_utils.h"
#include "tools/gn/input_file_manager.h"
#include "tools/gn/loader.h"
#include "tools/gn/ninja_utils.h"
#include "tools/gn/pool.h"
#include "tools/gn/scheduler.h"
#include "tools/gn/switches.h"
#include "tools/gn/target.h"
#include "tools/gn/trace.h"

#if defined(OS_WIN)
#include <windows.h>
#endif

namespace {

struct Counts {
  Counts() : count(0), last_seen(nullptr) {}

  // Number of targets of this type.
  int count;

  // The last one we encountered.
  const Target* last_seen;
};

std::string GetSelfInvocationCommand(const BuildSettings* build_settings) {
  base::FilePath executable;
  PathService::Get(base::FILE_EXE, &executable);

  base::CommandLine cmdline(executable.NormalizePathSeparatorsTo('/'));
  cmdline.AppendArg("gen");
  cmdline.AppendArg(build_settings->build_dir().value());
  cmdline.AppendSwitchPath(std::string("--") + switches::kRoot,
                           build_settings->root_path());
  // Successful automatic invocations shouldn't print output.
  cmdline.AppendSwitch(std::string("-") + switches::kQuiet);

  EscapeOptions escape_shell;
  escape_shell.mode = ESCAPE_NINJA_COMMAND;
#if defined(OS_WIN)
  // The command line code quoting varies by platform. We have one string,
  // possibly with spaces, that we want to quote. The Windows command line
  // quotes again, so we don't want quoting. The Posix one doesn't.
  escape_shell.inhibit_quoting = true;
#endif

  const base::CommandLine& our_cmdline =
      *base::CommandLine::ForCurrentProcess();
  const base::CommandLine::SwitchMap& switches = our_cmdline.GetSwitches();
  for (base::CommandLine::SwitchMap::const_iterator i = switches.begin();
       i != switches.end(); ++i) {
    // Only write arguments we haven't already written. Always skip "args"
    // since those will have been written to the file and will be used
    // implicitly in the future. Keeping --args would mean changes to the file
    // would be ignored.
    if (i->first != switches::kQuiet &&
        i->first != switches::kRoot &&
        i->first != switches::kArgs) {
      std::string escaped_value =
          EscapeString(FilePathToUTF8(i->second), escape_shell, nullptr);
      cmdline.AppendSwitchASCII(i->first, escaped_value);
    }
  }

#if defined(OS_WIN)
  return base::WideToUTF8(cmdline.GetCommandLineString());
#else
  return cmdline.GetCommandLineString();
#endif
}

// Given an output that appears more than once, generates an error message
// that describes the problem and which targets generate it.
Err GetDuplicateOutputError(const std::vector<const Target*>& all_targets,
                            const OutputFile& bad_output) {
  std::vector<const Target*> matches;
  for (const Target* target : all_targets) {
    for (const auto& output : target->computed_outputs()) {
      if (output == bad_output) {
        matches.push_back(target);
        break;
      }
    }
  }

  // There should always be at least two targets generating this file for this
  // function to be called in the first place.
  DCHECK(matches.size() >= 2);
  std::string matches_string;
  for (const Target* target : matches)
    matches_string += "  " + target->label().GetUserVisibleName(false) + "\n";

  Err result(matches[0]->defined_from(), "Duplicate output file.",
      "Two or more targets generate the same output:\n  " +
      bad_output.value() + "\n\n"
      "This is can often be fixed by changing one of the target names, or by \n"
      "setting an output_name on one of them.\n"
      "\nCollisions:\n" + matches_string);
  for (size_t i = 1; i < matches.size(); i++)
    result.AppendSubErr(Err(matches[i]->defined_from(), "Collision."));
  return result;
}

}  // namespace

NinjaBuildWriter::NinjaBuildWriter(
    const BuildSettings* build_settings,
    const std::map<const Settings*, const Toolchain*>& used_toolchains,
    const Toolchain* default_toolchain,
    const std::vector<const Target*>& default_toolchain_targets,
    std::ostream& out,
    std::ostream& dep_out)
    : build_settings_(build_settings),
      used_toolchains_(used_toolchains),
      default_toolchain_(default_toolchain),
      default_toolchain_targets_(default_toolchain_targets),
      out_(out),
      dep_out_(dep_out),
      path_output_(build_settings->build_dir(),
                   build_settings->root_path_utf8(),
                   ESCAPE_NINJA) {}

NinjaBuildWriter::~NinjaBuildWriter() {
}

bool NinjaBuildWriter::Run(Err* err) {
  WriteNinjaRules();
  WriteAllPools();
  WriteSubninjas();
  return WritePhonyAndAllRules(err);
}

// static
bool NinjaBuildWriter::RunAndWriteFile(
    const BuildSettings* build_settings,
    const Builder& builder,
    Err* err) {
  ScopedTrace trace(TraceItem::TRACE_FILE_WRITE, "build.ninja");

  std::vector<const Target*> all_targets = builder.GetAllResolvedTargets();
  std::map<const Settings*, const Toolchain*> used_toolchains;

  // Find the default toolchain info.
  Label default_toolchain_label = builder.loader()->GetDefaultToolchain();
  const Settings* default_toolchain_settings =
      builder.loader()->GetToolchainSettings(default_toolchain_label);
  const Toolchain* default_toolchain =
      builder.GetToolchain(default_toolchain_label);

  // Most targets will be in the default toolchain. Add it at the beginning and
  // skip adding it to the list every time in the loop.
  used_toolchains[default_toolchain_settings] = default_toolchain;

  std::vector<const Target*> default_toolchain_targets;
  default_toolchain_targets.reserve(all_targets.size());
  for (const Target* target : all_targets) {
    if (target->settings() == default_toolchain_settings) {
      default_toolchain_targets.push_back(target);
      // The default toolchain will already have been added to the used
      // settings array.
    } else if (used_toolchains.find(target->settings()) ==
               used_toolchains.end()) {
      used_toolchains[target->settings()] =
          builder.GetToolchain(target->settings()->toolchain_label());
    }
  }

  std::stringstream file;
  std::stringstream depfile;
  NinjaBuildWriter gen(build_settings, used_toolchains, default_toolchain,
                       default_toolchain_targets, file, depfile);
  if (!gen.Run(err))
    return false;

  // Unconditionally write the build.ninja. Ninja's build-out-of-date checking
  // will re-run GN when any build input is newer than build.ninja, so any time
  // the build is updated, build.ninja's timestamp needs to updated also, even
  // if the contents haven't been changed.
  base::FilePath ninja_file_name(build_settings->GetFullPath(
      SourceFile(build_settings->build_dir().value() + "build.ninja")));
  base::CreateDirectory(ninja_file_name.DirName());
  std::string ninja_contents = file.str();
  if (base::WriteFile(ninja_file_name, ninja_contents.data(),
                      static_cast<int>(ninja_contents.size())) !=
      static_cast<int>(ninja_contents.size()))
    return false;

  // Dep file listing build dependencies.
  base::FilePath dep_file_name(build_settings->GetFullPath(
      SourceFile(build_settings->build_dir().value() + "build.ninja.d")));
  std::string dep_contents = depfile.str();
  if (base::WriteFile(dep_file_name, dep_contents.data(),
                      static_cast<int>(dep_contents.size())) !=
      static_cast<int>(dep_contents.size()))
    return false;

  return true;
}

void NinjaBuildWriter::WriteNinjaRules() {
  out_ << "rule gn\n";
  out_ << "  command = " << GetSelfInvocationCommand(build_settings_) << "\n";
  out_ << "  description = Regenerating ninja files\n\n";

  // This rule will regenerate the ninja files when any input file has changed.
  out_ << "build build.ninja: gn\n"
       << "  generator = 1\n"
       << "  depfile = build.ninja.d\n";

  // Input build files. These go in the ".d" file. If we write them as
  // dependencies in the .ninja file itself, ninja will expect the files to
  // exist and will error if they don't. When files are listed in a depfile,
  // missing files are ignored.
  dep_out_ << "build.ninja:";
  std::vector<base::FilePath> input_files;
  g_scheduler->input_file_manager()->GetAllPhysicalInputFileNames(&input_files);

  // Other files read by the build.
  std::vector<base::FilePath> other_files = g_scheduler->GetGenDependencies();

  // Sort the input files to order them deterministically.
  // Additionally, remove duplicate filepaths that seem to creep in.
  std::set<base::FilePath> fileset(input_files.begin(), input_files.end());
  fileset.insert(other_files.begin(), other_files.end());

  for (const auto& other_file : fileset)
    dep_out_ << " " << FilePathToUTF8(other_file);

  out_ << std::endl;
}

void NinjaBuildWriter::WriteAllPools() {
  // Compute the pools referenced by all tools of all used toolchains.
  std::set<const Pool*> used_pools;
  for (const auto& pair : used_toolchains_) {
    for (int j = Toolchain::TYPE_NONE + 1; j < Toolchain::TYPE_NUMTYPES; j++) {
      Toolchain::ToolType tool_type = static_cast<Toolchain::ToolType>(j);
      const Tool* tool = pair.second->GetTool(tool_type);
      if (tool && tool->pool().ptr)
        used_pools.insert(tool->pool().ptr);
    }
  }

  for (const Pool* pool : used_pools) {
    std::string pool_name = pool->GetNinjaName(default_toolchain_->label());
    out_ << "pool " << pool_name << std::endl
         << "  depth = " << pool->depth() << std::endl
         << std::endl;
  }
}

void NinjaBuildWriter::WriteSubninjas() {
  for (const auto& pair : used_toolchains_) {
    out_ << "subninja ";
    path_output_.WriteFile(out_, GetNinjaFileForToolchain(pair.first));
    out_ << std::endl;
  }
  out_ << std::endl;
}

bool NinjaBuildWriter::WritePhonyAndAllRules(Err* err) {
  // Track rules as we generate them so we don't accidentally write a phony
  // rule that collides with something else.
  // GN internally generates an "all" target, so don't duplicate it.
  base::hash_set<std::string> written_rules;
  written_rules.insert("all");

  // Set if we encounter a target named "//:default".
  bool default_target_exists = false;

  // Targets in the root build file.
  std::vector<const Target*> toplevel_targets;

  // Targets with names matching their toplevel directories. For example
  // "//foo:foo". Expect this is the naming scheme for "big components."
  std::vector<const Target*> toplevel_dir_targets;

  // Tracks the number of each target with the given short name, as well
  // as the short names of executables (which will be a subset of short_names).
  std::map<std::string, Counts> short_names;
  std::map<std::string, Counts> exes;

  for (const Target* target : default_toolchain_targets_) {
    const Label& label = target->label();
    const std::string& short_name = label.name();

    if (label.dir().value() == "//" && label.name() == "default")
      default_target_exists = true;

    // Count the number of targets with the given short name.
    Counts& short_names_counts = short_names[short_name];
    short_names_counts.count++;
    short_names_counts.last_seen = target;

    // Count executables with the given short name.
    if (target->output_type() == Target::EXECUTABLE) {
      Counts& exes_counts = exes[short_name];
      exes_counts.count++;
      exes_counts.last_seen = target;
    }

    // Find targets in "important" directories.
    const std::string& dir_string = label.dir().value();
    if (dir_string.size() == 2 &&
        dir_string[0] == '/' && dir_string[1] == '/') {
      toplevel_targets.push_back(target);
    } else if (
        dir_string.size() == label.name().size() + 3 &&  // Size matches.
        dir_string[0] == '/' && dir_string[1] == '/' &&  // "//" at beginning.
        dir_string[dir_string.size() - 1] == '/' &&  // "/" at end.
        dir_string.compare(2, label.name().size(), label.name()) == 0) {
      toplevel_dir_targets.push_back(target);
    }

    // Add the output files from each target to the written rules so that
    // we don't write phony rules that collide with anything generated by the
    // build.
    //
    // If at this point there is a collision (no phony rules have been
    // generated yet), two targets make the same output so throw an error.
    for (const auto& output : target->computed_outputs()) {
      // Need to normalize because many toolchain outputs will be preceeded
      // with "./".
      std::string output_string(output.value());
      NormalizePath(&output_string);
      if (!written_rules.insert(output_string).second) {
        *err = GetDuplicateOutputError(default_toolchain_targets_, output);
        return false;
      }
    }
  }

  // First prefer the short names of toplevel targets.
  for (const Target* target : toplevel_targets) {
    if (written_rules.insert(target->label().name()).second)
      WritePhonyRule(target, target->label().name());
  }

  // Next prefer short names of toplevel dir targets.
  for (const Target* target : toplevel_dir_targets) {
    if (written_rules.insert(target->label().name()).second)
      WritePhonyRule(target, target->label().name());
  }

  // Write out the names labels of executables. Many toolchains will produce
  // executables in the root build directory with no extensions, so the names
  // will already exist and this will be a no-op.  But on Windows such programs
  // will have extensions, and executables may override the output directory to
  // go into some other place.
  //
  // Putting this after the "toplevel" rules above also means that you can
  // steal the short name from an executable by outputting the executable to
  // a different directory or using a different output name, and writing a
  // toplevel build rule.
  for (const auto& pair : exes) {
    const Counts& counts = pair.second;
    const std::string& short_name = counts.last_seen->label().name();
    if (counts.count == 1 && written_rules.insert(short_name).second)
      WritePhonyRule(counts.last_seen, short_name);
  }

  // Write short names when those names are unique and not already taken.
  for (const auto& pair : short_names) {
    const Counts& counts = pair.second;
    const std::string& short_name = counts.last_seen->label().name();
    if (counts.count == 1 && written_rules.insert(short_name).second)
      WritePhonyRule(counts.last_seen, short_name);
  }

  // Write the label variants of the target name.
  for (const Target* target : default_toolchain_targets_) {
    const Label& label = target->label();

    // Write the long name "foo/bar:baz" for the target "//foo/bar:baz".
    std::string long_name = label.GetUserVisibleName(false);
    base::TrimString(long_name, "/", &long_name);
    if (written_rules.insert(long_name).second)
      WritePhonyRule(target, long_name);

    // Write the directory name with no target name if they match
    // (e.g. "//foo/bar:bar" -> "foo/bar").
    if (FindLastDirComponent(label.dir()) == label.name()) {
      std::string medium_name = DirectoryWithNoLastSlash(label.dir());
      base::TrimString(medium_name, "/", &medium_name);
      // That may have generated a name the same as the short name of the
      // target which we already wrote.
      if (medium_name != label.name() &&
          written_rules.insert(medium_name).second)
        WritePhonyRule(target, medium_name);
    }

    // Write the short name if no other target shares that short name and
    // non of the higher-priority rules above claimed it.
    if (short_names[label.name()].count == 1 &&
        written_rules.insert(label.name()).second)
      WritePhonyRule(target, label.name());
  }

  // Write the autogenerated "all" rule.
  if (!default_toolchain_targets_.empty()) {
    out_ << "\nbuild all: phony";

    EscapeOptions ninja_escape;
    ninja_escape.mode = ESCAPE_NINJA;
    for (const Target* target : default_toolchain_targets_) {
      out_ << " $\n    ";
      path_output_.WriteFile(out_, target->dependency_output_file());
    }
  }
  out_ << std::endl;

  if (default_target_exists)
    out_ << "\ndefault default" << std::endl;
  else if (!default_toolchain_targets_.empty())
    out_ << "\ndefault all" << std::endl;

  return true;
}

void NinjaBuildWriter::WritePhonyRule(const Target* target,
                                      const std::string& phony_name) {
  EscapeOptions ninja_escape;
  ninja_escape.mode = ESCAPE_NINJA;

  // Escape for special chars Ninja will handle.
  std::string escaped = EscapeString(phony_name, ninja_escape, nullptr);

  out_ << "build " << escaped << ": phony ";
  path_output_.WriteFile(out_, target->dependency_output_file());
  out_ << std::endl;
}
