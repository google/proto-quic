// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <map>

#include "base/command_line.h"
#include "base/environment.h"
#include "base/files/file_util.h"
#include "base/process/launch.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "build/build_config.h"
#include "tools/gn/commands.h"
#include "tools/gn/filesystem_utils.h"
#include "tools/gn/input_file.h"
#include "tools/gn/parse_tree.h"
#include "tools/gn/setup.h"
#include "tools/gn/standard_out.h"
#include "tools/gn/tokenizer.h"
#include "tools/gn/trace.h"

#if defined(OS_WIN)
#include <windows.h>
#include <shellapi.h>
#endif

namespace commands {

namespace {

const char kSwitchList[] = "list";
const char kSwitchShort[] = "short";

bool DoesLineBeginWithComment(const base::StringPiece& line) {
  // Skip whitespace.
  size_t i = 0;
  while (i < line.size() && base::IsAsciiWhitespace(line[i]))
    i++;

  return i < line.size() && line[i] == '#';
}

// Returns the offset of the beginning of the line identified by |offset|.
size_t BackUpToLineBegin(const std::string& data, size_t offset) {
  // Degenerate case of an empty line. Below we'll try to return the
  // character after the newline, but that will be incorrect in this case.
  if (offset == 0 || Tokenizer::IsNewline(data, offset))
    return offset;

  size_t cur = offset;
  do {
    cur --;
    if (Tokenizer::IsNewline(data, cur))
      return cur + 1;  // Want the first character *after* the newline.
  } while (cur > 0);
  return 0;
}

// Assumes DoesLineBeginWithComment(), this strips the # character from the
// beginning and normalizes preceeding whitespace.
std::string StripHashFromLine(const base::StringPiece& line) {
  // Replace the # sign and everything before it with 3 spaces, so that a
  // normal comment that has a space after the # will be indented 4 spaces
  // (which makes our formatting come out nicely). If the comment is indented
  // from there, we want to preserve that indenting.
  return "   " + line.substr(line.find('#') + 1).as_string();
}

// Tries to find the comment before the setting of the given value.
void GetContextForValue(const Value& value,
                        std::string* location_str,
                        std::string* comment) {
  Location location = value.origin()->GetRange().begin();
  const InputFile* file = location.file();
  if (!file)
    return;

  *location_str = file->name().value() + ":" +
      base::IntToString(location.line_number());

  const std::string& data = file->contents();
  size_t line_off =
      Tokenizer::ByteOffsetOfNthLine(data, location.line_number());

  while (line_off > 1) {
    line_off -= 2;  // Back up to end of previous line.
    size_t previous_line_offset = BackUpToLineBegin(data, line_off);

    base::StringPiece line(&data[previous_line_offset],
                           line_off - previous_line_offset + 1);
    if (!DoesLineBeginWithComment(line))
      break;

    comment->insert(0, StripHashFromLine(line) + "\n");
    line_off = previous_line_offset;
  }
}

void PrintArgHelp(const base::StringPiece& name, const Value& value) {
  OutputString(name.as_string(), DECORATION_YELLOW);
  OutputString("  Default = " + value.ToString(true) + "\n");

  if (value.origin()) {
    std::string location, comment;
    GetContextForValue(value, &location, &comment);
    OutputString("    " + location + "\n" + comment);
  } else {
    OutputString("    (Internally set; try `gn help " + name.as_string() +
                 "`.)\n");
  }
}

int ListArgs(const std::string& build_dir) {
  Setup* setup = new Setup;
  setup->build_settings().set_check_for_bad_items(false);
  if (!setup->DoSetup(build_dir, false) || !setup->Run())
    return 1;

  Scope::KeyValueMap build_args;
  setup->build_settings().build_args().MergeDeclaredArguments(&build_args);

  // Find all of the arguments we care about. Use a regular map so they're
  // sorted nicely when we write them out.
  std::map<base::StringPiece, Value> sorted_args;
  std::string list_value =
      base::CommandLine::ForCurrentProcess()->GetSwitchValueASCII(kSwitchList);
  if (list_value.empty()) {
    // List all values.
    for (const auto& arg : build_args)
      sorted_args.insert(arg);
  } else {
    // List just the one specified as the parameter to --list.
    Scope::KeyValueMap::const_iterator found_arg = build_args.find(list_value);
    if (found_arg == build_args.end()) {
      Err(Location(), "Unknown build argument.",
          "You asked for \"" + list_value + "\" which I didn't find in any "
          "build file\nassociated with this build.").PrintToStdout();
      return 1;
    }
    sorted_args.insert(*found_arg);
  }

  if (base::CommandLine::ForCurrentProcess()->HasSwitch(kSwitchShort)) {
    // Short key=value output.
    for (const auto& arg : sorted_args) {
      OutputString(arg.first.as_string());
      OutputString(" = ");
      OutputString(arg.second.ToString(true));
      OutputString("\n");
    }
    return 0;
  }

  // Long output.
  for (const auto& arg : sorted_args) {
    PrintArgHelp(arg.first, arg.second);
    OutputString("\n");
  }

  return 0;
}

#if defined(OS_WIN)

bool RunEditor(const base::FilePath& file_to_edit) {
  SHELLEXECUTEINFO info;
  memset(&info, 0, sizeof(info));
  info.cbSize = sizeof(info);
  info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_CLASSNAME;
  info.lpFile = file_to_edit.value().c_str();
  info.nShow = SW_SHOW;
  info.lpClass = L".txt";
  if (!::ShellExecuteEx(&info)) {
    Err(Location(), "Couldn't run editor.",
        "Just edit \"" + FilePathToUTF8(file_to_edit) +
        "\" manually instead.").PrintToStdout();
    return false;
  }

  if (!info.hProcess) {
    // Windows re-used an existing process.
    OutputString("\"" + FilePathToUTF8(file_to_edit) +
                 "\" opened in editor, save it and press <Enter> when done.\n");
    getchar();
  } else {
    OutputString("Waiting for editor on \"" + FilePathToUTF8(file_to_edit) +
                 "\"...\n");
    ::WaitForSingleObject(info.hProcess, INFINITE);
    ::CloseHandle(info.hProcess);
  }
  return true;
}

#else  // POSIX

bool RunEditor(const base::FilePath& file_to_edit) {
  const char* editor_ptr = getenv("VISUAL");
  if (!editor_ptr)
    editor_ptr = getenv("GN_EDITOR");
  if (!editor_ptr)
    editor_ptr = getenv("EDITOR");
  if (!editor_ptr)
    editor_ptr = "vi";

  std::string cmd(editor_ptr);
  cmd.append(" \"");

  // Its impossible to do this properly since we don't know the user's shell,
  // but quoting and escaping internal quotes should handle 99.999% of all
  // cases.
  std::string escaped_name = file_to_edit.value();
  base::ReplaceSubstringsAfterOffset(&escaped_name, 0, "\"", "\\\"");
  cmd.append(escaped_name);
  cmd.push_back('"');

  OutputString("Waiting for editor on \"" + file_to_edit.value() +
               "\"...\n");
  return system(cmd.c_str()) == 0;
}

#endif

int EditArgsFile(const std::string& build_dir) {
  {
    // Scope the setup. We only use it for some basic state. We'll do the
    // "real" build below in the gen command.
    Setup setup;
    setup.build_settings().set_check_for_bad_items(false);
    // Don't fill build arguments. We're about to edit the file which supplies
    // these in the first place.
    setup.set_fill_arguments(false);
    if (!setup.DoSetup(build_dir, true))
      return 1;

    // Ensure the file exists. Need to normalize path separators since on
    // Windows they can come out as forward slashes here, and that confuses some
    // of the commands.
    base::FilePath arg_file =
        setup.build_settings().GetFullPath(setup.GetBuildArgFile())
        .NormalizePathSeparators();
    if (!base::PathExists(arg_file)) {
      std::string argfile_default_contents =
          "# Build arguments go here. Examples:\n"
          "#   is_component_build = true\n"
          "#   is_debug = false\n"
          "# See \"gn args <out_dir> --list\" for available build "
          "arguments.\n";
#if defined(OS_WIN)
      // Use Windows lineendings for this file since it will often open in
      // Notepad which can't handle Unix ones.
      base::ReplaceSubstringsAfterOffset(
          &argfile_default_contents, 0, "\n", "\r\n");
#endif
      base::CreateDirectory(arg_file.DirName());
      base::WriteFile(arg_file, argfile_default_contents.c_str(),
                      static_cast<int>(argfile_default_contents.size()));
    }

    ScopedTrace editor_trace(TraceItem::TRACE_SETUP, "Waiting for editor");
    if (!RunEditor(arg_file))
      return 1;
  }

  // Now do a normal "gen" command.
  OutputString("Generating files...\n");
  std::vector<std::string> gen_commands;
  gen_commands.push_back(build_dir);
  return RunGen(gen_commands);
}

}  // namespace

extern const char kArgs[] = "args";
extern const char kArgs_HelpShort[] =
    "args: Display or configure arguments declared by the build.";
extern const char kArgs_Help[] =
    "gn args <out_dir> [--list] [--short] [--args]\n"
    "\n"
    "  See also \"gn help buildargs\" for a more high-level overview of how\n"
    "  build arguments work.\n"
    "\n"
    "Usage\n"
    "  gn args <out_dir>\n"
    "      Open the arguments for the given build directory in an editor\n"
    "      (as specified by the EDITOR environment variable). If the given\n"
    "      build directory doesn't exist, it will be created and an empty\n"
    "      args file will be opened in the editor. You would type something\n"
    "      like this into that file:\n"
    "          enable_doom_melon=false\n"
    "          os=\"android\"\n"
    "\n"
    "      Note: you can edit the build args manually by editing the file\n"
    "      \"args.gn\" in the build directory and then running\n"
    "      \"gn gen <out_dir>\".\n"
    "\n"
    "  gn args <out_dir> --list[=<exact_arg>] [--short]\n"
    "      Lists all build arguments available in the current configuration,\n"
    "      or, if an exact_arg is specified for the list flag, just that one\n"
    "      build argument.\n"
    "\n"
    "      The output will list the declaration location, default value, and\n"
    "      comment preceeding the declaration. If --short is specified,\n"
    "      only the names and values will be printed.\n"
    "\n"
    "      If the out_dir is specified, the build configuration will be\n"
    "      taken from that build directory. The reason this is needed is that\n"
    "      the definition of some arguments is dependent on the build\n"
    "      configuration, so setting some values might add, remove, or change\n"
    "      the default values for other arguments. Specifying your exact\n"
    "      configuration allows the proper arguments to be displayed.\n"
    "\n"
    "      Instead of specifying the out_dir, you can also use the\n"
    "      command-line flag to specify the build configuration:\n"
    "        --args=<exact list of args to use>\n"
    "\n"
    "Examples\n"
    "  gn args out/Debug\n"
    "    Opens an editor with the args for out/Debug.\n"
    "\n"
    "  gn args out/Debug --list --short\n"
    "    Prints all arguments with their default values for the out/Debug\n"
    "    build.\n"
    "\n"
    "  gn args out/Debug --list=target_cpu\n"
    "    Prints information about the \"target_cpu\" argument for the "
        "out/Debug\n"
    "    build.\n"
    "\n"
    "  gn args --list --args=\"os=\\\"android\\\" enable_doom_melon=true\"\n"
    "    Prints all arguments with the default values for a build with the\n"
    "    given arguments set (which may affect the values of other\n"
    "    arguments).\n";

int RunArgs(const std::vector<std::string>& args) {
  if (args.size() != 1) {
    Err(Location(), "Exactly one build dir needed.",
        "Usage: \"gn args <out_dir>\"\n"
        "Or see \"gn help args\" for more variants.").PrintToStdout();
    return 1;
  }

  if (base::CommandLine::ForCurrentProcess()->HasSwitch(kSwitchList))
    return ListArgs(args[0]);
  return EditArgsFile(args[0]);
}

}  // namespace commands
