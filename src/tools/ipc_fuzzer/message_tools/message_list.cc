// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>

#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

#include "build/build_config.h"

// Include once to get the type definitions
#include "tools/ipc_fuzzer/message_lib/all_messages.h"

struct msginfo {
  const char* name;
  const char* file;
  int id;

  bool operator< (const msginfo& other) const {
    return id < other.id;
  }
};

// Redefine macros to generate table
#include "tools/ipc_fuzzer/message_lib/all_message_null_macros.h"
#undef IPC_MESSAGE_DECL
#define IPC_MESSAGE_DECL(name, ...) {#name, __FILE__, IPC_MESSAGE_ID()},

static msginfo msgtable[] = {
#include "tools/ipc_fuzzer/message_lib/all_messages.h"
};
#define MSGTABLE_SIZE (sizeof(msgtable)/sizeof(msgtable[0]))
static_assert(MSGTABLE_SIZE, "check your headers for an extra semicolon");

static bool check_msgtable() {
  bool result = true;
  int previous_class_id = 0;
  int highest_class_id = 0;
  const char* file_name = "NONE";
  const char* previous_file_name = "NONE";
  std::vector<int> exemptions;

  // Exclude test and other non-browser files from consideration.  Do not
  // include message files used inside the actual chrome browser in this list.
  exemptions.push_back(TestMsgStart);
  exemptions.push_back(FirefoxImporterUnittestMsgStart);
  exemptions.push_back(ShellMsgStart);
  exemptions.push_back(LayoutTestMsgStart);
  exemptions.push_back(MetroViewerMsgStart);
  exemptions.push_back(CCMsgStart);  // Nothing but param traits.

#if defined(DISABLE_NACL)
  exemptions.push_back(NaClMsgStart);
#endif  // defined(DISABLE_NACL)

#if !defined(OS_ANDROID)
  exemptions.push_back(JavaBridgeMsgStart);
  exemptions.push_back(MediaPlayerMsgStart);
  exemptions.push_back(EncryptedMediaMsgStart);
  exemptions.push_back(GinJavaBridgeMsgStart);
  exemptions.push_back(AndroidWebViewMsgStart);
#endif  // !defined(OS_ANDROID)

#if !defined(OS_POSIX)
  exemptions.push_back(CastMediaMsgStart); // FIXME: Add support for types.
#endif  // !defined(OS_POSIX)

#if !defined(USE_OZONE)
  exemptions.push_back(OzoneGpuMsgStart);
#endif  // !defined(USE_OZONE)

  for (size_t i = 0; i < MSGTABLE_SIZE; ++i) {
    int class_id = IPC_MESSAGE_ID_CLASS(msgtable[i].id);
    file_name = msgtable[i].file;
    if (class_id >= LastIPCMsgStart) {
      std::cout << "Invalid LastIPCMsgStart setting\n";
      result = false;
    }
    if (class_id == previous_class_id &&
        strcmp(file_name, previous_file_name) != 0) {
      std::cerr << "enum used in multiple files: "
                << file_name << " vs "
                << previous_file_name << "\n";
      result = false;
    }
    while (class_id > previous_class_id + 1) {
      std::vector<int>::iterator iter;
      iter = find(exemptions.begin(), exemptions.end(), previous_class_id + 1);
      if (iter == exemptions.end()) {
        std::cout << "Missing message file for enum "
                  << class_id - (previous_class_id + 1)
                  <<  " before enum used by " << file_name << "\n";
        result = false;
      }
      ++previous_class_id;
    }
    previous_class_id = class_id;
    previous_file_name = file_name;
    if (class_id > highest_class_id)
      highest_class_id = class_id;
  }

  while (LastIPCMsgStart > highest_class_id + 1) {
    std::vector<int>::iterator iter;
    iter = find(exemptions.begin(), exemptions.end(), highest_class_id+1);
    if (iter == exemptions.end()) {
      std::cout << "Missing message file for enum "
                << LastIPCMsgStart - (highest_class_id + 1)
                << " before enum LastIPCMsgStart\n";
      break;
    }
    ++highest_class_id;
  }

  if (!result)
    std::cout << "Please check tools/ipc_fuzzer/message_lib/all_messages.h\n";

  return result;
}

static void dump_msgtable(bool show_args, bool show_ids,
                          bool show_comma, const char *prefix) {
  bool first = true;
  for (size_t i = 0; i < MSGTABLE_SIZE; ++i) {
    if ((!prefix) || strstr(msgtable[i].name, prefix) == msgtable[i].name) {
      if (show_comma) {
        if (!first)
          std::cout << ",";
        first = false;
        std::cout << msgtable[i].id;
      } else {
        if (show_ids)
          std::cout << msgtable[i].id << " " <<
              IPC_MESSAGE_ID_CLASS(msgtable[i].id) << "," <<
              IPC_MESSAGE_ID_LINE(msgtable[i].id) << " ";
        std::cout << msgtable[i].name << "\n";
      }
    }
  }
  if (show_comma)
    std::cout << "\n";
}

int main(int argc, char **argv) {
  bool show_args = false;
  bool show_ids  = false;
  bool skip_check = false;
  bool show_comma = false;
  const char *filter = NULL;

  while (--argc > 0) {
    ++argv;
    if (std::string("--args") == *argv) {
      show_args = true;
    } else if (std::string("--comma") == *argv) {
      show_comma = true;
    } else if (std::string("--filter") == *argv) {
      filter = *(++argv);
      --argc;
    } else if (std::string("--ids") == *argv) {
      show_ids = true;
    } else if (std::string("--no-check") == *argv) {
      skip_check = true;
    } else {
      std::cout <<
          "usage: ipc_message_list [--args] [--ids] [--no-check] "
          "[--filter prefix] [--comma]\n";
      return 1;
    }
  }

  std::sort(msgtable, msgtable + MSGTABLE_SIZE);

  if (!skip_check && check_msgtable() == false)
    return 1;

  dump_msgtable(show_args, show_ids, show_comma, filter);
  return 0;
}
