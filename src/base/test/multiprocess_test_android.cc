// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/test/multiprocess_test.h"

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <memory>
#include <utility>
#include <vector>

#include "base/base_switches.h"
#include "base/command_line.h"
#include "base/containers/hash_tables.h"
#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/pickle.h"
#include "base/posix/global_descriptors.h"
#include "base/posix/unix_domain_socket_linux.h"
#include "testing/multiprocess_func_list.h"

namespace base {

namespace {

const int kMaxMessageSize = 1024 * 1024;
const int kFragmentSize = 4096;

// Message sent between parent process and helper child process.
enum class MessageType : uint32_t {
  START_REQUEST,
  START_RESPONSE,
  WAIT_REQUEST,
  WAIT_RESPONSE,
};

struct MessageHeader {
  uint32_t size;
  MessageType type;
};

struct StartProcessRequest {
  MessageHeader header =
      {sizeof(StartProcessRequest), MessageType::START_REQUEST};

  uint32_t num_args = 0;
  uint32_t num_fds = 0;
};

struct StartProcessResponse {
  MessageHeader header =
      {sizeof(StartProcessResponse), MessageType::START_RESPONSE};

  pid_t child_pid;
};

struct WaitProcessRequest {
  MessageHeader header =
      {sizeof(WaitProcessRequest), MessageType::WAIT_REQUEST};

  pid_t pid;
  uint64_t timeout_ms;
};

struct WaitProcessResponse {
  MessageHeader header =
      {sizeof(WaitProcessResponse), MessageType::WAIT_RESPONSE};

  bool success = false;
  int32_t exit_code = 0;
};

// Helper class that implements an alternate test child launcher for
// multi-process tests. The default implementation doesn't work if the child is
// launched after starting threads. However, for some tests (i.e. Mojo), this
// is necessary. This implementation works around that issue by forking a helper
// process very early in main(), before any real work is done. Then, when a
// child needs to be spawned, a message is sent to that helper process, which
// then forks and returns the result to the parent. The forked child then calls
// main() and things look as though a brand new process has been fork/exec'd.
class LaunchHelper {
 public:
  using MainFunction = int (*)(int, char**);

  LaunchHelper() {}

  // Initialise the alternate test child implementation.
  void Init(MainFunction main);

  // Starts a child test helper process.
  Process StartChildTestHelper(const std::string& procname,
                               const CommandLine& base_command_line,
                               const LaunchOptions& options);

  // Waits for a child test helper process.
  bool WaitForChildExitWithTimeout(const Process& process, TimeDelta timeout,
                                   int* exit_code);

  bool IsReady() const { return child_fd_ != -1; }
  bool IsChild() const { return is_child_; }

 private:
  // Wrappers around sendmsg/recvmsg that supports message fragmentation.
  void Send(int fd, const MessageHeader* msg, const std::vector<int>& fds);
  ssize_t Recv(int fd, void* buf, std::vector<ScopedFD>* fds);

  // Parent process implementation.
  void DoParent(int fd);
  // Helper process implementation.
  void DoHelper(int fd);

  void StartProcessInHelper(const StartProcessRequest* request,
                           std::vector<ScopedFD> fds);
  void WaitForChildInHelper(const WaitProcessRequest* request);

  bool is_child_ = false;

  // Parent vars.
  int child_fd_ = -1;

  // Helper vars.
  int parent_fd_ = -1;
  MainFunction main_ = nullptr;

  DISALLOW_COPY_AND_ASSIGN(LaunchHelper);
};

void LaunchHelper::Init(MainFunction main) {
  main_ = main;

  // Create a communication channel between the parent and child launch helper.
  // fd[0] belongs to the parent, fd[1] belongs to the child.
  int fds[2] = {-1, -1};
  int rv = socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds);
  PCHECK(rv == 0);
  CHECK_NE(-1, fds[0]);
  CHECK_NE(-1, fds[1]);

  pid_t pid = fork();
  PCHECK(pid >= 0) << "Fork failed";
  if (pid) {
    // Parent.
    rv = close(fds[1]);
    PCHECK(rv == 0);
    DoParent(fds[0]);
  } else {
    // Helper.
    rv = close(fds[0]);
    PCHECK(rv == 0);
    DoHelper(fds[1]);
    NOTREACHED();
    _exit(0);
  }
}

void LaunchHelper::Send(
    int fd, const MessageHeader* msg, const std::vector<int>& fds) {
  uint32_t bytes_remaining = msg->size;
  const char* buf = reinterpret_cast<const char*>(msg);
  while (bytes_remaining) {
    size_t send_size =
        (bytes_remaining > kFragmentSize) ? kFragmentSize : bytes_remaining;
    bool success = UnixDomainSocket::SendMsg(
        fd, buf, send_size,
        (bytes_remaining == msg->size) ? fds : std::vector<int>());
    CHECK(success);
    bytes_remaining -= send_size;
    buf += send_size;
  }
}

ssize_t LaunchHelper::Recv(int fd, void* buf, std::vector<ScopedFD>* fds) {
  ssize_t size = UnixDomainSocket::RecvMsg(fd, buf, kFragmentSize, fds);
  if (size <= 0)
    return size;

  const MessageHeader* header = reinterpret_cast<const MessageHeader*>(buf);
  CHECK(header->size < kMaxMessageSize);
  uint32_t bytes_remaining = header->size - size;
  char* buffer = reinterpret_cast<char*>(buf);
  buffer += size;
  while (bytes_remaining) {
    std::vector<ScopedFD> dummy_fds;
    size = UnixDomainSocket::RecvMsg(fd, buffer, kFragmentSize, &dummy_fds);
    if (size <= 0)
      return size;

    CHECK(dummy_fds.empty());
    CHECK(size == kFragmentSize ||
          static_cast<size_t>(size) == bytes_remaining);
    bytes_remaining -= size;
    buffer += size;
  }
  return header->size;
}

void LaunchHelper::DoParent(int fd) {
  child_fd_ = fd;
}

void LaunchHelper::DoHelper(int fd) {
  parent_fd_ = fd;
  is_child_ = true;
  std::unique_ptr<char[]> buf(new char[kMaxMessageSize]);
  while (true) {
    // Wait for a message from the parent.
    std::vector<ScopedFD> fds;
    ssize_t size = Recv(parent_fd_, buf.get(), &fds);
    if (size == 0 || (size < 0 && errno == ECONNRESET)) {
      _exit(0);
    }
    PCHECK(size > 0);

    const MessageHeader* header =
        reinterpret_cast<const MessageHeader*>(buf.get());
    CHECK_EQ(static_cast<ssize_t>(header->size), size);
    switch (header->type) {
      case MessageType::START_REQUEST:
        StartProcessInHelper(
            reinterpret_cast<const StartProcessRequest*>(buf.get()),
            std::move(fds));
        break;
      case MessageType::WAIT_REQUEST:
        WaitForChildInHelper(
            reinterpret_cast<const WaitProcessRequest*>(buf.get()));
        break;
      default:
        LOG(FATAL) << "Unsupported message type: "
                   << static_cast<uint32_t>(header->type);
    }
  }
}

void LaunchHelper::StartProcessInHelper(const StartProcessRequest* request,
                                        std::vector<ScopedFD> fds) {
  pid_t pid = fork();
  PCHECK(pid >= 0) << "Fork failed";
  if (pid) {
    // Helper.
    StartProcessResponse resp;
    resp.child_pid = pid;
    Send(parent_fd_, reinterpret_cast<const MessageHeader*>(&resp),
         std::vector<int>());
  } else {
    // Child.
    PCHECK(close(parent_fd_) == 0);
    parent_fd_ = -1;
    CommandLine::Reset();

    Pickle serialised_extra(reinterpret_cast<const char*>(request + 1),
                            request->header.size - sizeof(StartProcessRequest));
    PickleIterator iter(serialised_extra);
    std::vector<std::string> args;
    for (size_t i = 0; i < request->num_args; i++) {
      std::string arg;
      CHECK(iter.ReadString(&arg));
      args.push_back(std::move(arg));
    }

    CHECK_EQ(request->num_fds, fds.size());
    for (size_t i = 0; i < request->num_fds; i++) {
      int new_fd;
      CHECK(iter.ReadInt(&new_fd));
      int old_fd = fds[i].release();
      if (new_fd != old_fd) {
        if (dup2(old_fd, new_fd) < 0) {
          PLOG(FATAL) << "dup2";
        }
        PCHECK(close(old_fd) == 0);
      }
    }

    // argv has argc+1 elements, where the last element is NULL.
    std::unique_ptr<char*[]> argv(new char*[args.size() + 1]);
    for (size_t i = 0; i < args.size(); i++) {
      argv[i] = const_cast<char*>(args[i].c_str());
    }
    argv[args.size()] = nullptr;
    _exit(main_(args.size(), argv.get()));
    NOTREACHED();
  }
}

void LaunchHelper::WaitForChildInHelper(const WaitProcessRequest* request) {
  Process process(request->pid);
  TimeDelta timeout = TimeDelta::FromMilliseconds(request->timeout_ms);
  int exit_code = -1;
  bool success = process.WaitForExitWithTimeout(timeout, &exit_code);

  WaitProcessResponse resp;
  resp.exit_code = exit_code;
  resp.success = success;
  Send(parent_fd_, reinterpret_cast<const MessageHeader*>(&resp),
       std::vector<int>());
}

Process LaunchHelper::StartChildTestHelper(const std::string& procname,
                                           const CommandLine& base_command_line,
                                           const LaunchOptions& options) {

  CommandLine command_line(base_command_line);
  if (!command_line.HasSwitch(switches::kTestChildProcess))
    command_line.AppendSwitchASCII(switches::kTestChildProcess, procname);

  StartProcessRequest request;
  Pickle serialised_extra;
  const CommandLine::StringVector& argv = command_line.argv();
  for (const auto& arg : argv)
    CHECK(serialised_extra.WriteString(arg));
  request.num_args = argv.size();

  std::vector<int> fds_to_send;
  if (options.fds_to_remap) {
    for (auto p : *options.fds_to_remap) {
      CHECK(serialised_extra.WriteInt(p.second));
      fds_to_send.push_back(p.first);
    }
    request.num_fds = options.fds_to_remap->size();
  }

  size_t buf_size = sizeof(StartProcessRequest) + serialised_extra.size();
  request.header.size = buf_size;
  std::unique_ptr<char[]> buffer(new char[buf_size]);
  memcpy(buffer.get(), &request, sizeof(StartProcessRequest));
  memcpy(buffer.get() + sizeof(StartProcessRequest), serialised_extra.data(),
         serialised_extra.size());

  // Send start message.
  Send(child_fd_, reinterpret_cast<const MessageHeader*>(buffer.get()),
       fds_to_send);

  // Synchronously get response.
  StartProcessResponse response;
  std::vector<ScopedFD> recv_fds;
  ssize_t resp_size = Recv(child_fd_, &response, &recv_fds);
  PCHECK(resp_size == sizeof(StartProcessResponse));

  return Process(response.child_pid);
}

bool LaunchHelper::WaitForChildExitWithTimeout(
    const Process& process, TimeDelta timeout, int* exit_code) {

  WaitProcessRequest request;
  request.pid = process.Handle();
  request.timeout_ms = timeout.InMilliseconds();

  Send(child_fd_, reinterpret_cast<const MessageHeader*>(&request),
       std::vector<int>());

  WaitProcessResponse response;
  std::vector<ScopedFD> recv_fds;
  ssize_t resp_size = Recv(child_fd_, &response, &recv_fds);
  PCHECK(resp_size == sizeof(WaitProcessResponse));

  if (!response.success)
    return false;

  *exit_code = response.exit_code;
  return true;
}

LazyInstance<LaunchHelper>::Leaky g_launch_helper;

}  // namespace

void InitAndroidMultiProcessTestHelper(int (*main)(int, char**)) {
  DCHECK(main);
  // Don't allow child processes to themselves create new child processes.
  if (g_launch_helper.Get().IsChild())
    return;
  g_launch_helper.Get().Init(main);
}

bool AndroidIsChildProcess() {
  return g_launch_helper.Get().IsChild();
}

bool AndroidWaitForChildExitWithTimeout(
    const Process& process, TimeDelta timeout, int* exit_code) {
  CHECK(g_launch_helper.Get().IsReady());
  return g_launch_helper.Get().WaitForChildExitWithTimeout(
      process, timeout, exit_code);
}

// A very basic implementation for Android. On Android tests can run in an APK
// and we don't have an executable to exec*. This implementation does the bare
// minimum to execute the method specified by procname (in the child process).
//  - All options except |fds_to_remap| are ignored.
Process SpawnMultiProcessTestChild(const std::string& procname,
                                   const CommandLine& base_command_line,
                                   const LaunchOptions& options) {
  if (g_launch_helper.Get().IsReady()) {
    return g_launch_helper.Get().StartChildTestHelper(
        procname, base_command_line, options);
  }

  // TODO(viettrungluu): The FD-remapping done below is wrong in the presence of
  // cycles (e.g., fd1 -> fd2, fd2 -> fd1). crbug.com/326576
  FileHandleMappingVector empty;
  const FileHandleMappingVector* fds_to_remap =
      options.fds_to_remap ? options.fds_to_remap : &empty;

  pid_t pid = fork();

  if (pid < 0) {
    PLOG(ERROR) << "fork";
    return Process();
  }
  if (pid > 0) {
    // Parent process.
    return Process(pid);
  }
  // Child process.
  base::hash_set<int> fds_to_keep_open;
  for (FileHandleMappingVector::const_iterator it = fds_to_remap->begin();
       it != fds_to_remap->end(); ++it) {
    fds_to_keep_open.insert(it->first);
  }
  // Keep standard FDs (stdin, stdout, stderr, etc.) open since this
  // is not meant to spawn a daemon.
  int base = GlobalDescriptors::kBaseDescriptor;
  for (int fd = base; fd < sysconf(_SC_OPEN_MAX); ++fd) {
    if (fds_to_keep_open.find(fd) == fds_to_keep_open.end()) {
      close(fd);
    }
  }
  for (FileHandleMappingVector::const_iterator it = fds_to_remap->begin();
       it != fds_to_remap->end(); ++it) {
    int old_fd = it->first;
    int new_fd = it->second;
    if (dup2(old_fd, new_fd) < 0) {
      PLOG(FATAL) << "dup2";
    }
    close(old_fd);
  }
  CommandLine::Reset();
  CommandLine::Init(0, nullptr);
  CommandLine* command_line = CommandLine::ForCurrentProcess();
  command_line->InitFromArgv(base_command_line.argv());
  if (!command_line->HasSwitch(switches::kTestChildProcess))
    command_line->AppendSwitchASCII(switches::kTestChildProcess, procname);

  _exit(multi_process_function_list::InvokeChildProcessTest(procname));
  return Process();
}

}  // namespace base
