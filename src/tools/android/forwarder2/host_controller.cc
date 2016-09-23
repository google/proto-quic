// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/android/forwarder2/host_controller.h"

#include <memory>
#include <string>
#include <utility>

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/logging.h"
#include "base/threading/thread_task_runner_handle.h"
#include "tools/android/forwarder2/command.h"
#include "tools/android/forwarder2/forwarder.h"
#include "tools/android/forwarder2/socket.h"

namespace forwarder2 {

// static
std::unique_ptr<HostController> HostController::Create(
    int device_port,
    int host_port,
    int adb_port,
    int exit_notifier_fd,
    const ErrorCallback& error_callback) {
  std::unique_ptr<HostController> host_controller;
  std::unique_ptr<PipeNotifier> delete_controller_notifier(new PipeNotifier());
  std::unique_ptr<Socket> adb_control_socket(new Socket());
  adb_control_socket->AddEventFd(exit_notifier_fd);
  adb_control_socket->AddEventFd(delete_controller_notifier->receiver_fd());
  if (!adb_control_socket->ConnectTcp(std::string(), adb_port)) {
    LOG(ERROR) << "Could not connect HostController socket on port: "
               << adb_port;
    return host_controller;
  }
  // Send the command to the device start listening to the "device_forward_port"
  bool send_command_success = SendCommand(
      command::LISTEN, device_port, adb_control_socket.get());
  CHECK(send_command_success);
  int device_port_allocated;
  command::Type command;
  if (!ReadCommand(
          adb_control_socket.get(), &device_port_allocated, &command) ||
      command != command::BIND_SUCCESS) {
    LOG(ERROR) << "Device binding error using port " << device_port;
    return host_controller;
  }
  host_controller.reset(new HostController(
      device_port_allocated, host_port, adb_port, error_callback,
      std::move(adb_control_socket), std::move(delete_controller_notifier)));
  return host_controller;
}

HostController::~HostController() {
  DCHECK(deletion_task_runner_->RunsTasksOnCurrentThread());
  delete_controller_notifier_->Notify();
}

void HostController::Start() {
  thread_.Start();
  ReadNextCommandSoon();
}

HostController::HostController(
    int device_port,
    int host_port,
    int adb_port,
    const ErrorCallback& error_callback,
    std::unique_ptr<Socket> adb_control_socket,
    std::unique_ptr<PipeNotifier> delete_controller_notifier)
    : self_deleter_helper_(this, error_callback),
      device_port_(device_port),
      host_port_(host_port),
      adb_port_(adb_port),
      adb_control_socket_(std::move(adb_control_socket)),
      delete_controller_notifier_(std::move(delete_controller_notifier)),
      deletion_task_runner_(base::ThreadTaskRunnerHandle::Get()),
      thread_("HostControllerThread") {}

void HostController::ReadNextCommandSoon() {
  thread_.task_runner()->PostTask(
      FROM_HERE,
      base::Bind(&HostController::ReadCommandOnInternalThread,
                 base::Unretained(this)));
}

void HostController::ReadCommandOnInternalThread() {
  if (!ReceivedCommand(command::ACCEPT_SUCCESS, adb_control_socket_.get())) {
    LOG(ERROR) << "Did not receive ACCEPT_SUCCESS for port: "
               << host_port_;
    OnInternalThreadError();
    return;
  }
  // Try to connect to host server.
  std::unique_ptr<Socket> host_server_data_socket(new Socket());
  if (!host_server_data_socket->ConnectTcp(std::string(), host_port_)) {
    LOG(ERROR) << "Could not Connect HostServerData socket on port: "
               << host_port_;
    SendCommand(
        command::HOST_SERVER_ERROR, device_port_, adb_control_socket_.get());
    if (ReceivedCommand(command::ACK, adb_control_socket_.get())) {
      // It can continue if the host forwarder could not connect to the host
      // server but the device acknowledged that, so that the device could
      // re-try later.
      ReadNextCommandSoon();
      return;
    }
    OnInternalThreadError();
    return;
  }
  LOG(INFO) << "Will send HOST_SERVER_SUCCESS: " << host_port_;
  SendCommand(
      command::HOST_SERVER_SUCCESS, device_port_, adb_control_socket_.get());
  StartForwarder(std::move(host_server_data_socket));
  ReadNextCommandSoon();
}

void HostController::StartForwarder(
    std::unique_ptr<Socket> host_server_data_socket) {
  std::unique_ptr<Socket> adb_data_socket(new Socket());
  if (!adb_data_socket->ConnectTcp("", adb_port_)) {
    LOG(ERROR) << "Could not connect AdbDataSocket on port: " << adb_port_;
    OnInternalThreadError();
    return;
  }
  // Open the Adb data connection, and send a command with the
  // |device_forward_port| as a way for the device to identify the connection.
  SendCommand(command::DATA_CONNECTION, device_port_, adb_data_socket.get());

  // Check that the device received the new Adb Data Connection. Note that this
  // check is done through the |adb_control_socket_| that is handled in the
  // DeviceListener thread just after the call to WaitForAdbDataSocket().
  if (!ReceivedCommand(command::ADB_DATA_SOCKET_SUCCESS,
                       adb_control_socket_.get())) {
    LOG(ERROR) << "Device could not handle the new Adb Data Connection.";
    OnInternalThreadError();
    return;
  }
  forwarders_manager_.CreateAndStartNewForwarder(
      std::move(host_server_data_socket), std::move(adb_data_socket));
}

void HostController::OnInternalThreadError() {
  UnmapPortOnDevice();
  self_deleter_helper_.MaybeSelfDeleteSoon();
}

void HostController::UnmapPortOnDevice() {
  Socket socket;
  if (!socket.ConnectTcp("", adb_port_)) {
    LOG(ERROR) << "Could not connect to device on port " << adb_port_;
    return;
  }
  if (!SendCommand(command::UNLISTEN, device_port_, &socket)) {
    LOG(ERROR) << "Could not send unmap command for port " << device_port_;
    return;
  }
  if (!ReceivedCommand(command::UNLISTEN_SUCCESS, &socket)) {
    LOG(ERROR) << "Unamp command failed for port " << device_port_;
    return;
  }
}

}  // namespace forwarder2
