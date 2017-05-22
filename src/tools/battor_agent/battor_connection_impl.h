// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TOOLS_BATTOR_AGENT_BATTOR_CONNECTION_IMPL_H_
#define TOOLS_BATTOR_AGENT_BATTOR_CONNECTION_IMPL_H_

#include <fstream>
#include <vector>

#include "base/callback_forward.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/single_thread_task_runner.h"
#include "device/serial/serial.mojom.h"
#include "tools/battor_agent/battor_connection.h"
#include "tools/battor_agent/battor_error.h"
#include "tools/battor_agent/battor_protocol_types.h"

namespace device {
class SerialIoHandler;
}
namespace net {
class IOBuffer;
}

namespace battor {

// A BattOrConnectionImpl is a concrete implementation of a BattOrConnection.
class BattOrConnectionImpl
    : public BattOrConnection,
      public base::SupportsWeakPtr<BattOrConnectionImpl> {
 public:
  BattOrConnectionImpl(
      const std::string& path,
      BattOrConnection::Listener* listener,
      scoped_refptr<base::SingleThreadTaskRunner> file_thread_task_runner,
      scoped_refptr<base::SingleThreadTaskRunner> ui_thread_task_runner);
  ~BattOrConnectionImpl() override;

  void Open() override;
  void Close() override;
  void SendBytes(BattOrMessageType type,
                 const void* buffer,
                 size_t bytes_to_send) override;
  void ReadMessage(BattOrMessageType type) override;
  void CancelReadMessage() override;
  void Flush() override;

 protected:
  // Overridden by the test to use a fake serial connection.
  virtual scoped_refptr<device::SerialIoHandler> CreateIoHandler();

  // IO handler capable of reading and writing from the serial connection.
  scoped_refptr<device::SerialIoHandler> io_handler_;

 private:
  void OnOpened(bool success);

  // Reads the specified number of additional bytes and adds them to the pending
  // read buffer.
  void BeginReadBytes(size_t bytes_to_read);

  // Internal callback for when bytes are read. This method may trigger
  // additional reads if any newly read bytes are escape bytes.
  void OnBytesRead(int bytes_read, device::serial::ReceiveError error);

  void EndReadBytes(bool success,
                    BattOrMessageType type,
                    std::unique_ptr<std::vector<char>> data);

  // Pulls off the next complete message from already_read_buffer_, returning
  // its type and contents through out parameters and any error that occurred
  // through the return value.
  enum ParseMessageError {
    NONE = 0,
    NOT_ENOUGH_BYTES = 1,
    MISSING_START_BYTE = 2,
    INVALID_MESSAGE_TYPE = 3,
    TOO_MANY_START_BYTES = 4
  };

  ParseMessageError ParseMessage(BattOrMessageType* type,
                                 std::vector<char>* data);

  // Internal callback for when bytes are sent.
  void OnBytesSent(int bytes_sent, device::serial::SendError error);

  // Appends |str| to the serial log file if it exists.
  void LogSerial(const std::string& str);

  // The path of the BattOr.
  std::string path_;

  // All bytes that have already been read from the serial stream, but have not
  // yet been given to the listener as a complete message.
  std::vector<char> already_read_buffer_;
  // The bytes that were read in the pending read.
  scoped_refptr<net::IOBuffer> pending_read_buffer_;
  // The type of message we're looking for in the pending read.
  BattOrMessageType pending_read_message_type_;

  // The total number of bytes that we're expecting to send.
  size_t pending_write_length_;

  // Threads needed for serial communication.
  scoped_refptr<base::SingleThreadTaskRunner> file_thread_task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> ui_thread_task_runner_;

  std::fstream serial_log_;

  DISALLOW_COPY_AND_ASSIGN(BattOrConnectionImpl);
};

}  // namespace battor

#endif  // TOOLS_BATTOR_AGENT_BATTOR_CONNECTION_IMPL_H_
