// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/battor_agent/battor_connection_impl.h"

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/command_line.h"
#include "base/memory/ptr_util.h"
#include "base/strings/stringprintf.h"
#include "base/threading/thread_task_runner_handle.h"
#include "device/serial/buffer.h"
#include "device/serial/serial_io_handler.h"
#include "net/base/io_buffer.h"
#include "tools/battor_agent/serial_utils.h"

using base::StringPrintf;
using std::vector;

namespace battor {

namespace {

// The command line switch used to specify a file to which serial communication
// is logged.
const char kSerialLogPathSwitch[] = "battor-serial-log";

// Serial configuration parameters for the BattOr.
const uint32_t kBattOrBitrate = 2000000;
const device::serial::DataBits kBattOrDataBits =
    device::serial::DataBits::EIGHT;
const device::serial::ParityBit kBattOrParityBit =
    device::serial::ParityBit::NONE;
const device::serial::StopBits kBattOrStopBit = device::serial::StopBits::ONE;
const bool kBattOrCtsFlowControl = true;
const bool kBattOrHasCtsFlowControl = true;
// The maximum BattOr message is 50kB long.
const size_t kMaxMessageSizeBytes = 50000;

// Returns the maximum number of bytes that could be required to read a message
// of the specified type.
size_t GetMaxBytesForMessageType(BattOrMessageType type) {
  switch (type) {
    case BATTOR_MESSAGE_TYPE_CONTROL:
      return 2 * sizeof(BattOrControlMessage) + 3;
    case BATTOR_MESSAGE_TYPE_CONTROL_ACK:
      // The BattOr EEPROM is sent back with this type, even though it's
      // technically more of a response than an ack. We have to make sure that
      // we read enough bytes to accommodate this behavior.
      return 2 * sizeof(BattOrEEPROM) + 3;
    case BATTOR_MESSAGE_TYPE_SAMPLES:
      return 2 * kMaxMessageSizeBytes + 3;
    default:
      return 0;
  }
}

}  // namespace

BattOrConnectionImpl::BattOrConnectionImpl(
    const std::string& path,
    BattOrConnection::Listener* listener,
    scoped_refptr<base::SingleThreadTaskRunner> file_thread_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> ui_thread_task_runner)
    : BattOrConnection(listener),
      path_(path),
      file_thread_task_runner_(file_thread_task_runner),
      ui_thread_task_runner_(ui_thread_task_runner) {
  std::string serial_log_path =
      base::CommandLine::ForCurrentProcess()->GetSwitchValueASCII(
          kSerialLogPathSwitch);
  if (!serial_log_path.empty()) {
    serial_log_.open(serial_log_path.c_str(),
                     std::fstream::out | std::fstream::trunc);
  }
}

BattOrConnectionImpl::~BattOrConnectionImpl() {}

void BattOrConnectionImpl::Open() {
  if (io_handler_) {
    // Opening new connection so flush serial data from old connection.
    Flush();
    OnOpened(true);
    return;
  }

  io_handler_ = CreateIoHandler();

  device::serial::ConnectionOptions options;
  options.bitrate = kBattOrBitrate;
  options.data_bits = kBattOrDataBits;
  options.parity_bit = kBattOrParityBit;
  options.stop_bits = kBattOrStopBit;
  options.cts_flow_control = kBattOrCtsFlowControl;
  options.has_cts_flow_control = kBattOrHasCtsFlowControl;

  LogSerial("Opening serial connection.");
  io_handler_->Open(path_, options,
                    base::Bind(&BattOrConnectionImpl::OnOpened, AsWeakPtr()));
}

void BattOrConnectionImpl::OnOpened(bool success) {
  LogSerial(StringPrintf("Serial connection open finished with success: %d.",
                         success));

  if (!success)
    Close();

  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE, base::Bind(&Listener::OnConnectionOpened,
                            base::Unretained(listener_), success));
}

void BattOrConnectionImpl::Close() {
  LogSerial("Serial connection closed.");
  io_handler_ = nullptr;
}

void BattOrConnectionImpl::SendBytes(BattOrMessageType type,
                                     const void* buffer,
                                     size_t bytes_to_send) {
  const char* bytes = reinterpret_cast<const char*>(buffer);

  // Reserve a send buffer with enough extra bytes for the start, type, end, and
  // escape bytes.
  vector<char> data;
  data.reserve(2 * bytes_to_send + 3);

  data.push_back(BATTOR_CONTROL_BYTE_START);
  data.push_back(type);

  for (size_t i = 0; i < bytes_to_send; i++) {
    if (bytes[i] == BATTOR_CONTROL_BYTE_START ||
        bytes[i] == BATTOR_CONTROL_BYTE_END) {
      data.push_back(BATTOR_CONTROL_BYTE_ESCAPE);
    }

    data.push_back(bytes[i]);
  }

  data.push_back(BATTOR_CONTROL_BYTE_END);

  LogSerial(StringPrintf("Bytes sent: %s.", CharVectorToString(data).c_str()));

  pending_write_length_ = data.size();
  io_handler_->Write(base::MakeUnique<device::SendBuffer>(
      data, base::Bind(&BattOrConnectionImpl::OnBytesSent, AsWeakPtr())));
}

void BattOrConnectionImpl::ReadMessage(BattOrMessageType type) {
  LogSerial("Read requested.");

  pending_read_message_type_ = type;
  size_t message_max_bytes = GetMaxBytesForMessageType(type);

  LogSerial(
      "Before doing a serial read, checking to see if we already have a "
      "complete message in the 'already read' buffer.");

  BattOrMessageType parsed_type;
  std::unique_ptr<vector<char>> bytes(new vector<char>());
  bytes->reserve(message_max_bytes);
  ParseMessageError parse_message_error =
      ParseMessage(&parsed_type, bytes.get());
  if (parse_message_error == ParseMessageError::NONE) {
    LogSerial("Complete message found.");
    EndReadBytes(true, parsed_type, std::move(bytes));
    return;
  }

  if (parse_message_error != ParseMessageError::NOT_ENOUGH_BYTES) {
    LogSerial(StringPrintf(
        "Read failed because, before performing a serial read, the message in "
        "the 'already read' buffer had an irrecoverable error with code: %d.",
        parse_message_error));
    EndReadBytes(false, BATTOR_MESSAGE_TYPE_CONTROL, nullptr);
    return;
  }

  LogSerial("No complete message found in the 'already read' buffer.");
  BeginReadBytes(message_max_bytes - already_read_buffer_.size());
}

void BattOrConnectionImpl::CancelReadMessage() {
  io_handler_->CancelRead(device::serial::ReceiveError::TIMEOUT);
}

void BattOrConnectionImpl::Flush() {
  io_handler_->Flush();
  already_read_buffer_.clear();
}

scoped_refptr<device::SerialIoHandler> BattOrConnectionImpl::CreateIoHandler() {
  return device::SerialIoHandler::Create(file_thread_task_runner_,
                                         ui_thread_task_runner_);
}

void BattOrConnectionImpl::BeginReadBytes(size_t max_bytes_to_read) {
  LogSerial(
      StringPrintf("Starting read of up to %zu bytes.", max_bytes_to_read));

  pending_read_buffer_ =
      make_scoped_refptr(new net::IOBuffer(max_bytes_to_read));

  auto on_receive_buffer_filled =
      base::Bind(&BattOrConnectionImpl::OnBytesRead, AsWeakPtr());

  io_handler_->Read(base::MakeUnique<device::ReceiveBuffer>(
      pending_read_buffer_, static_cast<uint32_t>(max_bytes_to_read),
      on_receive_buffer_filled));
}

void BattOrConnectionImpl::OnBytesRead(int bytes_read,
                                       device::serial::ReceiveError error) {
  if (error != device::serial::ReceiveError::NONE) {
    LogSerial(StringPrintf(
        "Read failed due to serial read failure with error code: %d.",
        static_cast<int>(error)));
    EndReadBytes(false, BATTOR_MESSAGE_TYPE_CONTROL, nullptr);
    return;
  }

  if (bytes_read == 0) {
    // If we didn't have a message before, and we weren't able to read any
    // additional bytes, then there's no valid message available.
    LogSerial("Read failed due to no bytes being read.");
    EndReadBytes(false, BATTOR_MESSAGE_TYPE_CONTROL, nullptr);
    return;
  }

  if (pending_read_message_type_ == BATTOR_MESSAGE_TYPE_SAMPLES) {
    // If we're reading samples, don't log every byte that we receive. This
    // exacerbates a problem on Mac wherein we can't process sample frames
    // quickly enough to prevent the serial buffer from overflowing, causing us
    // to drop frames.
    LogSerial(StringPrintf("%d more bytes read.", bytes_read));
  } else {
    LogSerial(StringPrintf(
        "%d more bytes read: %s.", bytes_read,
        CharArrayToString(pending_read_buffer_->data(), bytes_read).c_str()));
  }

  already_read_buffer_.insert(already_read_buffer_.end(),
                              pending_read_buffer_->data(),
                              pending_read_buffer_->data() + bytes_read);

  BattOrMessageType type;
  size_t message_max_bytes =
      GetMaxBytesForMessageType(pending_read_message_type_);
  std::unique_ptr<vector<char>> bytes(new vector<char>());
  bytes->reserve(message_max_bytes);

  ParseMessageError parse_message_error = ParseMessage(&type, bytes.get());
  if (parse_message_error == ParseMessageError::NOT_ENOUGH_BYTES) {
    if (already_read_buffer_.size() >= message_max_bytes) {
      LogSerial(
          "Read failed due to no complete message after max read length.");
      EndReadBytes(false, BATTOR_MESSAGE_TYPE_CONTROL, nullptr);
      return;
    }

    LogSerial("(Message still incomplete: reading more bytes.)");
    BeginReadBytes(message_max_bytes - already_read_buffer_.size());
    return;
  }

  if (parse_message_error != ParseMessageError::NONE) {
    LogSerial(StringPrintf(
        "Read failed due to the message containing an irrecoverable error: %d.",
        parse_message_error));
    EndReadBytes(false, BATTOR_MESSAGE_TYPE_CONTROL, nullptr);
    return;
  }

  if (type != pending_read_message_type_) {
    LogSerial("Read failed due to receiving a message of the wrong type.");
    EndReadBytes(false, BATTOR_MESSAGE_TYPE_CONTROL, nullptr);
    return;
  }

  EndReadBytes(true, type, std::move(bytes));
}

void BattOrConnectionImpl::EndReadBytes(bool success,
                                        BattOrMessageType type,
                                        std::unique_ptr<vector<char>> bytes) {
  LogSerial(StringPrintf("Read finished with success: %d.", success));

  pending_read_buffer_ = nullptr;
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::Bind(&Listener::OnMessageRead, base::Unretained(listener_), success,
                 type, base::Passed(std::move(bytes))));
}

BattOrConnectionImpl::ParseMessageError BattOrConnectionImpl::ParseMessage(
    BattOrMessageType* type,
    vector<char>* bytes) {
  if (already_read_buffer_.size() <= 3)
    return ParseMessageError::NOT_ENOUGH_BYTES;

  // The first byte is the start byte.
  if (already_read_buffer_[0] != BATTOR_CONTROL_BYTE_START)
    return ParseMessageError::MISSING_START_BYTE;

  // The second byte specifies the message type.
  *type = static_cast<BattOrMessageType>(already_read_buffer_[1]);

  if (*type < static_cast<uint8_t>(BATTOR_MESSAGE_TYPE_CONTROL) ||
      *type > static_cast<uint8_t>(BATTOR_MESSAGE_TYPE_PRINT))
    return ParseMessageError::INVALID_MESSAGE_TYPE;

  // After that comes the message bytes.
  bool escape_next_byte = false;
  for (size_t i = 2; i < already_read_buffer_.size(); i++) {
    char next_byte = already_read_buffer_[i];

    if (escape_next_byte) {
      bytes->push_back(next_byte);
      escape_next_byte = false;
      continue;
    }

    switch (next_byte) {
      case BATTOR_CONTROL_BYTE_START:
        // Two start bytes in a message is invalid.
        return ParseMessageError::TOO_MANY_START_BYTES;

      case BATTOR_CONTROL_BYTE_END:
        already_read_buffer_.erase(already_read_buffer_.begin(),
                                   already_read_buffer_.begin() + i + 1);
        return ParseMessageError::NONE;

      case BATTOR_CONTROL_BYTE_ESCAPE:
        escape_next_byte = true;
        continue;

      default:
        bytes->push_back(next_byte);
    }
  }

  // If we made it to the end of the read buffer and no end byte was seen, then
  // we don't have a complete message.
  return ParseMessageError::NOT_ENOUGH_BYTES;
}

void BattOrConnectionImpl::OnBytesSent(int bytes_sent,
                                       device::serial::SendError error) {
  bool success = (error == device::serial::SendError::NONE) &&
                 (pending_write_length_ == static_cast<size_t>(bytes_sent));
  base::ThreadTaskRunnerHandle::Get()->PostTask(
      FROM_HERE,
      base::Bind(&Listener::OnBytesSent, base::Unretained(listener_), success));
}

void BattOrConnectionImpl::LogSerial(const std::string& str) {
  serial_log_ << str << std::endl << std::endl;
}

}  // namespace battor
