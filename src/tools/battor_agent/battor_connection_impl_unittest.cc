// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tools/battor_agent/battor_connection_impl.h"

#include "base/bind.h"
#include "base/bind_helpers.h"
#include "base/memory/ptr_util.h"
#include "base/memory/weak_ptr.h"
#include "base/test/test_simple_task_runner.h"
#include "base/threading/thread_task_runner_handle.h"
#include "device/serial/serial.mojom.h"
#include "device/serial/test_serial_io_handler.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "tools/battor_agent/battor_protocol_types.h"

namespace {

void NullWriteCallback(int, device::serial::SendError) {}
void NullReadCallback(int, device::serial::ReceiveError) {}

}  // namespace

namespace battor {

// TestableBattOrConnection uses a fake serial connection be testable.
class TestableBattOrConnection : public BattOrConnectionImpl {
 public:
  TestableBattOrConnection(BattOrConnection::Listener* listener)
      : BattOrConnectionImpl("/dev/test", listener, nullptr, nullptr) {}
  scoped_refptr<device::SerialIoHandler> CreateIoHandler() override {
    return device::TestSerialIoHandler::Create();
  }

  scoped_refptr<device::SerialIoHandler> GetIoHandler() { return io_handler_; }
};

// BattOrConnectionImplTest provides a BattOrConnection and captures the
// results of all its commands.
class BattOrConnectionImplTest : public testing::Test,
                                 public BattOrConnection::Listener {
 public:
  BattOrConnectionImplTest()
      : task_runner_(new base::TestSimpleTaskRunner()),
        thread_task_runner_handle_(task_runner_) {}

  void OnConnectionOpened(bool success) override { open_success_ = success; };
  void OnBytesSent(bool success) override { send_success_ = success; }
  void OnMessageRead(bool success,
                     BattOrMessageType type,
                     std::unique_ptr<std::vector<char>> bytes) override {
    is_read_complete_ = true;
    read_success_ = success;
    read_type_ = type;
    read_bytes_ = std::move(bytes);
  }

 protected:
  void SetUp() override {
    connection_.reset(new TestableBattOrConnection(this));
    task_runner_->ClearPendingTasks();
  }

  void OpenConnection() {
    connection_->Open();
    task_runner_->RunUntilIdle();
  }

  void ReadMessage(BattOrMessageType type) {
    is_read_complete_ = false;
    connection_->ReadMessage(type);
    task_runner_->RunUntilIdle();
  }

  // Reads the specified number of bytes directly from the serial connection.
  scoped_refptr<net::IOBuffer> ReadMessageRaw(int bytes_to_read) {
    scoped_refptr<net::IOBuffer> buffer(
        new net::IOBuffer((size_t)bytes_to_read));

    connection_->GetIoHandler()->Read(base::MakeUnique<device::ReceiveBuffer>(
        buffer, bytes_to_read, base::Bind(&NullReadCallback)));
    task_runner_->RunUntilIdle();

    return buffer;
  }

  void SendControlMessage(BattOrControlMessageType type,
                          uint16_t param1,
                          uint16_t param2) {
    BattOrControlMessage msg{type, param1, param2};
    connection_->SendBytes(BATTOR_MESSAGE_TYPE_CONTROL,
                           reinterpret_cast<char*>(&msg), sizeof(msg));
    task_runner_->RunUntilIdle();
  }

  // Writes the specified bytes directly to the serial connection.
  void SendBytesRaw(const char* data, uint16_t bytes_to_send) {
    std::vector<char> data_vector(data, data + bytes_to_send);
    connection_->GetIoHandler()->Write(base::MakeUnique<device::SendBuffer>(
        data_vector, base::Bind(&NullWriteCallback)));
    task_runner_->RunUntilIdle();
  }

  bool GetOpenSuccess() { return open_success_; }
  bool GetSendSuccess() { return send_success_; }
  bool IsReadComplete() { return is_read_complete_; }
  bool GetReadSuccess() { return read_success_; }
  BattOrMessageType GetReadType() { return read_type_; }
  std::vector<char>* GetReadMessage() { return read_bytes_.get(); }

 private:
  std::unique_ptr<TestableBattOrConnection> connection_;

  scoped_refptr<base::TestSimpleTaskRunner> task_runner_;
  base::ThreadTaskRunnerHandle thread_task_runner_handle_;

  // Result from the last connect command.
  bool open_success_;
  // Result from the last send command.
  bool send_success_;
  // Results from the last read command.
  bool is_read_complete_;
  bool read_success_;
  BattOrMessageType read_type_;
  std::unique_ptr<std::vector<char>> read_bytes_;
};

TEST_F(BattOrConnectionImplTest, InitSendsCorrectBytes) {
  OpenConnection();
  ASSERT_TRUE(GetOpenSuccess());

  SendControlMessage(BATTOR_CONTROL_MESSAGE_TYPE_INIT, 0, 0);

  const char expected_data[] = {
      BATTOR_CONTROL_BYTE_START,  BATTOR_MESSAGE_TYPE_CONTROL,
      BATTOR_CONTROL_BYTE_ESCAPE, BATTOR_CONTROL_MESSAGE_TYPE_INIT,
      BATTOR_CONTROL_BYTE_ESCAPE, 0x00,
      BATTOR_CONTROL_BYTE_ESCAPE, 0x00,
      BATTOR_CONTROL_BYTE_ESCAPE, 0x00,
      BATTOR_CONTROL_BYTE_ESCAPE, 0x00,
      BATTOR_CONTROL_BYTE_END,
  };

  ASSERT_TRUE(GetSendSuccess());
  ASSERT_EQ(0, std::memcmp(ReadMessageRaw(13)->data(), expected_data, 13));
}

TEST_F(BattOrConnectionImplTest, ResetSendsCorrectBytes) {
  OpenConnection();
  ASSERT_TRUE(GetOpenSuccess());

  SendControlMessage(BATTOR_CONTROL_MESSAGE_TYPE_RESET, 0, 0);

  const char expected_data[] = {
      BATTOR_CONTROL_BYTE_START,  BATTOR_MESSAGE_TYPE_CONTROL,
      BATTOR_CONTROL_BYTE_ESCAPE, BATTOR_CONTROL_MESSAGE_TYPE_RESET,
      BATTOR_CONTROL_BYTE_ESCAPE, 0x00,
      BATTOR_CONTROL_BYTE_ESCAPE, 0x00,
      BATTOR_CONTROL_BYTE_ESCAPE, 0x00,
      BATTOR_CONTROL_BYTE_ESCAPE, 0x00,
      BATTOR_CONTROL_BYTE_END,
  };

  ASSERT_TRUE(GetSendSuccess());
  ASSERT_EQ(0, std::memcmp(ReadMessageRaw(13)->data(), expected_data, 13));
}

TEST_F(BattOrConnectionImplTest, ReadMessageControlMessage) {
  OpenConnection();
  ASSERT_TRUE(GetOpenSuccess());

  const char data[] = {
      BATTOR_CONTROL_BYTE_START,
      BATTOR_MESSAGE_TYPE_CONTROL,
      BATTOR_CONTROL_BYTE_ESCAPE,
      BATTOR_CONTROL_MESSAGE_TYPE_RESET,
      0x04,
      0x04,
      0x04,
      0x04,
      BATTOR_CONTROL_BYTE_END,
  };
  SendBytesRaw(data, 9);
  ReadMessage(BATTOR_MESSAGE_TYPE_CONTROL);

  const char expected[] = {BATTOR_CONTROL_MESSAGE_TYPE_RESET, 0x04, 0x04, 0x04,
                           0x04};

  ASSERT_TRUE(IsReadComplete());
  ASSERT_TRUE(GetReadSuccess());
  ASSERT_EQ(BATTOR_MESSAGE_TYPE_CONTROL, GetReadType());
  ASSERT_EQ(0, std::memcmp(GetReadMessage()->data(), expected, 5));
}

TEST_F(BattOrConnectionImplTest, ReadMessageInvalidType) {
  OpenConnection();
  ASSERT_TRUE(GetOpenSuccess());

  const char data[] = {
      BATTOR_CONTROL_BYTE_START,
      static_cast<char>(UINT8_MAX),
      BATTOR_CONTROL_BYTE_ESCAPE,
      BATTOR_CONTROL_MESSAGE_TYPE_RESET,
      0x04,
      0x04,
      0x04,
      0x04,
      BATTOR_CONTROL_BYTE_END,
  };
  SendBytesRaw(data, 7);
  ReadMessage(BATTOR_MESSAGE_TYPE_CONTROL);

  ASSERT_TRUE(IsReadComplete());
  ASSERT_FALSE(GetReadSuccess());
}

TEST_F(BattOrConnectionImplTest, ReadMessageEndsMidMessageByte) {
  OpenConnection();
  ASSERT_TRUE(GetOpenSuccess());

  const char data[] = {
      BATTOR_CONTROL_BYTE_START,
      BATTOR_MESSAGE_TYPE_CONTROL,
      BATTOR_CONTROL_BYTE_ESCAPE,
      BATTOR_CONTROL_MESSAGE_TYPE_RESET,
      0x04,
  };
  SendBytesRaw(data, 5);
  ReadMessage(BATTOR_MESSAGE_TYPE_CONTROL);

  // The first read should recognize that a second read is necessary, but the
  // second read will hang because no bytes ever come in.
  ASSERT_FALSE(IsReadComplete());
}

TEST_F(BattOrConnectionImplTest, ReadMessageMissingEndByte) {
  OpenConnection();
  ASSERT_TRUE(GetOpenSuccess());

  const char data[] = {
      BATTOR_CONTROL_BYTE_START,
      BATTOR_MESSAGE_TYPE_CONTROL,
      BATTOR_CONTROL_BYTE_ESCAPE,
      BATTOR_CONTROL_MESSAGE_TYPE_RESET,
      0x04,
      0x04,
      0x04,
      0x04,
  };
  SendBytesRaw(data, 6);
  ReadMessage(BATTOR_MESSAGE_TYPE_CONTROL);

  // The first read should recognize that a second read is necessary, but the
  // second read will hang because no bytes ever come in.
  ASSERT_FALSE(IsReadComplete());
}

TEST_F(BattOrConnectionImplTest, ReadMessageWithEscapeCharacters) {
  OpenConnection();
  ASSERT_TRUE(GetOpenSuccess());

  const char data[] = {
      BATTOR_CONTROL_BYTE_START,
      BATTOR_MESSAGE_TYPE_CONTROL,
      BATTOR_CONTROL_BYTE_ESCAPE,
      BATTOR_CONTROL_MESSAGE_TYPE_RESET,
      BATTOR_CONTROL_BYTE_ESCAPE,
      0x00,
      0x04,
      0x04,
      0x04,
      BATTOR_CONTROL_BYTE_END,
  };
  SendBytesRaw(data, 10);
  ReadMessage(BATTOR_MESSAGE_TYPE_CONTROL);

  const char expected[] = {BATTOR_CONTROL_MESSAGE_TYPE_RESET, 0x00};

  ASSERT_TRUE(IsReadComplete());
  ASSERT_TRUE(GetReadSuccess());
  ASSERT_EQ(BATTOR_MESSAGE_TYPE_CONTROL, GetReadType());
  ASSERT_EQ(0, std::memcmp(GetReadMessage()->data(), expected, 2));
}

TEST_F(BattOrConnectionImplTest, ReadControlMessage) {
  OpenConnection();
  ASSERT_TRUE(GetOpenSuccess());

  SendControlMessage(BATTOR_CONTROL_MESSAGE_TYPE_RESET, 4, 7);
  ReadMessage(BATTOR_MESSAGE_TYPE_CONTROL);

  ASSERT_TRUE(IsReadComplete());
  ASSERT_TRUE(GetReadSuccess());
  ASSERT_EQ(BATTOR_MESSAGE_TYPE_CONTROL, GetReadType());

  BattOrControlMessage* msg =
      reinterpret_cast<BattOrControlMessage*>(GetReadMessage()->data());

  ASSERT_EQ(BATTOR_CONTROL_MESSAGE_TYPE_RESET, msg->type);
  ASSERT_EQ(4, msg->param1);
  ASSERT_EQ(7, msg->param2);
}

TEST_F(BattOrConnectionImplTest, ReadMessageExtraBytesStoredBetweenReads) {
  OpenConnection();
  ASSERT_TRUE(GetOpenSuccess());

  // Send a samples frame with length and sequence number of zero.
  const char data[] = {
      BATTOR_CONTROL_BYTE_START,
      BATTOR_MESSAGE_TYPE_SAMPLES,
      0x02,
      0x00,
      0x02,
      0x00,
      0x02,
      0x00,
      BATTOR_CONTROL_BYTE_END,
  };
  SendBytesRaw(data, 9);
  SendControlMessage(BATTOR_CONTROL_MESSAGE_TYPE_INIT, 5, 8);

  // When reading sample frames, we're forced to read lots because each frame
  // could be up to 50kB long. By reading a really short sample frame (like the
  // zero-length one above), the BattOrConnection is forced to store whatever
  // extra data it finds in the serial stream - in this case, the init control
  // message that we sent.
  ReadMessage(BATTOR_MESSAGE_TYPE_SAMPLES);

  ASSERT_TRUE(IsReadComplete());
  ASSERT_TRUE(GetReadSuccess());
  ASSERT_EQ(BATTOR_MESSAGE_TYPE_SAMPLES, GetReadType());

  ReadMessage(BATTOR_MESSAGE_TYPE_CONTROL);

  ASSERT_TRUE(IsReadComplete());
  ASSERT_TRUE(GetReadSuccess());
  ASSERT_EQ(BATTOR_MESSAGE_TYPE_CONTROL, GetReadType());

  BattOrControlMessage* init_msg =
      reinterpret_cast<BattOrControlMessage*>(GetReadMessage()->data());

  ASSERT_EQ(BATTOR_CONTROL_MESSAGE_TYPE_INIT, init_msg->type);
  ASSERT_EQ(5, init_msg->param1);
  ASSERT_EQ(8, init_msg->param2);
}

TEST_F(BattOrConnectionImplTest, ReadMessageFailsWithControlButExpectingAck) {
  OpenConnection();
  ASSERT_TRUE(GetOpenSuccess());

  const char data[] = {
      BATTOR_CONTROL_BYTE_START,
      BATTOR_MESSAGE_TYPE_CONTROL_ACK,
      BATTOR_CONTROL_BYTE_ESCAPE,
      BATTOR_CONTROL_MESSAGE_TYPE_RESET,
      0x04,
      BATTOR_CONTROL_BYTE_END,
  };
  SendBytesRaw(data, 6);
  ReadMessage(BATTOR_MESSAGE_TYPE_CONTROL);

  ASSERT_TRUE(IsReadComplete());
  ASSERT_FALSE(GetReadSuccess());
}

TEST_F(BattOrConnectionImplTest, ReadMessageFailsWithAckButExpectingControl) {
  OpenConnection();
  ASSERT_TRUE(GetOpenSuccess());

  const char data[] = {
      BATTOR_CONTROL_BYTE_START,         BATTOR_MESSAGE_TYPE_CONTROL_ACK,
      BATTOR_CONTROL_MESSAGE_TYPE_RESET, 0x04,
      BATTOR_CONTROL_BYTE_END,
  };
  SendBytesRaw(data, 5);
  ReadMessage(BATTOR_MESSAGE_TYPE_CONTROL);

  ASSERT_TRUE(IsReadComplete());
  ASSERT_FALSE(GetReadSuccess());
}

TEST_F(BattOrConnectionImplTest, ReadMessageControlTypePrintFails) {
  OpenConnection();
  ASSERT_TRUE(GetOpenSuccess());

  const char data[] = {
      BATTOR_CONTROL_BYTE_START, BATTOR_MESSAGE_TYPE_PRINT,
      BATTOR_CONTROL_BYTE_END,
  };
  SendBytesRaw(data, 3);
  ReadMessage(BATTOR_MESSAGE_TYPE_PRINT);

  ASSERT_TRUE(IsReadComplete());
  ASSERT_FALSE(GetReadSuccess());
}

}  // namespace battor
