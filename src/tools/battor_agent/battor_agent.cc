// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "tools/battor_agent/battor_agent.h"

#include <iomanip>

#include "base/bind.h"
#include "base/threading/thread_task_runner_handle.h"
#include "tools/battor_agent/battor_connection_impl.h"
#include "tools/battor_agent/battor_sample_converter.h"

using std::vector;

namespace battor {

namespace {

// The maximum number of times to retry when initializing a BattOr.
const uint8_t kMaxInitAttempts = 20;

// The maximum number of times to retry the StartTracing command.
const uint8_t kMaxStartTracingAttempts = 5;

// The number of milliseconds to wait before retrying initialization.
const uint16_t kInitRetryDelayMilliseconds = 100;

// The maximum number of times to retry when reading a message.
const uint8_t kMaxReadAttempts = 20;

// The number of milliseconds to wait before trying to read a message again.
const uint8_t kReadRetryDelayMilliseconds = 1;

// The amount of time we need to wait after recording a clock sync marker in
// order to ensure that the sample we synced to doesn't get thrown out.
const uint8_t kStopTracingClockSyncDelayMilliseconds = 100;

// The number of seconds allowed for a given action before timing out.
const uint8_t kBattOrTimeoutSeconds = 4;

// Returns true if the specified vector of bytes decodes to a message that is an
// ack for the specified control message type.
bool IsAckOfControlCommand(BattOrMessageType message_type,
                           BattOrControlMessageType control_message_type,
                           const vector<char>& msg) {
  if (message_type != BATTOR_MESSAGE_TYPE_CONTROL_ACK)
    return false;

  if (msg.size() != sizeof(BattOrControlMessageAck))
    return false;

  const BattOrControlMessageAck* ack =
      reinterpret_cast<const BattOrControlMessageAck*>(msg.data());

  if (ack->type != control_message_type)
    return false;

  return true;
}

// Attempts to decode the specified vector of bytes decodes to a valid EEPROM.
// Returns the new EEPROM, or nullptr if unsuccessful.
std::unique_ptr<BattOrEEPROM> ParseEEPROM(BattOrMessageType message_type,
                                          const vector<char>& msg) {
  if (message_type != BATTOR_MESSAGE_TYPE_CONTROL_ACK)
    return nullptr;

  if (msg.size() != sizeof(BattOrEEPROM))
    return nullptr;

  std::unique_ptr<BattOrEEPROM> eeprom(new BattOrEEPROM());
  memcpy(eeprom.get(), msg.data(), sizeof(BattOrEEPROM));
  return eeprom;
}

// Returns true if the specified vector of bytes decodes to a valid BattOr
// samples frame. The frame header and samples are returned via the frame_header
// and samples paramaters.
bool ParseSampleFrame(BattOrMessageType type,
                      const vector<char>& msg,
                      uint32_t expected_sequence_number,
                      BattOrFrameHeader* frame_header,
                      vector<RawBattOrSample>* samples) {
  if (type != BATTOR_MESSAGE_TYPE_SAMPLES)
    return false;

  // Each frame should contain a header and an integer number of BattOr samples.
  if ((msg.size() - sizeof(BattOrFrameHeader)) % sizeof(RawBattOrSample) != 0)
    return false;

  // The first bytes in the frame contain the frame header.
  const char* frame_ptr = reinterpret_cast<const char*>(msg.data());
  memcpy(frame_header, frame_ptr, sizeof(BattOrFrameHeader));
  frame_ptr += sizeof(BattOrFrameHeader);

  if (frame_header->sequence_number != expected_sequence_number) {
    LOG(WARNING) << "Unexpected sequence number: wanted "
                 << expected_sequence_number << ", but got "
                 << frame_header->sequence_number << ".";
    return false;
  }

  size_t remaining_bytes = msg.size() - sizeof(BattOrFrameHeader);
  if (remaining_bytes != frame_header->length)
    return false;

  samples->resize(remaining_bytes / sizeof(RawBattOrSample));
  memcpy(samples->data(), frame_ptr, remaining_bytes);

  return true;
}
}  // namespace

BattOrAgent::BattOrAgent(
    const std::string& path,
    Listener* listener,
    scoped_refptr<base::SingleThreadTaskRunner> file_thread_task_runner,
    scoped_refptr<base::SingleThreadTaskRunner> ui_thread_task_runner)
    : connection_(new BattOrConnectionImpl(path,
                                           this,
                                           file_thread_task_runner,
                                           ui_thread_task_runner)),
      listener_(listener),
      last_action_(Action::INVALID),
      command_(Command::INVALID),
      num_init_attempts_(0),
      num_start_tracing_attempts_(0),
      num_read_attempts_(0) {
  // We don't care what thread the constructor is called on - we only care that
  // all of the other method invocations happen on the same thread.
  thread_checker_.DetachFromThread();
}

BattOrAgent::~BattOrAgent() {
  DCHECK(thread_checker_.CalledOnValidThread());
}

void BattOrAgent::StartTracing() {
  DCHECK(thread_checker_.CalledOnValidThread());

  // When tracing is restarted, all previous clock sync markers are invalid.
  clock_sync_markers_.clear();
  last_clock_sync_time_ = base::TimeTicks();

  num_start_tracing_attempts_ = 1;
  command_ = Command::START_TRACING;
  PerformAction(Action::REQUEST_CONNECTION);
}

void BattOrAgent::StopTracing() {
  DCHECK(thread_checker_.CalledOnValidThread());

  command_ = Command::STOP_TRACING;
  PerformAction(Action::REQUEST_CONNECTION);
}

void BattOrAgent::RecordClockSyncMarker(const std::string& marker) {
  DCHECK(thread_checker_.CalledOnValidThread());

  command_ = Command::RECORD_CLOCK_SYNC_MARKER;
  pending_clock_sync_marker_ = marker;
  PerformAction(Action::REQUEST_CONNECTION);
}

void BattOrAgent::GetFirmwareGitHash() {
  DCHECK(thread_checker_.CalledOnValidThread());

  command_ = Command::GET_FIRMWARE_GIT_HASH;
  PerformAction(Action::REQUEST_CONNECTION);
}

void BattOrAgent::BeginConnect() {
  DCHECK(thread_checker_.CalledOnValidThread());

  connection_->Open();
}

void BattOrAgent::OnConnectionOpened(bool success) {
  // Return immediately if opening the connection already timed out.
  if (timeout_callback_.IsCancelled())
    return;
  timeout_callback_.Cancel();

  if (!success) {
    CompleteCommand(BATTOR_ERROR_CONNECTION_FAILED);
    return;
  }

  switch (command_) {
    case Command::START_TRACING:
      num_init_attempts_ = 1;
      PerformAction(Action::SEND_INIT);
      return;
    case Command::STOP_TRACING:
      PerformAction(Action::SEND_EEPROM_REQUEST);
      return;
    case Command::RECORD_CLOCK_SYNC_MARKER:
      PerformAction(Action::SEND_CURRENT_SAMPLE_REQUEST);
      return;
    case Command::GET_FIRMWARE_GIT_HASH:
      num_init_attempts_ = 1;
      PerformAction(Action::SEND_INIT);
      return;
    case Command::INVALID:
      NOTREACHED();
  }
}

void BattOrAgent::OnBytesSent(bool success) {
  DCHECK(thread_checker_.CalledOnValidThread());

  // Return immediately if whatever action we were trying to perform already
  // timed out.
  if (timeout_callback_.IsCancelled())
    return;
  timeout_callback_.Cancel();

  if (!success) {
    CompleteCommand(BATTOR_ERROR_SEND_ERROR);
    return;
  }

  switch (last_action_) {
    case Action::SEND_INIT:
      PerformAction(Action::READ_INIT_ACK);
      return;
    case Action::SEND_SET_GAIN:
      PerformAction(Action::READ_SET_GAIN_ACK);
      return;
    case Action::SEND_START_TRACING:
      PerformAction(Action::READ_START_TRACING_ACK);
      return;
    case Action::SEND_EEPROM_REQUEST:
      num_read_attempts_ = 1;
      PerformAction(Action::READ_EEPROM);
      return;
    case Action::SEND_SAMPLES_REQUEST:
      num_read_attempts_ = 1;
      PerformAction(Action::READ_CALIBRATION_FRAME);
      return;
    case Action::SEND_CURRENT_SAMPLE_REQUEST:
      num_read_attempts_ = 1;
      PerformAction(Action::READ_CURRENT_SAMPLE);
      return;
    case Action::SEND_GIT_HASH_REQUEST:
      num_read_attempts_ = 1;
      PerformAction(Action::READ_GIT_HASH);
      return;
    default:
      CompleteCommand(BATTOR_ERROR_UNEXPECTED_MESSAGE);
  }
}

void BattOrAgent::OnMessageRead(bool success,
                                BattOrMessageType type,
                                std::unique_ptr<vector<char>> bytes) {
  // Return immediately if whatever action we were trying to perform already
  // timed out.
  if (timeout_callback_.IsCancelled())
    return;
  timeout_callback_.Cancel();

  if (!success) {
    switch (last_action_) {
      case Action::READ_GIT_HASH:
      case Action::READ_EEPROM:
      case Action::READ_CALIBRATION_FRAME:
      case Action::READ_DATA_FRAME:
      case Action::READ_CURRENT_SAMPLE:
        if (num_read_attempts_++ > kMaxReadAttempts) {
          CompleteCommand(BATTOR_ERROR_RECEIVE_ERROR);
          return;
        }

        PerformDelayedAction(last_action_, base::TimeDelta::FromMilliseconds(
                                               kReadRetryDelayMilliseconds));
        return;

      // Retry sending an INIT if it an ACK is not received.
      case Action::SEND_INIT:
      case Action::READ_INIT_ACK:
        if (num_init_attempts_++ < kMaxInitAttempts) {
          PerformDelayedAction(Action::SEND_INIT,
              base::TimeDelta::FromMilliseconds(kInitRetryDelayMilliseconds));
        } else {
          CompleteCommand(BATTOR_ERROR_TOO_MANY_INIT_RETRIES);
        }

        return;

      case Action::READ_START_TRACING_ACK:
        if (num_start_tracing_attempts_++ < kMaxStartTracingAttempts) {
          num_init_attempts_ = 1;
          PerformAction(Action::SEND_INIT);
        } else {
          CompleteCommand(BATTOR_ERROR_TOO_MANY_START_TRACING_RETRIES);
        }

        return;

      default:
        CompleteCommand(BATTOR_ERROR_RECEIVE_ERROR);
        return;
    }
  }

  switch (last_action_) {
    case Action::READ_INIT_ACK:
      if (!IsAckOfControlCommand(type, BATTOR_CONTROL_MESSAGE_TYPE_INIT,
                                 *bytes)) {
        if (num_init_attempts_++ < kMaxInitAttempts) {
          PerformDelayedAction(Action::SEND_INIT,
              base::TimeDelta::FromMilliseconds(kInitRetryDelayMilliseconds));
        } else {
          CompleteCommand(BATTOR_ERROR_TOO_MANY_INIT_RETRIES);
        }

        return;
      }

      switch (command_) {
        case Command::START_TRACING:
          PerformAction(Action::SEND_SET_GAIN);
          return;
        case Command::GET_FIRMWARE_GIT_HASH:
          PerformAction(Action::SEND_GIT_HASH_REQUEST);
          return;
        default:
          CompleteCommand(BATTOR_ERROR_UNEXPECTED_MESSAGE);
          return;
      }

    case Action::READ_SET_GAIN_ACK:
      if (!IsAckOfControlCommand(type, BATTOR_CONTROL_MESSAGE_TYPE_SET_GAIN,
                                 *bytes)) {
        CompleteCommand(BATTOR_ERROR_UNEXPECTED_MESSAGE);
        return;
      }

      PerformAction(Action::SEND_START_TRACING);
      return;

    case Action::READ_START_TRACING_ACK:
      if (!IsAckOfControlCommand(
              type, BATTOR_CONTROL_MESSAGE_TYPE_START_SAMPLING_SD, *bytes)) {
        if (num_start_tracing_attempts_++ < kMaxStartTracingAttempts) {
          num_init_attempts_ = 1;
          PerformAction(Action::SEND_INIT);
        } else {
          CompleteCommand(BATTOR_ERROR_TOO_MANY_START_TRACING_RETRIES);
        }

        return;
      }

      CompleteCommand(BATTOR_ERROR_NONE);
      return;

    case Action::READ_EEPROM: {
      battor_eeprom_ = ParseEEPROM(type, *bytes);
      if (!battor_eeprom_) {
        CompleteCommand(BATTOR_ERROR_UNEXPECTED_MESSAGE);
        return;
      }

      // Make sure that we don't request samples until a safe amount of time has
      // elapsed since recording the last clock sync marker: we need to ensure
      // that the sample we synced to doesn't get thrown out.
      base::TimeTicks min_request_samples_time =
          last_clock_sync_time_ + base::TimeDelta::FromMilliseconds(
                                      kStopTracingClockSyncDelayMilliseconds);
      base::TimeDelta request_samples_delay = std::max(
          min_request_samples_time - base::TimeTicks::Now(), base::TimeDelta());

      PerformDelayedAction(Action::SEND_SAMPLES_REQUEST, request_samples_delay);
      return;
    }
    case Action::READ_CALIBRATION_FRAME: {
      BattOrFrameHeader frame_header;
      if (!ParseSampleFrame(type, *bytes, next_sequence_number_++,
                            &frame_header, &calibration_frame_)) {
        CompleteCommand(BATTOR_ERROR_UNEXPECTED_MESSAGE);
        return;
      }

      // Make sure that the calibration frame has actual samples in it.
      if (calibration_frame_.empty()) {
        CompleteCommand(BATTOR_ERROR_UNEXPECTED_MESSAGE);
        return;
      }

      num_read_attempts_ = 1;
      PerformAction(Action::READ_DATA_FRAME);
      return;
    }

    case Action::READ_DATA_FRAME: {
      BattOrFrameHeader frame_header;
      vector<RawBattOrSample> frame;
      if (!ParseSampleFrame(type, *bytes, next_sequence_number_++,
                            &frame_header, &frame)) {
        CompleteCommand(BATTOR_ERROR_UNEXPECTED_MESSAGE);
        return;
      }

      // Check for the empty frame the BattOr uses to indicate it's done
      // streaming samples.
      if (frame.empty()) {
        CompleteCommand(BATTOR_ERROR_NONE);
        return;
      }

      samples_.insert(samples_.end(), frame.begin(), frame.end());

      num_read_attempts_ = 1;
      PerformAction(Action::READ_DATA_FRAME);
      return;
    }

    case Action::READ_CURRENT_SAMPLE:
      if (type != BATTOR_MESSAGE_TYPE_CONTROL_ACK ||
          bytes->size() != sizeof(uint32_t)) {
        CompleteCommand(BATTOR_ERROR_UNEXPECTED_MESSAGE);
        return;
      }

      uint32_t sample_num;
      memcpy(&sample_num, bytes->data(), sizeof(uint32_t));
      clock_sync_markers_[sample_num] = pending_clock_sync_marker_;
      last_clock_sync_time_ = base::TimeTicks::Now();
      CompleteCommand(BATTOR_ERROR_NONE);
      return;

    case Action::READ_GIT_HASH:
      if (type != BATTOR_MESSAGE_TYPE_CONTROL_ACK ){
        CompleteCommand(BATTOR_ERROR_UNEXPECTED_MESSAGE);
        return;
      }
      firmware_git_hash_ = std::string(bytes->begin(), bytes->end());
      CompleteCommand(BATTOR_ERROR_NONE);
      return;

    default:
      CompleteCommand(BATTOR_ERROR_UNEXPECTED_MESSAGE);
  }
}

void BattOrAgent::PerformAction(Action action) {
  DCHECK(thread_checker_.CalledOnValidThread());

  timeout_callback_.Reset(
      base::Bind(&BattOrAgent::OnActionTimeout, AsWeakPtr()));
  base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
      FROM_HERE, timeout_callback_.callback(),
      base::TimeDelta::FromSeconds(kBattOrTimeoutSeconds));

  last_action_ = action;

  switch (action) {
    case Action::REQUEST_CONNECTION:
      BeginConnect();
      return;

    // The following actions are required for StartTracing:
    case Action::SEND_INIT:
      // Clear out the serial data that may exist from prior init attempts.
      connection_->Flush();

      SendControlMessage(BATTOR_CONTROL_MESSAGE_TYPE_INIT, 0, 0);
      return;
    case Action::READ_INIT_ACK:
      connection_->ReadMessage(BATTOR_MESSAGE_TYPE_CONTROL_ACK);
      return;
    case Action::SEND_SET_GAIN:
      // Set the BattOr's gain. Setting the gain tells the BattOr the range of
      // power measurements that we expect to see.
      SendControlMessage(BATTOR_CONTROL_MESSAGE_TYPE_SET_GAIN, BATTOR_GAIN_LOW,
                         0);
      return;
    case Action::READ_SET_GAIN_ACK:
      connection_->ReadMessage(BATTOR_MESSAGE_TYPE_CONTROL_ACK);
      return;
    case Action::SEND_START_TRACING:
      SendControlMessage(BATTOR_CONTROL_MESSAGE_TYPE_START_SAMPLING_SD, 0, 0);
      return;
    case Action::READ_START_TRACING_ACK:
      connection_->ReadMessage(BATTOR_MESSAGE_TYPE_CONTROL_ACK);
      return;

    // The following actions are required for StopTracing:
    case Action::SEND_EEPROM_REQUEST:
      // Read the BattOr's EEPROM to get calibration information that's required
      // to convert the raw samples to accurate ones.
      SendControlMessage(BATTOR_CONTROL_MESSAGE_TYPE_READ_EEPROM,
                         sizeof(BattOrEEPROM), 0);
      return;
    case Action::READ_EEPROM:
      connection_->ReadMessage(BATTOR_MESSAGE_TYPE_CONTROL_ACK);
      return;
    case Action::SEND_SAMPLES_REQUEST:
      // Send a request to the BattOr to tell it to start streaming the samples
      // that it's stored on its SD card over the serial connection.
      SendControlMessage(BATTOR_CONTROL_MESSAGE_TYPE_READ_SD_UART, 0, 0);
      return;
    case Action::READ_CALIBRATION_FRAME:
      // Data frames are numbered starting at zero and counting up by one each
      // data frame. We keep track of the next frame sequence number we expect
      // to see to ensure we don't miss any data.
      next_sequence_number_ = 0;
    case Action::READ_DATA_FRAME:
      // The first frame sent back from the BattOr contains voltage and current
      // data that excludes whatever device is being measured from the
      // circuit. We use this first frame to establish a baseline voltage and
      // current.
      //
      // All further frames contain real (but uncalibrated) voltage and current
      // data.
      connection_->ReadMessage(BATTOR_MESSAGE_TYPE_SAMPLES);
      return;

    // The following actions are required for RecordClockSyncMarker:
    case Action::SEND_CURRENT_SAMPLE_REQUEST:
      SendControlMessage(BATTOR_CONTROL_MESSAGE_TYPE_READ_SAMPLE_COUNT, 0, 0);
      return;
    case Action::READ_CURRENT_SAMPLE:
      connection_->ReadMessage(BATTOR_MESSAGE_TYPE_CONTROL_ACK);
      return;

    case Action::SEND_GIT_HASH_REQUEST:
      connection_->Flush();
      SendControlMessage(
          BATTOR_CONTROL_MESSAGE_TYPE_GET_FIRMWARE_GIT_HASH, 0, 0);
      return;

    case Action::READ_GIT_HASH:
      connection_->ReadMessage(BATTOR_MESSAGE_TYPE_CONTROL_ACK);
      return;

    case Action::INVALID:
      NOTREACHED();
  }
}

void BattOrAgent::PerformDelayedAction(Action action, base::TimeDelta delay) {
  base::ThreadTaskRunnerHandle::Get()->PostDelayedTask(
      FROM_HERE, base::Bind(&BattOrAgent::PerformAction, AsWeakPtr(), action),
      delay);
}

void BattOrAgent::OnActionTimeout() {
  switch (last_action_) {
    case Action::READ_INIT_ACK:
      if (num_init_attempts_++ < kMaxInitAttempts) {
        // OnMessageRead() will fail and retry SEND_INIT.
        connection_->CancelReadMessage();
      } else {
        CompleteCommand(BATTOR_ERROR_TOO_MANY_INIT_RETRIES);
      }
      return;

    // TODO(crbug.com/672631): There's currently a BattOr firmware bug that's
    // causing the BattOr to reset when it's sent the START_TRACING command.
    // When the BattOr resets, it emits 0x00 to the serial connection. This 0x00
    // isn't long enough for the connection to consider it a full ack of the
    // START_TRACING command, so it continues to wait for more data. We handle
    // this case here by assuming any timeouts while waiting for the
    // StartTracing ack are related to this bug and retrying the full
    // initialization sequence.
    case Action::READ_START_TRACING_ACK:
      if (num_start_tracing_attempts_ < kMaxStartTracingAttempts) {
        // OnMessageRead() will fail and retry StartTracing.
        connection_->CancelReadMessage();
      } else {
        CompleteCommand(BATTOR_ERROR_TOO_MANY_START_TRACING_RETRIES);
      }
      return;

    default:
      CompleteCommand(BATTOR_ERROR_TIMEOUT);
      timeout_callback_.Cancel();
  }
}

void BattOrAgent::SendControlMessage(BattOrControlMessageType type,
                                     uint16_t param1,
                                     uint16_t param2) {
  DCHECK(thread_checker_.CalledOnValidThread());

  BattOrControlMessage msg{type, param1, param2};
  connection_->SendBytes(BATTOR_MESSAGE_TYPE_CONTROL, &msg, sizeof(msg));
}

void BattOrAgent::CompleteCommand(BattOrError error) {
  switch (command_) {
    case Command::START_TRACING:
      base::ThreadTaskRunnerHandle::Get()->PostTask(
          FROM_HERE, base::Bind(&Listener::OnStartTracingComplete,
                                base::Unretained(listener_), error));
      break;
    case Command::STOP_TRACING:
      base::ThreadTaskRunnerHandle::Get()->PostTask(
          FROM_HERE,
          base::Bind(&Listener::OnStopTracingComplete,
                     base::Unretained(listener_), SamplesToString(), error));
      break;
    case Command::RECORD_CLOCK_SYNC_MARKER:
      base::ThreadTaskRunnerHandle::Get()->PostTask(
          FROM_HERE, base::Bind(&Listener::OnRecordClockSyncMarkerComplete,
                                base::Unretained(listener_), error));
      break;
    case Command::GET_FIRMWARE_GIT_HASH:
      base::ThreadTaskRunnerHandle::Get()->PostTask(
          FROM_HERE, base::Bind(&Listener::OnGetFirmwareGitHashComplete,
                                base::Unretained(listener_),
                                firmware_git_hash_, error));
      break;
    case Command::INVALID:
      NOTREACHED();
  }

  last_action_ = Action::INVALID;
  command_ = Command::INVALID;
  pending_clock_sync_marker_.clear();
  battor_eeprom_.reset();
  calibration_frame_.clear();
  samples_.clear();
  next_sequence_number_ = 0;
}

std::string BattOrAgent::SamplesToString() {
  if (calibration_frame_.empty() || samples_.empty() || !battor_eeprom_)
    return "";

  BattOrSampleConverter converter(*battor_eeprom_, calibration_frame_);

  std::stringstream trace_stream;
  trace_stream << std::fixed;

  // Create a header that indicates the BattOr's parameters for these samples.
  BattOrSample min_sample = converter.MinSample();
  BattOrSample max_sample = converter.MaxSample();
  trace_stream << "# BattOr" << std::endl
               << std::setprecision(1) << "# voltage_range ["
               << min_sample.voltage_mV << ", " << max_sample.voltage_mV
               << "] mV" << std::endl
               << "# current_range [" << min_sample.current_mA << ", "
               << max_sample.current_mA << "] mA" << std::endl
               << "# sample_rate " << battor_eeprom_->sd_sample_rate << " Hz"
               << ", gain " << battor_eeprom_->low_gain << "x" << std::endl;

  // Create a string representation of the BattOr samples.
  for (size_t i = 0; i < samples_.size(); i++) {
    BattOrSample sample = converter.ToSample(samples_[i], i);
    trace_stream << std::setprecision(2) << sample.time_ms << " "
                 << std::setprecision(1) << sample.current_mA << " "
                 << sample.voltage_mV;

    // If there's a clock sync marker for the current sample, print it.
    auto clock_sync_marker = clock_sync_markers_.find(
        static_cast<uint32_t>(calibration_frame_.size() + i));
    if (clock_sync_marker != clock_sync_markers_.end())
      trace_stream << " <" << clock_sync_marker->second << ">";

    trace_stream << std::endl;
  }

  return trace_stream.str();
}

}  // namespace battor
