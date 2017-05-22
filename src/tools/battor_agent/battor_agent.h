// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TOOLS_BATTOR_AGENT_BATTOR_AGENT_H_
#define TOOLS_BATTOR_AGENT_BATTOR_AGENT_H_

#include <map>

#include "base/cancelable_callback.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/memory/weak_ptr.h"
#include "base/single_thread_task_runner.h"
#include "base/threading/thread_checker.h"
#include "tools/battor_agent/battor_connection.h"
#include "tools/battor_agent/battor_error.h"

namespace battor {

// A BattOrAgent is a class used to asynchronously communicate with a BattOr for
// the purpose of collecting power samples. A BattOr is an external USB device
// that's capable of recording accurate, high-frequency (2000Hz) power samples.
//
// The serial connection is automatically opened when the first command
// (e.g. StartTracing(), StopTracing(), etc.) is issued, and automatically
// closed when either StopTracing() or the destructor is called. For Telemetry,
// this means that the connection must be reinitialized for every command that's
// issued because a new BattOrAgent is constructed. For Chromium, we use the
// same BattOrAgent for multiple commands and thus avoid having to reinitialize
// the serial connection.
//
// This class is NOT thread safe. Any interactions with this class that involve
// IO (i.e. any interactions that require a callback) must be done from the
// same IO thread, which must also have a running MessageLoop.
class BattOrAgent : public BattOrConnection::Listener,
                    public base::SupportsWeakPtr<BattOrAgent> {
 public:
  // The listener interface that must be implemented in order to interact with
  // the BattOrAgent.
  class Listener {
   public:
    virtual void OnStartTracingComplete(BattOrError error) = 0;
    virtual void OnStopTracingComplete(const std::string& trace,
                                       BattOrError error) = 0;
    virtual void OnRecordClockSyncMarkerComplete(BattOrError error) = 0;
    virtual void OnGetFirmwareGitHashComplete(const std::string& version,
                                              BattOrError error) = 0;
  };

  BattOrAgent(
      const std::string& path,
      Listener* listener,
      scoped_refptr<base::SingleThreadTaskRunner> file_thread_task_runner,
      scoped_refptr<base::SingleThreadTaskRunner> ui_thread_task_runner);
  virtual ~BattOrAgent();

  void StartTracing();
  void StopTracing();
  void RecordClockSyncMarker(const std::string& marker);
  void GetFirmwareGitHash();

  // Returns whether the BattOr is able to record clock sync markers in its own
  // trace log.
  static bool SupportsExplicitClockSync() { return true; }

  // BattOrConnection::Listener implementation.
  void OnConnectionOpened(bool success) override;
  void OnBytesSent(bool success) override;
  void OnMessageRead(bool success,
                     BattOrMessageType type,
                     std::unique_ptr<std::vector<char>> bytes) override;

 protected:
  // The connection that knows how to communicate with the BattOr in terms of
  // protocol primitives. This is protected so that it can be replaced with a
  // fake in testing.
  std::unique_ptr<BattOrConnection> connection_;

  // Timeout for when an action isn't completed within the allotted time. This
  // is virtual and protected so that timeouts can be disabled in testing. The
  // testing task runner that runs delayed tasks immediately deals poorly with
  // timeouts posted as future tasks.
  virtual void OnActionTimeout();

 private:
  enum class Command {
    INVALID,
    START_TRACING,
    STOP_TRACING,
    RECORD_CLOCK_SYNC_MARKER,
    GET_FIRMWARE_GIT_HASH,
  };

  enum class Action {
    INVALID,

    // Actions required to connect to a BattOr.
    REQUEST_CONNECTION,

    // Actions required for starting tracing.
    SEND_INIT,
    READ_INIT_ACK,
    SEND_SET_GAIN,
    READ_SET_GAIN_ACK,
    SEND_START_TRACING,
    READ_START_TRACING_ACK,

    // Actions required for stopping tracing.
    SEND_EEPROM_REQUEST,
    READ_EEPROM,
    SEND_SAMPLES_REQUEST,
    READ_CALIBRATION_FRAME,
    READ_DATA_FRAME,

    // Actions required for recording a clock sync marker.
    SEND_CURRENT_SAMPLE_REQUEST,
    READ_CURRENT_SAMPLE,

    // Actions required for returning firmware git hash.
    SEND_GIT_HASH_REQUEST,
    READ_GIT_HASH,
  };

  // Performs an action.
  void PerformAction(Action action);
  // Performs an action after a delay.
  void PerformDelayedAction(Action action, base::TimeDelta delay);

  // Requests a connection to the BattOr.
  void BeginConnect();

  // Sends a control message over the connection.
  void SendControlMessage(BattOrControlMessageType type,
                          uint16_t param1,
                          uint16_t param2);

  // Retry the last command.
  void RetryCommand();

  // Completes the command with the specified error.
  void CompleteCommand(BattOrError error);

  // Returns a formatted version of samples_ with timestamps and real units.
  std::string SamplesToString();

  // Sets and restarts the action timeout timer.
  void SetActionTimeout(uint16_t timeout_seconds);

  // The listener that handles the commands' results. It must outlive the agent.
  Listener* listener_;

  // The last action executed by the agent. This should only be updated in
  // PerformAction().
  Action last_action_;

  // The tracing command currently being executed by the agent.
  Command command_;

  // A map from the sample number (including samples from the calibration frame)
  // to the ID of the clock sync marker that is associated with that sample
  // number. If we ever have to store a large number of these, consider using an
  // unordered map.
  std::map<uint32_t, std::string> clock_sync_markers_;

  // The clock sync marker being recorded (if we're currently recording one).
  std::string pending_clock_sync_marker_;

  // The time at which the last clock sync marker was recorded.
  base::TimeTicks last_clock_sync_time_;

  // Checker to make sure that this is only ever called on the IO thread.
  base::ThreadChecker thread_checker_;

  // The BattOr's EEPROM (which is required for calibration).
  std::unique_ptr<BattOrEEPROM> battor_eeprom_;

  // The first frame (required for calibration).
  std::vector<RawBattOrSample> calibration_frame_;

  // The actual data samples recorded.
  std::vector<RawBattOrSample> samples_;

  // The expected sequence number of the next frame. We use this to ensure that
  // we receive frames in order.
  uint32_t next_sequence_number_;

  // The number of times we've attempted a command.
  uint8_t num_command_attempts_;

  // The timeout that's run when an action times out.
  base::CancelableClosure timeout_callback_;

  // The git hash of the BattOr firmware.
  std::string firmware_git_hash_;

  DISALLOW_COPY_AND_ASSIGN(BattOrAgent);
};

}  // namespace battor

#endif  // TOOLS_BATTOR_AGENT_BATTOR_AGENT_H_
