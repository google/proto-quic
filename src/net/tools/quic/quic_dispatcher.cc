// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/quic_dispatcher.h"

#include <utility>

#include "base/debug/stack_trace.h"
#include "base/logging.h"
#include "base/macros.h"
#include "base/stl_util.h"
#include "net/quic/quic_bug_tracker.h"
#include "net/quic/quic_flags.h"
#include "net/quic/quic_utils.h"
#include "net/tools/quic/quic_per_connection_packet_writer.h"
#include "net/tools/quic/quic_simple_server_session.h"
#include "net/tools/quic/quic_time_wait_list_manager.h"

using base::StringPiece;
using std::string;

namespace net {

namespace {

// An alarm that informs the QuicDispatcher to delete old sessions.
class DeleteSessionsAlarm : public QuicAlarm::Delegate {
 public:
  explicit DeleteSessionsAlarm(QuicDispatcher* dispatcher)
      : dispatcher_(dispatcher) {}

  void OnAlarm() override { dispatcher_->DeleteSessions(); }

 private:
  // Not owned.
  QuicDispatcher* dispatcher_;

  DISALLOW_COPY_AND_ASSIGN(DeleteSessionsAlarm);
};

}  // namespace

QuicDispatcher::QuicDispatcher(
    const QuicConfig& config,
    const QuicCryptoServerConfig* crypto_config,
    const QuicVersionVector& supported_versions,
    std::unique_ptr<QuicConnectionHelperInterface> helper,
    std::unique_ptr<QuicAlarmFactory> alarm_factory)
    : config_(config),
      crypto_config_(crypto_config),
      compressed_certs_cache_(
          QuicCompressedCertsCache::kQuicCompressedCertsCacheSize),
      helper_(std::move(helper)),
      alarm_factory_(std::move(alarm_factory)),
      delete_sessions_alarm_(
          alarm_factory_->CreateAlarm(new DeleteSessionsAlarm(this))),
      supported_versions_(supported_versions),
      current_packet_(nullptr),
      framer_(supported_versions,
              /*unused*/ QuicTime::Zero(),
              Perspective::IS_SERVER),
      last_error_(QUIC_NO_ERROR) {
  framer_.set_visitor(this);
}

QuicDispatcher::~QuicDispatcher() {
  STLDeleteValues(&session_map_);
  STLDeleteElements(&closed_session_list_);
}

void QuicDispatcher::InitializeWithWriter(QuicPacketWriter* writer) {
  DCHECK(writer_ == nullptr);
  writer_.reset(writer);
  time_wait_list_manager_.reset(CreateQuicTimeWaitListManager());
}

void QuicDispatcher::ProcessPacket(const IPEndPoint& server_address,
                                   const IPEndPoint& client_address,
                                   const QuicReceivedPacket& packet) {
  current_server_address_ = server_address;
  current_client_address_ = client_address;
  current_packet_ = &packet;
  // ProcessPacket will cause the packet to be dispatched in
  // OnUnauthenticatedPublicHeader, or sent to the time wait list manager
  // in OnUnauthenticatedHeader.
  framer_.ProcessPacket(packet);
  // TODO(rjshade): Return a status describing if/why a packet was dropped,
  //                and log somehow.  Maybe expose as a varz.
}

bool QuicDispatcher::OnUnauthenticatedPublicHeader(
    const QuicPacketPublicHeader& header) {
  current_connection_id_ = header.connection_id;

  // Port zero is only allowed for unidirectional UDP, so is disallowed by QUIC.
  // Given that we can't even send a reply rejecting the packet, just drop the
  // packet.
  if (current_client_address_.port() == 0) {
    return false;
  }

  // Stopgap test: The code does not construct full-length connection IDs
  // correctly from truncated connection ID fields.  Prevent this from causing
  // the connection ID lookup to error by dropping any packet with a short
  // connection ID.
  if (header.connection_id_length != PACKET_8BYTE_CONNECTION_ID) {
    return false;
  }

  // Packets with connection IDs for active connections are processed
  // immediately.
  QuicConnectionId connection_id = header.connection_id;
  SessionMap::iterator it = session_map_.find(connection_id);
  if (it != session_map_.end()) {
    it->second->ProcessUdpPacket(current_server_address_,
                                 current_client_address_, *current_packet_);
    return false;
  }

  // If the packet is a public reset for a connection ID that is not active,
  // there is nothing we must do or can do.
  if (header.reset_flag) {
    return false;
  }

  if (time_wait_list_manager_->IsConnectionIdInTimeWait(connection_id)) {
    // Set the framer's version based on the recorded version for this
    // connection and continue processing for non-public-reset packets.
    return HandlePacketForTimeWait(header);
  }

  // The packet has an unknown connection ID.

  // Unless the packet provides a version, assume that we can continue
  // processing using our preferred version.
  QuicVersion version = supported_versions_.front();
  if (header.version_flag) {
    QuicVersion packet_version = header.versions.front();
    if (framer_.IsSupportedVersion(packet_version)) {
      version = packet_version;
    } else {
      if (FLAGS_quic_stateless_version_negotiation) {
        if (ShouldCreateSessionForUnknownVersion(framer_.last_version_tag())) {
          return true;
        }
        // Since the version is not supported, send a version negotiation
        // packet and stop processing the current packet.
        time_wait_list_manager()->SendVersionNegotiationPacket(
            connection_id, supported_versions_, current_server_address_,
            current_client_address_);
        return false;
      } else {
        // Packets set to be processed but having an unsupported version will
        // cause a connection to be created.  The connection will handle
        // sending a version negotiation packet.
        // TODO(ianswett): This will malfunction if the full header of the
        // packet causes a parsing error when parsed using the server's
        // preferred version.
      }
    }
  }
  // Set the framer's version and continue processing.
  framer_.set_version(version);
  return true;
}

bool QuicDispatcher::OnUnauthenticatedHeader(const QuicPacketHeader& header) {
  QuicConnectionId connection_id = header.public_header.connection_id;

  if (time_wait_list_manager_->IsConnectionIdInTimeWait(
          header.public_header.connection_id)) {
    // This connection ID is already in time-wait state.
    time_wait_list_manager_->ProcessPacket(
        current_server_address_, current_client_address_,
        header.public_header.connection_id, header.packet_number,
        *current_packet_);
    return false;
  }

  // Packet's connection ID is unknown.
  // Apply the validity checks.
  QuicPacketFate fate = ValidityChecks(header);
  switch (fate) {
    case kFateProcess: {
      // Create a session and process the packet.
      QuicServerSessionBase* session =
          CreateQuicSession(connection_id, current_client_address_);
      DVLOG(1) << "Created new session for " << connection_id;
      session_map_.insert(std::make_pair(connection_id, session));
      session->ProcessUdpPacket(current_server_address_,
                                current_client_address_, *current_packet_);
      break;
    }
    case kFateTimeWait:
      // Add this connection_id to the time-wait state, to safely reject
      // future packets.
      DVLOG(1) << "Adding connection ID " << connection_id
               << "to time-wait list.";
      time_wait_list_manager_->AddConnectionIdToTimeWait(
          connection_id, framer_.version(),
          /*connection_rejected_statelessly=*/false, nullptr);
      DCHECK(time_wait_list_manager_->IsConnectionIdInTimeWait(
          header.public_header.connection_id));
      time_wait_list_manager_->ProcessPacket(
          current_server_address_, current_client_address_,
          header.public_header.connection_id, header.packet_number,
          *current_packet_);
      break;
    case kFateDrop:
      // Do nothing with the packet.
      break;
  }

  return false;
}

QuicDispatcher::QuicPacketFate QuicDispatcher::ValidityChecks(
    const QuicPacketHeader& header) {
  // To have all the checks work properly without tears, insert any new check
  // into the framework of this method in the section for checks that return the
  // check's fate value.  The sections for checks must be ordered with the
  // highest priority fate first.

  // Checks that return kFateDrop.

  // Checks that return kFateTimeWait.

  // All packets within a connection sent by a client before receiving a
  // response from the server are required to have the version negotiation flag
  // set.  Since this may be a client continuing a connection we lost track of
  // via server restart, send a rejection to fast-fail the connection.
  if (!header.public_header.version_flag) {
    DVLOG(1) << "Packet without version arrived for unknown connection ID "
             << header.public_header.connection_id;
    return kFateTimeWait;
  }

  // Check that the sequence numer is within the range that the client is
  // expected to send before receiving a response from the server.
  if (header.packet_number == kInvalidPacketNumber ||
      header.packet_number > kMaxReasonableInitialPacketNumber) {
    return kFateTimeWait;
  }

  return kFateProcess;
}

void QuicDispatcher::CleanUpSession(SessionMap::iterator it,
                                    bool should_close_statelessly) {
  QuicConnection* connection = it->second->connection();

  write_blocked_list_.erase(connection);
  if (should_close_statelessly) {
    DCHECK(connection->termination_packets() != nullptr &&
           !connection->termination_packets()->empty());
  }
  time_wait_list_manager_->AddConnectionIdToTimeWait(
      it->first, connection->version(), should_close_statelessly,
      connection->termination_packets());
  session_map_.erase(it);
}

void QuicDispatcher::DeleteSessions() {
  STLDeleteElements(&closed_session_list_);
}

void QuicDispatcher::OnCanWrite() {
  // The socket is now writable.
  writer_->SetWritable();

  // Give all the blocked writers one chance to write, until we're blocked again
  // or there's no work left.
  while (!write_blocked_list_.empty() && !writer_->IsWriteBlocked()) {
    QuicBlockedWriterInterface* blocked_writer =
        write_blocked_list_.begin()->first;
    write_blocked_list_.erase(write_blocked_list_.begin());
    blocked_writer->OnCanWrite();
  }
}

bool QuicDispatcher::HasPendingWrites() const {
  return !write_blocked_list_.empty();
}

void QuicDispatcher::Shutdown() {
  while (!session_map_.empty()) {
    QuicServerSessionBase* session = session_map_.begin()->second;
    session->connection()->CloseConnection(
        QUIC_PEER_GOING_AWAY, "Server shutdown imminent",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    // Validate that the session removes itself from the session map on close.
    DCHECK(session_map_.empty() || session_map_.begin()->second != session);
  }
  DeleteSessions();
}

void QuicDispatcher::OnConnectionClosed(QuicConnectionId connection_id,
                                        QuicErrorCode error,
                                        const string& error_details) {
  SessionMap::iterator it = session_map_.find(connection_id);
  if (it == session_map_.end()) {
    QUIC_BUG << "ConnectionId " << connection_id
             << " does not exist in the session map.  Error: "
             << QuicUtils::ErrorToString(error);
    QUIC_BUG << base::debug::StackTrace().ToString();
    return;
  }

  DVLOG_IF(1, error != QUIC_NO_ERROR)
      << "Closing connection (" << connection_id
      << ") due to error: " << QuicUtils::ErrorToString(error)
      << ", with details: " << error_details;

  if (closed_session_list_.empty()) {
    delete_sessions_alarm_->Cancel();
    delete_sessions_alarm_->Set(helper()->GetClock()->ApproximateNow());
  }
  closed_session_list_.push_back(it->second);
  const bool should_close_statelessly =
      (error == QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT);
  CleanUpSession(it, should_close_statelessly);
}

void QuicDispatcher::OnWriteBlocked(
    QuicBlockedWriterInterface* blocked_writer) {
  if (!writer_->IsWriteBlocked()) {
    QUIC_BUG << "QuicDispatcher::OnWriteBlocked called when the writer is "
                "not blocked.";
    // Return without adding the connection to the blocked list, to avoid
    // infinite loops in OnCanWrite.
    return;
  }
  write_blocked_list_.insert(std::make_pair(blocked_writer, true));
}

void QuicDispatcher::OnConnectionAddedToTimeWaitList(
    QuicConnectionId connection_id) {
  DVLOG(1) << "Connection " << connection_id << " added to time wait list.";
}

void QuicDispatcher::OnPacket() {}

void QuicDispatcher::OnError(QuicFramer* framer) {
  QuicErrorCode error = framer->error();
  SetLastError(error);
  DVLOG(1) << QuicUtils::ErrorToString(error);
}

bool QuicDispatcher::ShouldCreateSessionForUnknownVersion(QuicTag version_tag) {
  return false;
}

bool QuicDispatcher::OnProtocolVersionMismatch(
    QuicVersion /*received_version*/) {
  if (FLAGS_quic_stateless_version_negotiation) {
    QUIC_BUG_IF(
        !time_wait_list_manager_->IsConnectionIdInTimeWait(
            current_connection_id_) &&
        !ShouldCreateSessionForUnknownVersion(framer_.last_version_tag()))
        << "Unexpected version mismatch: "
        << QuicUtils::TagToString(framer_.last_version_tag());
  }

  // Keep processing after protocol mismatch - this will be dealt with by the
  // time wait list or connection that we will create.
  return true;
}

void QuicDispatcher::OnPublicResetPacket(
    const QuicPublicResetPacket& /*packet*/) {
  DCHECK(false);
}

void QuicDispatcher::OnVersionNegotiationPacket(
    const QuicVersionNegotiationPacket& /*packet*/) {
  DCHECK(false);
}

void QuicDispatcher::OnDecryptedPacket(EncryptionLevel level) {
  DCHECK(false);
}

bool QuicDispatcher::OnPacketHeader(const QuicPacketHeader& /*header*/) {
  DCHECK(false);
  return false;
}

bool QuicDispatcher::OnStreamFrame(const QuicStreamFrame& /*frame*/) {
  DCHECK(false);
  return false;
}

bool QuicDispatcher::OnAckFrame(const QuicAckFrame& /*frame*/) {
  DCHECK(false);
  return false;
}

bool QuicDispatcher::OnStopWaitingFrame(const QuicStopWaitingFrame& /*frame*/) {
  DCHECK(false);
  return false;
}

bool QuicDispatcher::OnPaddingFrame(const QuicPaddingFrame& /*frame*/) {
  DCHECK(false);
  return false;
}

bool QuicDispatcher::OnPingFrame(const QuicPingFrame& /*frame*/) {
  DCHECK(false);
  return false;
}

bool QuicDispatcher::OnRstStreamFrame(const QuicRstStreamFrame& /*frame*/) {
  DCHECK(false);
  return false;
}

bool QuicDispatcher::OnConnectionCloseFrame(
    const QuicConnectionCloseFrame& /*frame*/) {
  DCHECK(false);
  return false;
}

bool QuicDispatcher::OnGoAwayFrame(const QuicGoAwayFrame& /*frame*/) {
  DCHECK(false);
  return false;
}

bool QuicDispatcher::OnWindowUpdateFrame(
    const QuicWindowUpdateFrame& /*frame*/) {
  DCHECK(false);
  return false;
}

bool QuicDispatcher::OnBlockedFrame(const QuicBlockedFrame& frame) {
  DCHECK(false);
  return false;
}

bool QuicDispatcher::OnPathCloseFrame(const QuicPathCloseFrame& frame) {
  DCHECK(false);
  return false;
}

void QuicDispatcher::OnPacketComplete() {
  DCHECK(false);
}

QuicServerSessionBase* QuicDispatcher::CreateQuicSession(
    QuicConnectionId connection_id,
    const IPEndPoint& client_address) {
  // The QuicServerSessionBase takes ownership of |connection| below.
  QuicConnection* connection = new QuicConnection(
      connection_id, client_address, helper_.get(), alarm_factory_.get(),
      CreatePerConnectionWriter(),
      /* owns_writer= */ true, Perspective::IS_SERVER, supported_versions_);

  QuicServerSessionBase* session = new QuicSimpleServerSession(
      config_, connection, this, crypto_config_, &compressed_certs_cache_);
  session->Initialize();
  return session;
}

QuicTimeWaitListManager* QuicDispatcher::CreateQuicTimeWaitListManager() {
  return new QuicTimeWaitListManager(writer_.get(), this, helper_.get(),
                                     alarm_factory_.get());
}

bool QuicDispatcher::HandlePacketForTimeWait(
    const QuicPacketPublicHeader& header) {
  if (header.reset_flag) {
    // Public reset packets do not have packet numbers, so ignore the packet.
    return false;
  }

  // Switch the framer to the correct version, so that the packet number can
  // be parsed correctly.
  framer_.set_version(time_wait_list_manager_->GetQuicVersionFromConnectionId(
      header.connection_id));

  // Continue parsing the packet to extract the packet number.  Then
  // send it to the time wait manager in OnUnathenticatedHeader.
  return true;
}

QuicPacketWriter* QuicDispatcher::CreatePerConnectionWriter() {
  return new QuicPerConnectionPacketWriter(writer_.get());
}

void QuicDispatcher::SetLastError(QuicErrorCode error) {
  last_error_ = error;
}

}  // namespace net
