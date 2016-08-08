// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_flags.h"

// If true, it will return as soon as an error is detected while validating
// CHLO.
bool FLAGS_use_early_return_when_verifying_chlo = true;

// If true, QUIC BBR congestion control may be enabled via Finch and/or via QUIC
// connection options.
bool FLAGS_quic_allow_bbr = false;

// Time period for which a given connection_id should live in the time-wait
// state.
int64_t FLAGS_quic_time_wait_list_seconds = 200;

// Currently, this number is quite conservative.  The max QPS limit for an
// individual server silo is currently set to 1000 qps, though the actual max
// that we see in the wild is closer to 450 qps.  Regardless, this means that
// the longest time-wait list we should see is 200 seconds * 1000 qps = 200000.
// Of course, there are usually many queries per QUIC connection, so we allow a
// factor of 3 leeway.
//
// Maximum number of connections on the time-wait list. A negative value implies
// no configured limit.
int64_t FLAGS_quic_time_wait_list_max_connections = 600000;

// Enables server-side support for QUIC stateless rejects.
bool FLAGS_enable_quic_stateless_reject_support = true;

// This flag is not in use, just to keep consistency for shared code.
bool FLAGS_quic_always_log_bugs_for_tests = true;

// If true, multipath is enabled for the connection.
bool FLAGS_quic_enable_multipath = false;

// If true, require handshake confirmation for QUIC connections, functionally
// disabling 0-rtt handshakes.
// TODO(rtenneti): Enable this flag after CryptoServerTest's are fixed.
bool FLAGS_quic_require_handshake_confirmation = false;

// If true, Cubic's epoch is shifted when the sender is application-limited.
bool FLAGS_shift_quic_cubic_epoch_when_app_limited = true;

// If true, QUIC will measure head of line (HOL) blocking due between
// streams due to packet losses on the headers stream.  The
// measurements will be surfaced via UMA histogram
// Net.QuicSession.HeadersHOLBlockedTime.
bool FLAGS_quic_measure_headers_hol_blocking_time = true;

// If true, disable pacing in QUIC.
bool FLAGS_quic_disable_pacing_for_perf_tests = false;

// If true, Close the connection instead of writing unencrypted stream data.
bool FLAGS_quic_never_write_unencrypted_data = true;

// If true, QUIC connections can do bandwidth resumption with an initial window
// of < 10 packets.
bool FLAGS_quic_no_lower_bw_resumption_limit = true;

// Use largest acked in the most recent ack instead of largest acked ever in
// loss recovery.
bool FLAGS_quic_loss_recovery_use_largest_acked = true;

// Only set one alarm for sending at once, either the send alarm or
// retransmission alarm.  Disabled because it breaks QUIC time loss detection.
bool FLAGS_quic_only_one_sending_alarm = false;

// If true, QUIC public reset packets will have the \"pre-v33\" public header
// flags.
bool FLAGS_quic_use_old_public_reset_packets = true;

// Adds a RATE connection option to do rate based sending.
bool FLAGS_quic_rate_based_sending = true;

// If true, QUIC will use cheap stateless rejects without creating a full
// connection.
bool FLAGS_quic_use_cheap_stateless_rejects = false;

// If true, treat timestamps from SO_TIMESTAMPING as QuicWallTimes rather
// than QuicTimes.
bool FLAGS_quic_socket_walltimestamps = true;

// If true, QUIC respect HTTP2 SETTINGS frame rather than always close the
// connection.
bool FLAGS_quic_respect_http2_settings_frame = true;

// Do not use a QuicAckListener in order to confirm a larger Path MTU.
bool FLAGS_quic_no_mtu_discovery_ack_listener = true;

// Deprecate QuicPacketCreator::next_packet_number_length_ because it's no
// longer necessary.
bool FLAGS_quic_simple_packet_number_length = true;

// If true, enables QUIC_VERSION_35.
bool FLAGS_quic_enable_version_35 = true;

// If true, enables QUIC_VERSION_36.
bool FLAGS_quic_enable_version_36 = true;

// If true, requires support for X509 certificates in QUIC CHLO PDMDs.
bool FLAGS_quic_require_x509 = true;

// If true, deprecate safeguards for b/26023400.
bool FLAGS_quic_deprecate_kfixd = false;

// If true, a connection does not migrate on an old packet even the peer address
// changes.
bool FLAGS_quic_do_not_migrate_on_old_packet = true;

// If true, use async codepaths to invoke ProofSource::GetProof.
bool FLAGS_enable_async_get_proof = false;

// If true, neuter null encrypted packets before sending the next handshake
// message.
bool FLAGS_quic_neuter_unencrypted_when_sending = false;

// If true, QuicAlarm::Update will call a faster UpdateImpl implementation
// instead of canceling and reregistering the alarm.
bool FLAGS_quic_change_alarms_efficiently = false;

// If true, requires handshake confirmations for all QUIC handshakes with
// versions less than 33.
bool FLAGS_quic_require_handshake_confirmation_pre33 = false;

// If true, use the interval form of iteration over a PacketNumberQueue instead
// of iterating over the individual numbers.
bool FLAGS_quic_use_packet_number_queue_intervals = false;

bool FLAGS_quic_sequencer_buffer_retire_block_in_time = true;

// Remove obsolete code to force QUIC to go forward secure, now that the server
// immediately goes forward secure.
bool FLAGS_quic_remove_obsolete_forward_secure = false;

// If true, close QUIC connection explicitly on write error due to packet being
// too large.
bool FLAGS_quic_close_connection_on_packet_too_large = true;

// Use GetLeastUnacked when updating the packet number length, instead of
// GetLeastPacketAwaitedByPeer.
bool FLAGS_quic_least_unacked_packet_number_length = true;

// If true, close the write side of a QUIC spdy stream when all queued bytes
// have been written and a FIN has been sent.
bool FLAGS_quic_close_stream_after_writing_queued_data = false;

// If true, close connection with QUIC_TOO_MANY_FRAME_GAPS error when number of
// gaps in QuicStreamSequenceBuffer exceeds allowed limit.
bool FLAGS_quic_limit_frame_gaps_in_buffer = false;

// If true, QuicSentPacketManager will use inline pacing functionality instead
// of wrapping the SendAlgorithm with a PacingSender.
bool FLAGS_quic_use_inline_pacing = false;
