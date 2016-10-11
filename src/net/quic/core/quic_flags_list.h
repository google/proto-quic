// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file intentionally does not have header guards, it's included
// inside a macro to generate values.

// This file contains the list of QUIC protocol flags.

// If true, QUIC BBR congestion control may be enabled via Finch and/or via QUIC
// connection options.
QUIC_FLAG(bool, FLAGS_quic_allow_bbr, false)

// Time period for which a given connection_id should live in the time-wait
// state.
QUIC_FLAG(int64_t, FLAGS_quic_time_wait_list_seconds, 200)

// Currently, this number is quite conservative.  The max QPS limit for an
// individual server silo is currently set to 1000 qps, though the actual max
// that we see in the wild is closer to 450 qps.  Regardless, this means that
// the longest time-wait list we should see is 200 seconds * 1000 qps, 200000.
// Of course, there are usually many queries per QUIC connection, so we allow a
// factor of 3 leeway.
//
// Maximum number of connections on the time-wait list. A negative value implies
// no configured limit.
QUIC_FLAG(int64_t, FLAGS_quic_time_wait_list_max_connections, 600000)

// Enables server-side support for QUIC stateless rejects.
QUIC_FLAG(bool, FLAGS_enable_quic_stateless_reject_support, true)

// This flag is not in use, just to keep consistency for shared code.
QUIC_FLAG(bool, FLAGS_quic_always_log_bugs_for_tests, true)

// If true, multipath is enabled for the connection.
QUIC_FLAG(bool, FLAGS_quic_enable_multipath, false)

// If true, require handshake confirmation for QUIC connections, functionally
// disabling 0-rtt handshakes.
// TODO(rtenneti): Enable this flag after CryptoServerTest's are fixed.
QUIC_FLAG(bool, FLAGS_quic_require_handshake_confirmation, false)

// If true, disable pacing in QUIC.
QUIC_FLAG(bool, FLAGS_quic_disable_pacing_for_perf_tests, false)

// If true, QUIC public reset packets will have the \"pre-v33\" public header
// flags.
QUIC_FLAG(bool, FLAGS_quic_use_old_public_reset_packets, true)

// If true, QUIC will use cheap stateless rejects without creating a full
// connection.
QUIC_FLAG(bool, FLAGS_quic_use_cheap_stateless_rejects, true)

// If true, QUIC respect HTTP2 SETTINGS frame rather than always close the
// connection.
QUIC_FLAG(bool, FLAGS_quic_respect_http2_settings_frame, true)

// If true, enables QUIC_VERSION_35.
QUIC_FLAG(bool, FLAGS_quic_enable_version_35, true)

// If true, re-enables QUIC_VERSION_36.
QUIC_FLAG(bool, FLAGS_quic_enable_version_36_v2, true)

// If true, use async codepaths to invoke ProofSource::GetProof.
QUIC_FLAG(bool, FLAGS_enable_async_get_proof, false)

// If true, requires handshake confirmations for all QUIC handshakes with
// versions less than 33.
QUIC_FLAG(bool, FLAGS_quic_require_handshake_confirmation_pre33, false)

// If true, defer creation of new connection till its CHLO arrives.
QUIC_FLAG(bool, FLAGS_quic_buffer_packet_till_chlo, true)

// Disable MTU probing if MTU probe causes ERR_MSG_TOO_BIG instead of aborting
// the connection.
QUIC_FLAG(bool, FLAGS_graceful_emsgsize_on_mtu_probe, true)

// If true, only open limited number of quic sessions per epoll event. Leave the
// rest to next event. This flag can be turned on only if
// --quic_buffer_packet_till_chlo is true.
QUIC_FLAG(bool, FLAGS_quic_limit_num_new_sessions_per_epoll_loop, true)

// If true, lazy allocate and early release memeory used in
// QuicStreamSequencerBuffer to buffer incoming data.
QUIC_FLAG(bool, FLAGS_quic_reduce_sequencer_buffer_memory_life_time, true)

// If true, allow server address change if it is because of mapped ipv4 address.
QUIC_FLAG(bool, FLAGS_quic_allow_server_address_change_for_mapped_ipv4, true)

// If true, disables QUIC version less than 34.
QUIC_FLAG(bool, FLAGS_quic_disable_pre_34, false)

// When true, decode the packet number from the largest received packet, rather
// than the most recent.
QUIC_FLAG(bool, FLAGS_quic_packet_numbers_largest_received, true)

// Only close the connection on the 5th RTO client side when the 5RTO option
// is enabled.
QUIC_FLAG(bool, FLAGS_quic_only_5rto_client_side, true)

// If true, QUIC server push will enabled by default.
QUIC_FLAG(bool, FLAGS_quic_enable_server_push_by_default, true)

// Only inform the QuicSentPacketManager of packets that were sent,
// not those that we tried to send.
QUIC_FLAG(bool, FLAGS_quic_only_track_sent_packets, true)

// If true, connection is closed when packet generator is trying to
// add a frame which alone cannot fit into a packet.
QUIC_FLAG(bool, FLAGS_quic_close_connection_on_huge_frames, true)

// As the Linux kernel does, limit QUIC's Cubic congestion control to
// only increase the CWND 1 packet for every two packets acked.
QUIC_FLAG(bool, FLAGS_quic_limit_cubic_cwnd_increase, true)

// If true, export reject reasons for all rejects, i.e., rejects,
// stateless rejects and cheap stateless rejects.
QUIC_FLAG(bool, FLAGS_quic_export_rej_for_all_rejects, true)

// Allow large send deltas to be used as RTT samples.
QUIC_FLAG(bool, FLAGS_quic_allow_large_send_deltas, true)

// Engage early retransmit anytime the largest acked is greater than
// or equal to the largest retransmittable packet.
QUIC_FLAG(bool, FLAGS_quic_largest_sent_retransmittable, true)

// If true, close connection when sequencer buffer enter into unexpected state.
QUIC_FLAG(bool, FLAGS_quic_stream_sequencer_buffer_debug, true)

// If true, release QuicCryptoStream\'s read buffer when stream are less
// frequently used.
QUIC_FLAG(bool, FLAGS_quic_release_crypto_stream_buffer, false)

// Use a more conservative backoff of 2x instead of 1.5x for handshake
// retransmissions, as well as a larger minimum.
QUIC_FLAG(bool, FLAGS_quic_conservative_handshake_retransmits, true)

// If true, buffer packets while parsing public headers instead of parsing down
// if CHLO is already buffered.
QUIC_FLAG(bool, FLAGS_quic_buffer_packets_after_chlo, false)

// Previously QUIC didn't register a packet as received until it was fully
// processed, but now that flow control is implemented, it can be received once
// decrypted.
QUIC_FLAG(bool, FLAGS_quic_receive_packet_once_decrypted, false)

// If true, enable the Lazy FACK style loss detection in QUIC.
QUIC_FLAG(bool, FLAGS_quic_enable_lazy_fack, true)

// If true, do not override a connection in global map if exists. Only create
// QUIC session if it is successfully inserted to the global map. Toss the
// packet if insertion fails.
QUIC_FLAG(bool, FLAGS_quic_create_session_after_insertion, false)

// If true, rejected packet number is removed from public reset packet.
QUIC_FLAG(bool, FLAGS_quic_remove_packet_number_from_public_reset, false)
