// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file intentionally does not have header guards, it's included
// inside a macro to generate values.

// This file contains the list of QUIC protocol flags.

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
QUIC_FLAG(bool,
          FLAGS_quic_reloadable_flag_enable_quic_stateless_reject_support,
          true)

// If true, require handshake confirmation for QUIC connections, functionally
// disabling 0-rtt handshakes.
// TODO(rtenneti): Enable this flag after CryptoServerTest's are fixed.
QUIC_FLAG(bool,
          FLAGS_quic_reloadable_flag_quic_require_handshake_confirmation,
          false)

// If true, disable pacing in QUIC.
QUIC_FLAG(bool, FLAGS_quic_disable_pacing_for_perf_tests, false)

// If true, QUIC public reset packets will have the \"pre-v33\" public header
// flags.
QUIC_FLAG(bool,
          FLAGS_quic_reloadable_flag_quic_use_old_public_reset_packets,
          true)

// If true, QUIC will use cheap stateless rejects without creating a full
// connection.
QUIC_FLAG(bool,
          FLAGS_quic_reloadable_flag_quic_use_cheap_stateless_rejects,
          true)

// If true, QUIC respect HTTP2 SETTINGS frame rather than always close the
// connection.
QUIC_FLAG(bool,
          FLAGS_quic_reloadable_flag_quic_respect_http2_settings_frame,
          true)

// If true, only open limited number of quic sessions per epoll event. Leave the
// rest to next event.
QUIC_FLAG(bool,
          FLAGS_quic_reloadable_flag_quic_limit_num_new_sessions_per_epoll_loop,
          true)

// If true, release QuicCryptoStream\'s read buffer when stream are less
// frequently used.
QUIC_FLAG(bool,
          FLAGS_quic_reloadable_flag_quic_release_crypto_stream_buffer,
          true)

// If true, v33 QUIC client uses 1 bit to specify 8-byte connection id in
// public flag.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_remove_v33_hacks2, false)

// If true, allows packets to be buffered in anticipation of a future CHLO, and
// allow CHLO packets to be buffered until next iteration of the event loop.
QUIC_FLAG(bool, FLAGS_quic_allow_chlo_buffering, true)

// If true, GFE sends SETTINGS_MAX_HEADER_LIST_SIZE to the client at the
// beginning of a connection.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_send_max_header_list_size, true)

// If greater than zero, mean RTT variation is multiplied by the specified
// factor and added to the congestion window limit.
QUIC_FLAG(double, FLAGS_quic_bbr_rtt_variation_weight, 0.0f)

// Congestion window gain for QUIC BBR during PROBE_BW phase.
QUIC_FLAG(double, FLAGS_quic_bbr_cwnd_gain, 2.0f)

// If true, do not send or process stop waiting frames in QUIC if the NSTP
// connection option is provided.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_no_stop_waiting_frames, false)

// Allows one self address change.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_allow_one_address_change, false)

// Support bandwidth resumption in QUIC BBR.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_bbr_bandwidth_resumption, false)

// Add the equivalent number of bytes as 3 TCP TSO segments to QUIC's BBR CWND.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_bbr_add_tso_cwnd, false)

// If true, enable version 38 which supports new PADDING frame and respects NSTP
// connection option.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_enable_version_38, true)

// If true, enable QUIC v39.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_enable_version_39, true)

// Simplify QUIC\'s adaptive time loss detection to measure the necessary
// reordering window for every spurious retransmit.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_fix_adaptive_time_loss, false)

// If true, enable random padding of size [1, 256] when response body is
// compressed for QUIC version >= 38.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_enable_random_padding, true)

// If enabled, use refactored stream creation methods.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_refactor_stream_creation, false)

// If true, GFEs generate and validate source address token using the actual
// client IP for proxied session.
QUIC_FLAG(bool,
          FLAGS_quic_reloadable_flag_quic_use_client_address_for_stk_in_proxy,
          true)

// If true, export a varz mapping QUIC non 0-rtt handshake with corresponding
// frontend service.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_account_handshake, false)

// Allows the 3RTO QUIC connection option to close a QUIC connection after
// 3RTOs if there are no open streams.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_enable_3rtos, false)

// If true, enable experiment for testing PCC congestion-control.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_enable_pcc, false)

// If true, enable QUIC v40.
QUIC_FLAG(bool, FLAGS_quic_enable_version_40, false)

// If true, use the more CPU efficient bandwidth sampler datastructure.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_faster_bandwidth_sampler, true)

// In QUIC, QuicSession gets notified when stream frames are acked, discarded or
// retransmitted.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_use_stream_notifier2, false)

// When true, defaults to BBR congestion control instead of Cubic.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_default_to_bbr, false)

// If true, stream sent data is saved in streams rather than stream frames.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_stream_owns_data, false)

// Allow a new rate based recovery in QUIC BBR to be enabled via connection
// option.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_bbr_rate_recovery, false)

// If true, allow trailing headers with duplicate keys, and combine the values
// from duplicate keys into a single delimted header.
QUIC_FLAG(bool,
          FLAGS_quic_reloadable_flag_quic_handle_duplicate_trailers,
          false)

// Allows QUIC BBR up to twice the previously measured ack aggregation to be
// added to the CWND as long as bytes_in_flight goes below the target recently.
QUIC_FLAG(bool,
          FLAGS_quic_reloadable_flag_quic_bbr_ack_aggregation_bytes2,
          false)

// If true, disables support for QUIC version 36.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_disable_version_36, false)

// If true, disables support for the packets-based QUIC congestion control
// algorithms.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_disable_packets_based_cc, false)

// When enabled, adds up to 1.5x the previously measured ack aggregation in
// bytes to the CWND, but reduces that amount by 1/2 the bytes acked since the
// queue was drained.
QUIC_FLAG(bool,
          FLAGS_quic_reloadable_flag_quic_bbr_ack_aggregation_bytes3,
          false)

// When enabled, ack frame uses a deque internally instead of a set.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_frames_deque, false)

// If true, server supported versions is updated before SelectMutualVersion.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_to_backend_multi_version, true)

// If true, QUIC packet creator passes a stack allocated SerializedPacket to the
// connection.
QUIC_FLAG(bool,
          FLAGS_quic_reloadable_flag_quic_clear_packet_before_handed_over,
          false)

// If true, enable QUIC v41.
QUIC_FLAG(bool, FLAGS_quic_enable_version_41, false)

// Small optimization for QuicSentPacketManager::HandleAckForSentPackets.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_handle_acks, false)

// When true, respect configured limits on header list size.
QUIC_FLAG(bool, FLAGS_quic_restart_flag_quic_header_list_size, false)

// When true, allows the LRTT connection option to cause QUIC BBR to exit
// STARTUP when in recovery and there has been no bandwidth increase for 1RTT.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_bbr_exit_startup_on_loss, false)
