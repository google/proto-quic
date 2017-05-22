// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file intentionally does not have header guards, it's included
// inside a macro to generate values.

// This file contains the list of QUIC protocol flags.

// If true, QUIC BBR congestion control may be enabled via Finch and/or via QUIC
// connection options.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_allow_new_bbr, true)

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

// If true, multipath is enabled for the connection.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_enable_multipath, false)

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

// If true, QUIC server push will enabled by default.
QUIC_FLAG(bool,
          FLAGS_quic_reloadable_flag_quic_enable_server_push_by_default,
          true)

// If true, release QuicCryptoStream\'s read buffer when stream are less
// frequently used.
QUIC_FLAG(bool,
          FLAGS_quic_reloadable_flag_quic_release_crypto_stream_buffer,
          true)

// If true, do not override a connection in global map if exists. Only create
// QUIC session if it is successfully inserted to the global map. Toss the
// packet if insertion fails.
QUIC_FLAG(bool,
          FLAGS_quic_reloadable_flag_quic_create_session_after_insertion,
          false)

// If true, v33 QUIC client uses 1 bit to specify 8-byte connection id in
// public flag.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_remove_v33_hacks2, false)

// Enable QUIC force HOL blocking experiment.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_enable_force_hol_blocking, true)

// If true, allows packets to be buffered in anticipation of a future CHLO, and
// allow CHLO packets to be buffered until next iteration of the event loop.
QUIC_FLAG(bool, FLAGS_quic_allow_chlo_buffering, true)

// If true, fix some casts that were causing off-by-one errors in QUIC's cubic
// "convex" increases.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_fix_cubic_convex_mode, true)

// If true, GFE sends SETTINGS_MAX_HEADER_LIST_SIZE to the client at the
// beginning of a connection.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_send_max_header_list_size, true)

// If true, fix quantization of CubicBytes while performing convex increases.
QUIC_FLAG(bool,
          FLAGS_quic_reloadable_flag_quic_fix_cubic_bytes_quantization,
          true)

// If true, fix Cubic\'s use of kBetaLastMax for n-connection emulation.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_fix_beta_last_max, true)

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

// If true, multipath bit is not used in public flag.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_remove_multipath_bit, true)

// Allow QUIC's flow control autotuning to increase the window as
// quickly for the first adjustment as in subsequent ones.
QUIC_FLAG(bool,
          FLAGS_quic_reloadable_flag_quic_flow_control_faster_autotune,
          true)

// If true, QUIC BBR stores a max filtered number of bytes delivered at a rate
// faster than the sending rate.
QUIC_FLAG(bool,
          FLAGS_quic_reloadable_flag_quic_bbr_ack_aggregation_bytes,
          false)

// If true, allow cubic updates on every ack, rather than occasionally limiting
// the frequency to once every 30ms.
QUIC_FLAG(bool,
          FLAGS_quic_reloadable_flag_quic_enable_cubic_per_ack_updates,
          true)

// Support bandwidth resumption in QUIC BBR.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_bbr_bandwidth_resumption, false)

// Add the equivalent number of bytes as 3 TCP TSO segments to QUIC's BBR CWND.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_bbr_add_tso_cwnd, false)

// If true, enable version 38 which supports new PADDING frame and respects NSTP
// connection option.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_enable_version_38, true)

// If true, enable QUIC v39.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_enable_version_39, true)

// If true, on client side, 8-byte connection ID in public header is read and
// written in big endian.
QUIC_FLAG(bool,
          FLAGS_quic_restart_flag_quic_big_endian_connection_id_client,
          false)

// If true, on server side, 8-byte connection ID in public header is read and
// written in big endian.
QUIC_FLAG(bool,
          FLAGS_quic_restart_flag_quic_big_endian_connection_id_server,
          false)

// Simplify QUIC\'s adaptive time loss detection to measure the necessary
// reordering window for every spurious retransmit.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_fix_adaptive_time_loss, false)

// If true, enable random padding of size [1, 256] when response body is
// compressed for QUIC version >= 38.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_enable_random_padding, false)

// Use conservation in PROBE_BW ouside of super-unity gain and immediately
// preceeding cycle.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_bbr_extra_conservation, false)

// Increase BBR's inflight limit if recent ack rate is low.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_bbr_slow_recent_delivery, false)

// Congestion window gain for QUIC BBR during slow delivery.
QUIC_FLAG(double, FLAGS_quic_bbr_slow_delivery_cwnd_gain, 4.0f)

// Threshold multiplier below which delivery is considered slow.
QUIC_FLAG(double, FLAGS_quic_bbr_slow_delivery_threshold_multiplier, 0.5f)

// If true, update state if trailing headers with a :final-offset key are
// received for a previously closed QUIC stream.
QUIC_FLAG(bool,
          FLAGS_quic_reloadable_flag_quic_final_offset_from_trailers,
          false)

// Fix the algorithm used by packet conservation.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_bbr_fix_conservation, false)

// If enabled, use refactored stream creation methods.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_refactor_stream_creation, false)

// A second take on fixing QUIC BBR packet conservation.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_bbr_fix_conservation2, false)

// If true, GFEs generate and validate source address token using the actual
// client IP for proxied session.
QUIC_FLAG(bool,
          FLAGS_quic_reloadable_flag_quic_use_client_address_for_stk_in_proxy,
          false)

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
