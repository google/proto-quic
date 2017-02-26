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

// If true, re-enables QUIC_VERSION_36.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_enable_version_36_v3, true)

// If true, only open limited number of quic sessions per epoll event. Leave the
// rest to next event.
QUIC_FLAG(bool,
          FLAGS_quic_reloadable_flag_quic_limit_num_new_sessions_per_epoll_loop,
          true)

// If true, QUIC server push will enabled by default.
QUIC_FLAG(bool,
          FLAGS_quic_reloadable_flag_quic_enable_server_push_by_default,
          true)

// Allow large send deltas to be used as RTT samples.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_allow_large_send_deltas, true)

// If true, release QuicCryptoStream\'s read buffer when stream are less
// frequently used.
QUIC_FLAG(bool,
          FLAGS_quic_reloadable_flag_quic_release_crypto_stream_buffer,
          true)

// Use a more conservative backoff of 2x instead of 1.5x for handshake
// retransmissions, as well as a larger minimum.
QUIC_FLAG(bool,
          FLAGS_quic_reloadable_flag_quic_conservative_handshake_retransmits,
          false)

// If true, buffer packets while parsing public headers instead of parsing down
// if CHLO is already buffered.
QUIC_FLAG(bool,
          FLAGS_quic_reloadable_flag_quic_buffer_packets_after_chlo,
          false)

// If true, enable the Lazy FACK style loss detection in QUIC.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_enable_lazy_fack, true)

// If true, do not override a connection in global map if exists. Only create
// QUIC session if it is successfully inserted to the global map. Toss the
// packet if insertion fails.
QUIC_FLAG(bool,
          FLAGS_quic_reloadable_flag_quic_create_session_after_insertion,
          false)

// If true, rejected packet number is removed from public reset packet.
QUIC_FLAG(
    bool,
    FLAGS_quic_reloadable_flag_quic_remove_packet_number_from_public_reset,
    false)

// If true, v33 QUIC client uses 1 bit to specify 8-byte connection id in
// public flag.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_remove_v33_hacks2, false)

// If true, limits QUIC uncompressed headers to 16K.
QUIC_FLAG(bool,
          FLAGS_quic_reloadable_flag_quic_limit_uncompressed_headers,
          false)

// If true, release headers stream\'s sequencer buffer when there is no active
// stream.
QUIC_FLAG(
    bool,
    FLAGS_quic_reloadable_flag_quic_headers_stream_release_sequencer_buffer,
    true)

// Enable QUIC force HOL blocking experiment.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_enable_force_hol_blocking, true)

// If true, allows packets to be buffered in anticipation of a future CHLO, and
// allow CHLO packets to be buffered until next iteration of the event loop.
QUIC_FLAG(bool, FLAGS_quic_allow_chlo_buffering, true)

// Add a new client connection options field to QuicOptions which is only used
// to configure client side features, such as congestion control.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_client_connection_options, true)

// If true, fix some casts that were causing off-by-one errors in QUIC's cubic
// "convex" increases.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_fix_cubic_convex_mode, false)

// If true, GFE sends SETTINGS_MAX_HEADER_LIST_SIZE to the client at the
// beginning of a connection.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_send_max_header_list_size, true)

// If true, fix quantization of CubicBytes while performing convex increases.
QUIC_FLAG(bool,
          FLAGS_quic_reloadable_flag_quic_fix_cubic_bytes_quantization,
          false)

// If true, QUIC cubic code will use the event time when adjusting CWND after an
// ACK instead of the clock\'s current approximate time.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_use_event_time, true)

// If true, lazy allocate and early release memeory used in
// QuicStreamSequencerBuffer to buffer incoming data.
QUIC_FLAG(
    bool,
    FLAGS_quic_reloadable_flag_quic_reduce_sequencer_buffer_memory_life_time,
    true)

// If true, Makes GFE respect the connection options for initial flow control
// window larger than 32 KB.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_large_ifw_options, true)

// If true, fix Cubic\'s use of kBetaLastMax for n-connection emulation.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_fix_beta_last_max, false)

// If true, enable QUIC v37.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_enable_version_37, true)

// If true, disables QUIC v34.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_disable_version_34, true)

// Allow quic to properly support proxying 100 Continue responses.
QUIC_FLAG(bool, FLAGS_quic_restart_flag_quic_supports_100_continue, false)

// If true, enable quic version 38
QUIC_FLAG(bool, FLAGS_quic_enable_version_38, false)

// When true, ensures the session's flow control window is always at least 1.5x
// larger than the largest stream flow control window.
QUIC_FLAG(bool, FLAGS_quic_reloadable_flag_quic_flow_control_invariant, false)

// If greater than zero, mean RTT variation is multiplied by the specified
// factor and added to the congestion window limit.
QUIC_FLAG(double, FLAGS_quic_bbr_rtt_variation_weight, 0.0f)

// Congestion window gain for QUIC BBR during PROBE_BW phase.
QUIC_FLAG(double, FLAGS_quic_bbr_cwnd_gain, 2.0f)

// If true, bidi streaming is always enabled in QUIC.
QUIC_FLAG(bool,
          FLAGS_quic_reloadable_flag_quic_always_enable_bidi_streaming,
          false)
