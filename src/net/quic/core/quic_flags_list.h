// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file intentionally does not have header guards, it's included
// inside a macro to generate values.

// This file contains the list of QUIC protocol flags.

// If true, QUIC BBR congestion control may be enabled via Finch and/or via QUIC
// connection options.
QUIC_FLAG(bool, FLAGS_quic_allow_new_bbr, true)

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

// If true, re-enables QUIC_VERSION_36.
QUIC_FLAG(bool, FLAGS_quic_enable_version_36_v3, false)

// If true, use async codepaths to invoke ProofSource::GetProof.
QUIC_FLAG(bool, FLAGS_enable_async_get_proof, false)

// If true, only open limited number of quic sessions per epoll event. Leave the
// rest to next event.
QUIC_FLAG(bool, FLAGS_quic_limit_num_new_sessions_per_epoll_loop, true)

// Only close the connection on the 5th RTO client side when the 5RTO option
// is enabled.
QUIC_FLAG(bool, FLAGS_quic_only_5rto_client_side, false)

// If true, QUIC server push will enabled by default.
QUIC_FLAG(bool, FLAGS_quic_enable_server_push_by_default, true)

// If true, export reject reasons for all rejects, i.e., rejects,
// stateless rejects and cheap stateless rejects.
QUIC_FLAG(bool, FLAGS_quic_export_rej_for_all_rejects, true)

// Allow large send deltas to be used as RTT samples.
QUIC_FLAG(bool, FLAGS_quic_allow_large_send_deltas, true)

// Engage early retransmit anytime the largest acked is greater than
// or equal to the largest retransmittable packet.
QUIC_FLAG(bool, FLAGS_quic_largest_sent_retransmittable, true)

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

// If true, v33 QUIC client uses 1 bit to specify 8-byte connection id in
// public flag.
QUIC_FLAG(bool, FLAGS_quic_remove_v33_hacks2, false)

// If true, limits QUIC uncompressed headers to 16K.
QUIC_FLAG(bool, FLAGS_quic_limit_uncompressed_headers, false)

// If true, release headers stream\'s sequencer buffer when there is no active
// stream.
QUIC_FLAG(bool, FLAGS_quic_headers_stream_release_sequencer_buffer, false)

// Default enable QUIC's Cubic in bytes implementation instead of
// Cubic in packets.
QUIC_FLAG(bool, FLAGS_quic_default_enable_cubic_bytes, true)

// Set the retransmission alarm only when there are unacked
// retransmittable packets.
QUIC_FLAG(bool, FLAGS_quic_more_conservative_retransmission_alarm, true)

// Enable QUIC force HOL blocking experiment.
QUIC_FLAG(bool, FLAGS_quic_enable_force_hol_blocking, true)

// If true, allows packets to be buffered in anticipation of a future CHLO, and
// allow CHLO packets to be buffered until next iteration of the event loop.
QUIC_FLAG(bool, FLAGS_quic_allow_chlo_buffering, true)

// If true, fix version manager bug, in which version flag does not really
// help.
QUIC_FLAG(bool, FLAGS_quic_fix_version_manager, false)

// Add a new client connection options field to QuicOptions which is only used
// to configure client side features, such as congestion control.
QUIC_FLAG(bool, FLAGS_quic_client_connection_options, true)

// If true, fix some casts that were causing off-by-one errors in QUIC's cubic
// "convex" increases.
QUIC_FLAG(bool, FLAGS_quic_fix_cubic_convex_mode, false)

// Ensure that BBR startup pacing rate does not drop below the initial one.
QUIC_FLAG(bool, FLAGS_quic_bbr_faster_startup, false)
