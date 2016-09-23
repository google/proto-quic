// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_ANDROID_NETWORK_CHANGE_NOTIFIER_ANDROID_H_
#define NET_ANDROID_NETWORK_CHANGE_NOTIFIER_ANDROID_H_

#include <memory>

#include "base/android/jni_android.h"
#include "base/compiler_specific.h"
#include "base/macros.h"
#include "net/android/network_change_notifier_delegate_android.h"
#include "net/base/network_change_notifier.h"

namespace net {

struct DnsConfig;
class NetworkChangeNotifierAndroidTest;
class NetworkChangeNotifierFactoryAndroid;

// NetworkChangeNotifierAndroid observes network events from the Android
// notification system and forwards them to observers.
//
// The implementation is complicated by the differing lifetime and thread
// affinity requirements of Android notifications and of NetworkChangeNotifier.
//
// High-level overview:
// NetworkChangeNotifier.java - Receives notifications from Android system, and
// notifies native code via JNI (on the main application thread).
// NetworkChangeNotifierDelegateAndroid ('Delegate') - Listens for notifications
//   sent via JNI on the main application thread, and forwards them to observers
//   on their threads. Owned by Factory, lives exclusively on main application
//   thread.
// NetworkChangeNotifierFactoryAndroid ('Factory') - Creates the Delegate on the
//   main thread to receive JNI events, and vends Notifiers. Lives exclusively
//   on main application thread, and outlives all other classes.
// NetworkChangeNotifierAndroid ('Notifier') - Receives event notifications from
//   the Delegate. Processes and forwards these events to the
//   NetworkChangeNotifier observers on their threads. May live on any thread
//   and be called by any thread.
//
// For more details, see the implementation file.
class NET_EXPORT_PRIVATE NetworkChangeNotifierAndroid
    : public NetworkChangeNotifier,
      public NetworkChangeNotifierDelegateAndroid::Observer {
 public:
  ~NetworkChangeNotifierAndroid() override;

  // NetworkChangeNotifier:
  ConnectionType GetCurrentConnectionType() const override;
  // Requires ACCESS_WIFI_STATE permission in order to provide precise WiFi link
  // speed.
  void GetCurrentMaxBandwidthAndConnectionType(
      double* max_bandwidth_mbps,
      ConnectionType* connection_type) const override;
  bool AreNetworkHandlesCurrentlySupported() const override;
  void GetCurrentConnectedNetworks(NetworkList* network_list) const override;
  ConnectionType GetCurrentNetworkConnectionType(
      NetworkHandle network) const override;
  NetworkHandle GetCurrentDefaultNetwork() const override;

  // NetworkChangeNotifierDelegateAndroid::Observer:
  void OnConnectionTypeChanged() override;
  void OnMaxBandwidthChanged(double max_bandwidth_mbps,
                             ConnectionType type) override;
  void OnNetworkConnected(NetworkHandle network) override;
  void OnNetworkSoonToDisconnect(NetworkHandle network) override;
  void OnNetworkDisconnected(NetworkHandle network) override;
  void OnNetworkMadeDefault(NetworkHandle network) override;

  static bool Register(JNIEnv* env);

  // Promote GetMaxBandwidthForConnectionSubtype to public for the Android
  // delegate class.
  using NetworkChangeNotifier::GetMaxBandwidthForConnectionSubtype;

 protected:
  void OnFinalizingMetricsLogRecord() override;

 private:
  friend class NetworkChangeNotifierAndroidTest;
  friend class NetworkChangeNotifierFactoryAndroid;

  class DnsConfigServiceThread;

  // Enable NetworkHandles support for tests.
  void ForceNetworkHandlesSupportedForTesting();

  NetworkChangeNotifierAndroid(NetworkChangeNotifierDelegateAndroid* delegate,
                               const DnsConfig* dns_config_for_testing);

  static NetworkChangeCalculatorParams NetworkChangeCalculatorParamsAndroid();

  NetworkChangeNotifierDelegateAndroid* const delegate_;
  std::unique_ptr<DnsConfigServiceThread> dns_config_service_thread_;
  bool force_network_handles_supported_for_testing_;

  DISALLOW_COPY_AND_ASSIGN(NetworkChangeNotifierAndroid);
};

}  // namespace net

#endif  // NET_ANDROID_NETWORK_CHANGE_NOTIFIER_ANDROID_H_
