// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/core/quic_version_manager.h"

#include "net/quic/core/quic_flags.h"
#include "net/quic/core/quic_versions.h"

namespace net {

QuicVersionManager::QuicVersionManager(QuicVersionVector supported_versions)
    : enable_version_38_(FLAGS_quic_enable_version_38),
      enable_version_37_(FLAGS_quic_reloadable_flag_quic_enable_version_37),
      enable_version_36_(FLAGS_quic_reloadable_flag_quic_enable_version_36_v3),
      disable_version_34_(FLAGS_quic_reloadable_flag_quic_disable_version_34),
      allowed_supported_versions_(supported_versions),
      filtered_supported_versions_(
          FilterSupportedVersions(supported_versions)) {}

QuicVersionManager::~QuicVersionManager() {}

const QuicVersionVector& QuicVersionManager::GetSupportedVersions() {
  MaybeRefilterSupportedVersions();
  return filtered_supported_versions_;
}

void QuicVersionManager::MaybeRefilterSupportedVersions() {
  if (enable_version_38_ != FLAGS_quic_enable_version_38 ||
      enable_version_37_ != FLAGS_quic_reloadable_flag_quic_enable_version_37 ||
      enable_version_36_ !=
          FLAGS_quic_reloadable_flag_quic_enable_version_36_v3 ||
      disable_version_34_ !=
          FLAGS_quic_reloadable_flag_quic_disable_version_34) {
    enable_version_38_ = FLAGS_quic_enable_version_38;
    enable_version_37_ = FLAGS_quic_reloadable_flag_quic_enable_version_37;
    enable_version_36_ = FLAGS_quic_reloadable_flag_quic_enable_version_36_v3;
    disable_version_34_ = FLAGS_quic_reloadable_flag_quic_disable_version_34;
    RefilterSupportedVersions();
  }
}

void QuicVersionManager::RefilterSupportedVersions() {
  filtered_supported_versions_ =
      FilterSupportedVersions(allowed_supported_versions_);
}

}  // namespace net
