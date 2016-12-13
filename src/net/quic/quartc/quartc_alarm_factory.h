// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_QUARTC_QUARTC_ALARM_FACTORY_H_
#define NET_QUIC_QUARTC_QUARTC_ALARM_FACTORY_H_

#include <utility>

#include "net/quic/core/quic_alarm_factory.h"
#include "net/quic/platform/api/quic_clock.h"
#include "net/quic/platform/api/quic_export.h"

namespace base {
class TaskRunner;
}  // namespace base

namespace net {

// Creates Chromium-based QuartcAlarms used throughout QUIC. The alarm posts
// messages to the Chromium message queue for tasks such as retransmission.
// Used for the tests inside Chromium.
class QUIC_EXPORT_PRIVATE QuartcAlarmFactory : public QuicAlarmFactory {
 public:
  QuartcAlarmFactory(base::TaskRunner* task_runner, const QuicClock* clock);
  ~QuartcAlarmFactory() override;

  QuicAlarm* CreateAlarm(QuicAlarm::Delegate* delegate) override;

  QuicArenaScopedPtr<QuicAlarm> CreateAlarm(
      QuicArenaScopedPtr<QuicAlarm::Delegate> delegate,
      QuicConnectionArena* arena) override;

 private:
  base::TaskRunner* task_runner_;
  // Not owned by QuartcAlarmFactory. The implementation of
  // QuicConnectionHelperInterface owns it.
  const QuicClock* clock_;

  DISALLOW_COPY_AND_ASSIGN(QuartcAlarmFactory);
};

}  // namespace net

#endif  // NET_QUIC_QUARTC_QUARTC_ALARM_FACTORY_H_
