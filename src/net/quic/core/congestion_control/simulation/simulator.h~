// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_QUIC_CORE_CONGESTION_CONTROL_SIMULATION_SIMULATOR_H_
#define NET_QUIC_CORE_CONGESTION_CONTROL_SIMULATION_SIMULATOR_H_

#include <map>
#include <unordered_map>
#include <unordered_set>

#include "net/quic/core/congestion_control/simulation/actor.h"
#include "net/quic/core/congestion_control/simulation/alarm_factory.h"
#include "net/quic/core/quic_bug_tracker.h"
#include "net/quic/core/quic_connection.h"
#include "net/quic/core/quic_simple_buffer_allocator.h"

namespace net {
namespace simulation {

// Simulator is responsible for scheduling actors in the simulation and
// providing basic utility interfaces (clock, alarms, RNG and others).
class Simulator : public QuicConnectionHelperInterface {
 public:
  Simulator();
  ~Simulator() override;

  // Register an actor with the simulator.  Returns a handle which the actor can
  // use to schedule and unschedule itself.
  void AddActor(Actor* actor);

  // Schedule the specified actor.  This method will ensure that |actor| is
  // called at |new_time| at latest.  If Schedule() is called multiple times
  // before the Actor is called, Act() is called exactly once, at the earliest
  // time requested, and the Actor has to reschedule itself manually for the
  // subsequent times if they are still necessary.
  void Schedule(Actor* actor, QuicTime new_time);

  // Remove the specified actor from the schedule.
  void Unschedule(Actor* actor);

  // Begin QuicConnectionHelperInterface implementation.
  const QuicClock* GetClock() const override;
  QuicRandom* GetRandomGenerator() override;
  QuicBufferAllocator* GetBufferAllocator() override;
  // End QuicConnectionHelperInterface implementation.

  QuicAlarmFactory* GetAlarmFactory();

  // Run the simulation until either no actors are scheduled or
  // |termination_predicate| returns true.  Returns true if terminated due to
  // predicate, and false otherwise.
  template <class TerminationPredicate>
  bool RunUntil(TerminationPredicate termination_predicate);

 private:
  class Clock : public QuicClock {
   public:
    // Do not start at zero as certain code can treat zero as an invalid
    // timestamp.
    const QuicTime kStartTime =
        QuicTime::Zero() + QuicTime::Delta::FromMicroseconds(1);

    Clock();

    QuicTime ApproximateNow() const override;
    QuicTime Now() const override;
    QuicWallTime WallNow() const override;

    QuicTime now_;
  };

  // Finds the next scheduled actor, advances time to the schedule time and
  // notifies the actor.
  void HandleNextScheduledActor();

  Clock clock_;
  QuicRandom* random_generator_;
  SimpleBufferAllocator buffer_allocator_;
  AlarmFactory alarm_factory_;

  // Schedule of when the actors will be executed via an Act() call.  The
  // schedule is subject to the following invariants:
  // - An actor cannot be scheduled for a later time than it's currently in the
  //   schedule.
  // - An actor is removed from schedule either immediately before Act() is
  //   called or by explicitly calling Unschedule().
  // - Each Actor appears in the map at most once.
  std::multimap<QuicTime, Actor*> schedule_;
  // For each actor, maintain the time it is scheduled at.  The value for
  // unscheduled actors is QuicTime::Infinite().
  std::unordered_map<Actor*, QuicTime> scheduled_times_;
  std::unordered_set<std::string> actor_names_;

  DISALLOW_COPY_AND_ASSIGN(Simulator);
};

template <class TerminationPredicate>
bool Simulator::RunUntil(TerminationPredicate termination_predicate) {
  while (!schedule_.empty()) {
    if (termination_predicate()) {
      return true;
    }
    HandleNextScheduledActor();
  }
  return false;
}

}  // namespace simulation
}  // namespace net

#endif  // NET_QUIC_CORE_CONGESTION_CONTROL_SIMULATION_SIMULATOR_H_
