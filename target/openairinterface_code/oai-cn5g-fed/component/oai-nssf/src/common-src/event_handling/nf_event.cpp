/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "nf_event.hpp"

using namespace oai::event_handling;

//------------------------------------------------------------------------------
bs2::connection nf_event::subscribe_task_nf_heartbeat(
    const task_sig_t::slot_type& sig, uint64_t period, uint64_t start) {
  /* Wrap the actual callback in a lambda. The latter checks whether the
   * current time is after start time, and ensures that the callback is only
   * called every X ms with X being the period time. This way, it is possible
   * to register to be notified every X ms instead of every ms, which provides
   * greater freedom to implementations. */
  auto f = [period, start, sig](uint64_t t) {
    if (t >= start && (t - start) % period == 0) sig(t);
  };
  return task_tick.connect(f);
}
