/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_NRF_EVENT_HPP_SEEN
#define FILE_NRF_EVENT_HPP_SEEN

#include <boost/signals2.hpp>
namespace bs2 = boost::signals2;

#include "nrf.h"
#include "nrf_event_sig.hpp"
#include "task_manager.hpp"

namespace oai {
namespace nrf {
namespace app {

class task_manager;
// class nrf_profile;

class nrf_event {
 public:
  nrf_event(){};
  nrf_event(nrf_event const&) = delete;
  void operator=(nrf_event const&) = delete;

  static nrf_event& get_instance() {
    static nrf_event instance;
    return instance;
  }

  // class register/handle event
  friend class nrf_app;
  friend class task_manager;
  friend class nrf_profile;

  /*
   * Subscribe to the task tick event
   * @param [const task_sig_t::slot_type &] sig
   * @param [uint64_t] period: interval between two events
   * @param [uint64_t] start:
   * @return void
   */
  bs2::connection subscribe_task_tick(
      const task_sig_t::slot_type& sig, uint64_t period, uint64_t start = 0);

  /*
   * Subscribe to the extended task tick event
   * @param [const task_sig_t::slot_type &] sig
   * @param [uint64_t] period: interval between two events
   * @param [uint64_t] start:
   * @return void
   */
  bs2::connection subscribe_task_tick_extended(
      const task_sig_t::extended_slot_type& sig, uint64_t period,
      uint64_t start = 0);

  /*
   * Subscribe to the nf status change event
   * @param [const task_sig_t::slot_type &] sig
   * @param [uint64_t] period: interval between two events
   * @param [uint64_t] start:
   * @return void
   */
  bs2::connection subscribe_nf_status_change(
      const nf_status_change_sig_t::slot_type& sig);

  bs2::connection subscribe_nf_status_registered(
      const nf_status_sig_t::slot_type& sig);

  bs2::connection subscribe_nf_status_deregistered(
      const nf_deregistered_sig_t::slot_type& sig);

  bs2::connection subscribe_nf_status_profile_changed(
      const nf_status_sig_t::slot_type& sig);

 private:
  task_sig_t task_tick;
  nf_status_change_sig_t nf_status_change;
  nf_status_sig_t nf_status_registered;
  nf_deregistered_sig_t nf_status_deregistered;
  nf_status_sig_t nf_status_profile_changed;
};
}  // namespace app
}  // namespace nrf
}  // namespace oai

#endif /* FILE_NRF_EVENT_HPP_SEEN */
