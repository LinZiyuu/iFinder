/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_UDR_EVENT_HPP_SEEN
#define FILE_UDR_EVENT_HPP_SEEN

#include <boost/signals2.hpp>
namespace bs2 = boost::signals2;

#include "task_manager.hpp"
#include "udr.h"
#include "udr_event_sig.hpp"

namespace oai::udr::app {
class task_manager;
class udr_event {
 public:
  udr_event(){};
  udr_event(udr_event const&) = delete;
  void operator=(udr_event const&) = delete;

  static udr_event& get_instance() {
    static udr_event instance;
    return instance;
  }

  // class register/handle event
  friend class udr_app;
  friend class udr_nrf;
  friend class task_manager;

  //------------------------------------------------------------------------------
  /*
   * Subscribe to the task tick event
   * @param [const task_sig_t::slot_type &] sig
   * @param [uint64_t] period: interval between two events
   * @param [uint64_t] start:
   * @return void
   */
  bs2::connection subscribe_task_nf_heartbeat(
      const task_sig_t::slot_type& sig, uint64_t period, uint64_t start = 0);

  /*
   * Subscribe to the task db connection reset event
   * @param [const db_connection_sig_t::slot_type &] sig
   * @param [uint64_t] period: interval between two events
   * @param [uint64_t] start:
   * @return void
   */
  // bs2::connection subscribe_task_db_connection_reset(
  //    const db_connection_sig_t::slot_type& sig, uint64_t period,
  //    uint64_t start = 0);

 private:
  task_sig_t task_tick;
  // db_connection_sig_t db_connection_sig;
};
}  // namespace oai::udr::app
#endif
