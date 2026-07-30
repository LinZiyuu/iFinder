/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef TASK_MANAGER_H_
#define TASK_MANAGER_H_

#include "nrf_event.hpp"

#include <linux/types.h>
#include <sys/timerfd.h>

using namespace oai::nrf::app;

namespace oai {
namespace nrf {
namespace app {

class nrf_event;
class task_manager {
 public:
  task_manager(nrf_event& ev);
  ~task_manager();

  /*
   * Manage the tasks
   * @param [void]
   * @return void
   */
  void manage_tasks();

  /*
   * Run the tasks (for the moment, simply call function manage_tasks)
   * @param [void]
   * @return void
   */
  void run();

 private:
  /*
   * Make sure that the task tick run every 1ms
   * @param [void]
   * @return void
   */
  void wait_for_cycle();

  nrf_event& event_sub_;
  int sfd;
  bool terminate;
  bool terminated;
};
}  // namespace app
}  // namespace nrf
}  // namespace oai

#endif
