/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef TASK_MANAGER_H_
#define TASK_MANAGER_H_

#include <linux/types.h>
#include <sys/timerfd.h>

#include "udr_event.hpp"

namespace oai {
namespace udr {
namespace app {

class udr_event;
class task_manager {
 public:
  task_manager(udr_event& ev);
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

  udr_event& event_sub_;
  int sfd;
  bool terminate;
  bool terminated;
};
}  // namespace app
}  // namespace udr
}  // namespace oai

#endif
