/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_THREAD_SCHED_HPP_SEEN
#define FILE_THREAD_SCHED_HPP_SEEN

#include <sched.h>
#include "logger_base.hpp"

namespace oai::utils {

class thread_sched_params {
 public:
  thread_sched_params()
      : cpu_id(0),
        sched_policy(SCHED_FIFO),
        sched_priority(84),
        thread_pool_size(1) {}
  int cpu_id;
  int sched_policy;
  int sched_priority;
  unsigned int thread_pool_size;
  void apply(const int task_id, const oai::logger::printf_logger& logger) const;
};

}  // namespace oai::utils
#endif /* FILE_THREAD_SCHED_HPP_SEEN */
