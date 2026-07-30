/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_LMF_EVENT_SIG_HPP_SEEN
#define FILE_LMF_EVENT_SIG_HPP_SEEN

#include <boost/signals2.hpp>
#include <string>

namespace bs2 = boost::signals2;

namespace oai::lmf::app {

typedef bs2::signal_type<
    void(uint64_t), bs2::keywords::mutex_type<bs2::dummy_mutex>>::type
    task_sig_t;

}  // namespace oai::lmf::app
#endif
