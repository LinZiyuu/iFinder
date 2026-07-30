/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_UDR_EVENT_SIG_HPP_SEEN
#define FILE_UDR_EVENT_SIG_HPP_SEEN

#include <boost/signals2.hpp>
#include <string>

#include "database_wrapper_abstraction.hpp"

namespace bs2 = boost::signals2;

namespace oai::udr::app {

typedef bs2::signal_type<
    void(uint64_t), bs2::keywords::mutex_type<bs2::dummy_mutex>>::type
    task_sig_t;

// typedef bs2::signal_type<
//    void(uint64_t, std::shared_ptr<database_wrapper_abstraction>&),
//    bs2::keywords::mutex_type<bs2::dummy_mutex>>::type db_connection_sig_t;

}  // namespace oai::udr::app
#endif
