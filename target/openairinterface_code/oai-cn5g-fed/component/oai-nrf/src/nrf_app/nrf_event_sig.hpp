/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_NRF_EVENT_SIG_HPP_SEEN
#define FILE_NRF_EVENT_SIG_HPP_SEEN

#include <boost/signals2.hpp>

namespace bs2 = boost::signals2;

namespace oai {
namespace nrf {
namespace app {

class nrf_profile;

typedef bs2::signal_type<
    void(uint64_t), bs2::keywords::mutex_type<bs2::mutex>>::type task_sig_t;

// Signal for NF Status
// Subscription ID, NF Status
typedef bs2::signal_type<
    void(const std::string&), bs2::keywords::mutex_type<bs2::mutex>>::type
    nf_status_sig_t;

typedef bs2::signal_type<
    void(const std::shared_ptr<nrf_profile>& p),
    bs2::keywords::mutex_type<bs2::mutex>>::type nf_deregistered_sig_t;

typedef bs2::signal_type<
    void(const std::shared_ptr<nrf_profile>& p),
    bs2::keywords::mutex_type<bs2::mutex>>::type nf_status_change_sig_t;

}  // namespace app
}  // namespace nrf
}  // namespace oai

#endif /* FILE_NRF_EVENT_SIG_HPP_SEEN */
