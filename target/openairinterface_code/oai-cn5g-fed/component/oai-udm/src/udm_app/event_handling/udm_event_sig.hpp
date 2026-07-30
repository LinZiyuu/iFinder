/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_UDM_EVENT_SIG_HPP_SEEN
#define FILE_UDM_EVENT_SIG_HPP_SEEN

#include <boost/signals2.hpp>
#include <string>

namespace bs2 = boost::signals2;

namespace oai::udm::app {

typedef bs2::signal_type<
    void(uint64_t), bs2::keywords::mutex_type<bs2::dummy_mutex>>::type
    task_sig_t;

// Signal for Loss of Connectivity
// SUPI, Connectivity status, HTTP version
typedef bs2::signal_type<
    void(std::string, uint8_t, uint8_t),
    bs2::keywords::mutex_type<bs2::dummy_mutex>>::type
    loss_of_connectivity_sig_t;

// Signal for UE Reachability for Data
// SUPI, Reachability status, HTTP version
typedef bs2::signal_type<
    void(std::string, uint8_t, uint8_t),
    bs2::keywords::mutex_type<bs2::dummy_mutex>>::type
    ue_reachability_for_data_sig_t;

// UE_REACHABILITY_FOR_SMS
// LOCATION_REPORTING
// CHANGE_OF_SUPI_PEI_ASSOCIATION
// ROAMING_STATUS
// COMMUNICATION_FAILURE
// AVAILABILITY_AFTER_DNN_FAILURE
// CN_TYPE_CHANGE

}  // namespace oai::udm::app
#endif
