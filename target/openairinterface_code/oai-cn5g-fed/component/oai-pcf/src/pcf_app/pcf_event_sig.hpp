/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_PCF_EVENT_SIG_HPP_SEEN
#define FILE_PCF_EVENT_SIG_HPP_SEEN

#include <boost/signals2.hpp>
#include <string>
#include "SmPolicyDecision.h"

namespace bs2 = boost::signals2;

namespace oai::pcf::app {

using namespace oai::model::pcf;

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

// Signal for sm_policy_control to perform session binding
typedef bs2::signal_type<
    void(
        const std::optional<std::string>&, const std::optional<std::string>&,
        const std::optional<std::string>&, std::optional<std::string>&,
        oai::model::pcf::SmPolicyDecision&),
    bs2::keywords::mutex_type<bs2::dummy_mutex>>::type sm_session_binding_sig_t;

// Signal for sm_policy_control to update policy decision
typedef bs2::signal_type<
    void(std::optional<std::string>&, oai::model::pcf::SmPolicyDecision&),
    bs2::keywords::mutex_type<bs2::dummy_mutex>>::type sm_update_decision_sig_t;

}  // namespace oai::pcf::app
#endif
