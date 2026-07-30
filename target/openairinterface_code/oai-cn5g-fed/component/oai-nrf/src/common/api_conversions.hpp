/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_API_CONVERSIONS_HPP_SEEN
#define FILE_API_CONVERSIONS_HPP_SEEN

#include "NFProfile.h"
#include "SubscriptionData.h"
#include "nrf.h"
#include "nrf_profile.hpp"
#include "nrf_subscription.hpp"

using namespace oai::model::nrf;
using namespace oai::nrf::app;

namespace oai {
namespace nrf {
namespace api_conv {

/*
 * Convert a json-type profile to a NF profile
 * @param [const NFProfile &] NFProfile: Json-type profile from OpenAPITool
 * @param [std::shared_ptr<nrf_profile> &] profile: NF profile
 * @return true if successful, otherwise, return false
 */
bool profile_api_to_nrf_profile(
    const NFProfile& api_profile, std::shared_ptr<nrf_profile>& profile);

/*
 * Convert a json-type profile to a subscription profile
 * @param [const SubscriptionData &] subData: Json-type subscription data from
 * OpenAPITool
 * @param [std::shared_ptr<nrf_subscription> &] sub: NRF Subscription
 * @return true if successful, otherwise, return false
 */
bool subscription_api_to_nrf_subscription(
    const SubscriptionData& api_sub, std::shared_ptr<nrf_subscription>& sub);

/*
 * Convert a string to NF type
 * @param [const std::string &] str: string input
 * @return the corresponding nf_type
 */
nf_type_t string_to_nf_type(const std::string& str);

/*
 * Convert NF type to string
 * @param [const nf_type_t &] nf_type: NF type
 * @return the corresponding string
 */
std::string nf_type_to_string(const nf_type_t& nf_type);

/*
 * Convert a string to UP interface type
 * @param [const std::string &] str: string input
 * @return the corresponding up_interface_type
 */
nf_up_interface_type_t string_to_up_interface_type(const std::string& str);

/*
 * Convert a string to Patch operation
 * @param [const std::string &] str: string input
 * @return the corresponding Patch operation
 */
patch_op_type_t string_to_patch_operation(const std::string& str);

bool validate_uuid(const std::string& str);

}  // namespace api_conv
}  // namespace nrf
}  // namespace oai

#endif /* FILE_API_CONVERSIONS_HPP_SEEN */
