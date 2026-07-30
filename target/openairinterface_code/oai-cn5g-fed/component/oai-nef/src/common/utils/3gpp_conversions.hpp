/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_3GPP_CONVERSIONS_HPP_SEEN
#define FILE_3GPP_CONVERSIONS_HPP_SEEN

#include "AmfCreateEventSubscription.h"
#include "AmfEventReport.h"
#include "MonitoringEventReport.h"
#include "MonitoringEventSubscription.h"
#include "nef.h"

namespace xgpp_conv {

/*
 * Convert from a Monitoring Event Subscription to an AMF Event Subscription
 * @param [const oai::nef::model::MonitoringEventSubscription& ]
 * monitoring_event_sub: Monitoring Event Subscription
 * @param [oai::nef::model::AmfEventSubscription& ] amf_event_sub: AMF Event
 * Subscription
 * @return true if the conversion is successful, otherwise false
 */
bool monitoring_event_to_amf_event(
    const oai::nef::model::MonitoringEventSubscription& monitoring_event_sub,
    oai::nef::model::AmfCreateEventSubscription& amf_event_sub);

/*
 * Convert from an AMF Event Report to a Monitoring Event Report
 * @param [const oai::nef::model::AmfEventReport& ] amf_report: AMF Event Report
 * @param [oai::nef::model::MonitoringEventReport& ] monitoring_report:
 * Monitoring Event Report
 * @return true if the conversion is successful, otherwise false
 */
bool amf_report_to_monitoring_report(
    const oai::nef::model::AmfEventReport& amf_report,
    oai::nef::model::MonitoringEventReport& monitoring_report);

/*
 * Convert a string to Patch operation
 * @param [const std::string &] str: string input
 * @return the corresponding Patch operation
 */
patch_op_type_t string_to_patch_operation(const std::string& str);

}  // namespace xgpp_conv

#endif /* FILE_3GPP_CONVERSIONS_HPP_SEEN */
