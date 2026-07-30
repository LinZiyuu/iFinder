/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "3gpp_conversions.hpp"

#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "conversions.hpp"

using namespace oai::nef::model;
//------------------------------------------------------------------------------
bool xgpp_conv::monitoring_event_to_amf_event(
    const oai::nef::model::MonitoringEventSubscription& monitoring_event_sub,
    oai::nef::model::AmfCreateEventSubscription& amf_event_sub) {
  // AmfEventSubscription
  AmfEventSubscription ev_subscription;

  // AMF EventList
  std::vector<AmfEvent> amf_events;
  AmfEvent amf_event          = {};
  AmfEventType amf_event_type = {};

  switch (monitoring_event_sub.getMonitoringType().getEnumValue()) {
    case MonitoringType_anyOf::eMonitoringType_anyOf::UE_REACHABILITY: {
      amf_event_type.setEnumValue(
          AmfEventType_anyOf::eAmfEventType_anyOf::REACHABILITY_REPORT);
    } break;
    case MonitoringType_anyOf::eMonitoringType_anyOf::LOCATION_REPORTING: {
      amf_event_type.setEnumValue(
          AmfEventType_anyOf::eAmfEventType_anyOf::LOCATION_REPORT);
    } break;

    case MonitoringType_anyOf::eMonitoringType_anyOf::LOSS_OF_CONNECTIVITY: {
      amf_event_type.setEnumValue(
          AmfEventType_anyOf::eAmfEventType_anyOf::LOSS_OF_CONNECTIVITY);
    } break;

    case MonitoringType_anyOf::eMonitoringType_anyOf::COMMUNICATION_FAILURE: {
      amf_event_type.setEnumValue(AmfEventType_anyOf::eAmfEventType_anyOf::
                                      COMMUNICATION_FAILURE_REPORT);
    } break;

    case MonitoringType_anyOf::eMonitoringType_anyOf::
        AVAILABILITY_AFTER_DDN_FAILURE: {
      // TODO:  amf_event_type.setEnumValue(
      //  AmfEventType_anyOf::eAmfEventType_anyOf::INVALID_VALUE_OPENAPI_GENERATED);
    } break;

    case MonitoringType_anyOf::eMonitoringType_anyOf::
        NUMBER_OF_UES_IN_AN_AREA: {
      amf_event_type.setEnumValue(
          AmfEventType_anyOf::eAmfEventType_anyOf::UES_IN_AREA_REPORT);
    } break;

    default: {
      amf_event_type.setEnumValue(AmfEventType_anyOf::eAmfEventType_anyOf::
                                      INVALID_VALUE_OPENAPI_GENERATED);
      return false;
    } break;
  }
  amf_event.setType(amf_event_type);
  amf_events.push_back(amf_event);
  ev_subscription.setEventList(amf_events);

  // EventNotifyUri: Notification endpoint of the Consumer (e.g., AF to get the
  // notification data)
  ev_subscription.setEventNotifyUri(
      monitoring_event_sub.getNotificationDestination());
  // TODO:
  // NotifyCorrelationId

  // NfId -  to be set later on NEF APP
  // SubsChangeNotifyUri (Notification endpoint of NEF, to get the notification
  // when subscription changes) - to be set later on NEF APP

  // TODO:
  // SubsChangeNotifyCorrelationId
  // Supi
  // GroupId
  // Gpsi
  // Pei
  // AnyUE

  //   AmfEventMode Options
  AmfEventMode option               = {};
  AmfEventTrigger amf_event_trigger = {};
  amf_event_trigger.setEnumValue(
      AmfEventTrigger_anyOf::eAmfEventTrigger_anyOf::
          CONTINUOUS);  // TODO: get from MonitoringEventSubscription
  option.setTrigger(amf_event_trigger);
  option.setMaxReports(monitoring_event_sub.getMaximumNumberOfReports());
  option.setExpiry(monitoring_event_sub.getMonitorExpireTime());

  ev_subscription.setOptions(option);
  amf_event_sub.setSubscription(ev_subscription);

  // SupportedFeatures
  amf_event_sub.setSupportedFeatures(
      monitoring_event_sub.getSupportedFeatures());

  return true;
}

//------------------------------------------------------------------------------
bool xgpp_conv::amf_report_to_monitoring_report(
    const oai::nef::model::AmfEventReport& amf_report,
    oai::nef::model::MonitoringEventReport& monitoring_report) {
  return true;
}

//------------------------------------------------------------------------------
patch_op_type_t xgpp_conv::string_to_patch_operation(const std::string& str) {
  if (str.compare("add") == 0) return PATCH_OP_ADD;
  if (str.compare("copy") == 0) return PATCH_OP_COPY;
  if (str.compare("move") == 0) return PATCH_OP_MOVE;
  if (str.compare("remove") == 0) return PATCH_OP_REMOVE;
  if (str.compare("replace") == 0) return PATCH_OP_REPLACE;
  if (str.compare("test") == 0) return PATCH_OP_TEST;
  // default
  return PATCH_OP_UNKNOWN;
}
