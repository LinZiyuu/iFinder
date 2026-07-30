/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "NonUeN2InfoNotifyApiImpl.h"

#include "lmf_nrf.hpp"
#include "logger.hpp"
#include "conversions.hpp"
#include "bstrlib.h"

#include "N2InformationNotification.h"

using namespace oai::model::common;
using namespace oai::model::lmf;

namespace oai::lmf::api {

NonUeN2InfoNotifyApiImpl::NonUeN2InfoNotifyApiImpl(
    std::shared_ptr<Pistache::Rest::Router> rtr,
    oai::lmf::app::lmf_app* lmf_app_inst)
    : NonUeN2InfoNotifyApi(rtr), m_lmf_app(lmf_app_inst) {}

void NonUeN2InfoNotifyApiImpl::receive_non_ue_n2info_nrppa_notification(
    std::vector<mime_part>& parts, Pistache::Http::ResponseWriter& response) {
  using namespace oai::model::lmf;

  Logger::lmf_server().debug(
      "Receive an NonUeN2Info NRPPA Notify, handling...");

  N2InformationNotification n2InformationNotification{
      nlohmann::json::parse(parts.at(0).body)};

  // TODO: handle subscrription id
  n2InformationNotification.getN2NotifySubscriptionId();
  // TODO: handle lcs corrlation id
  n2InformationNotification.getLcsCorrelationId();

  if (!n2InformationNotification.n2InfoContainerIsSet()) {
    response.send(Pistache::Http::Code::Bad_Request);
    Logger::lmf_server().error("N2InfoContainer not present");
    return;
  }
  // N2 Container Present
  Logger::lmf_server().debug("N2InfoContainer is present, handling...");

  auto const& n2InfoContainer = n2InformationNotification.getN2InfoContainer();
  auto const& eN2InformationClass =
      n2InfoContainer.getN2InformationClass().getEnumValue();

  // Check N2 Information Class
  if (eN2InformationClass !=
      N2InformationClass_anyOf::eN2InformationClass_anyOf::NRPPA) {
    response.send(Pistache::Http::Code::Bad_Request);
    Logger::lmf_server().error(
        "N2 Information Class not NRPPA: %d",
        static_cast<int>(eN2InformationClass));
    return;
  }
  Logger::lmf_server().debug("N2 Information Class: NRPPA");

  if (!n2InfoContainer.nrppaInfoIsSet()) {
    response.send(Pistache::Http::Code::Bad_Request);
    Logger::lmf_server().error("nrppaInfo not present");
    return;
  }
  auto const& nrppaInfo = n2InfoContainer.getNrppaInfo();

  if (nrppaInfo.getNfId() != lmf_nrf_inst->lmf_instance_id) {
    Logger::lmf_server().warn(
        "nfId != '%s': '%s'", lmf_nrf_inst->lmf_instance_id,
        nrppaInfo.getNfId());
  }

  auto const& nrppaPdu = nrppaInfo.getNrppaPdu();
  if (!nrppaPdu.ngapIeTypeIsSet()) {
    response.send(Pistache::Http::Code::Bad_Request);
    Logger::lmf_server().error("ngapIeType not present");
    return;
  }
  // NGAP IE Type
  auto const& eNgapIeType = nrppaPdu.getNgapIeType().getEnumValue();
  if (eNgapIeType != NgapIeType_anyOf::eNgapIeType_anyOf::NRPPA_PDU) {
    response.send(Pistache::Http::Code::Bad_Request);
    Logger::lmf_server().error(
        "ngapIeType not NRPPA_PDU: %d", static_cast<int>(eNgapIeType));
    return;
  }
  Logger::lmf_server().debug("NGAP IE Type: NRPPA_PDU");
  auto const& ngapData = nrppaPdu.getNgapData();
  Logger::lmf_server().debug("content-id: %s", ngapData.getContentId());

  if (parts.at(1).content_type != "application/vnd.3gpp.ngap") {
    Logger::lmf_server().warn(
        "content-type != 'application/vnd.3gpp.ngap': '%s'",
        parts.at(1).content_type);
  }

  auto const& body   = parts.at(1).body;
  NRPPA_PDU_t* nrppa = nullptr;
  auto const& rc     = asn_decode(
      NULL, ATS_ALIGNED_CANONICAL_PER, &asn_DEF_NRPPA_PDU, (void**) &nrppa,
      body.c_str(), body.length());
  if (rc.code != RC_OK) {
    ASN_STRUCT_FREE(asn_DEF_NRPPA_PDU, nrppa);
    response.send(Pistache::Http::Code::Bad_Request);
    Logger::lmf_server().error("asn_decode failed: %d", rc.code);
    return;
  }
  // xer_fprint(stdout, &asn_DEF_NRPPA_PDU, nrppa);
  // Logger::lmf_server().debug("asn_decode ok, consumed: %d", rc.consumed);

  ProblemDetails problem_details = {};
  uint8_t http_code              = 0;

  if (m_lmf_app->handle_non_ue_n2info_nrppa_notification(
          share_nrppa_pdu(nrppa))) {
    response.send(Pistache::Http::Code(204));
  }
}

}  // namespace oai::lmf::api
