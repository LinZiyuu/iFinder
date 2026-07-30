/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_LMF_APP_HPP_SEEN
#define FILE_LMF_APP_HPP_SEEN

#define ASN_DISABLE_OER_SUPPORT

#include <pistache/http.h>

#include <boost/range/combine.hpp>
#include <condition_variable>
#include <map>
#include <shared_mutex>
#include <string>

#include "CoordinateID.h"
#include "InputData.h"
#include "Measurement-ID.h"
#include "N2InformationNotification.h"
#include "NRPPATransactionID.h"
#include "ProblemDetails.h"
#include "RelativeCartesianLocation.h"
#include "TRP-ID.h"
#include "lmf.h"
#include "lmf_cause_error.hpp"
#include "lmf_event.hpp"
#include "lmf_gnb.hpp"
#include "lmf_location_determination.hpp"
#include "lmf_n1_n2_message_subscription.hpp"
#include "lmf_non_ue_n2_message_subscription.hpp"
#include "mime_parser.hpp"
#include "uint_generator.hpp"

namespace oai::lmf::app {

class lmf_app {
 public:
  explicit lmf_app(const std::string& config_file, lmf_event& ev);
  lmf_app(lmf_app const&) = delete;
  void operator=(lmf_app const&) = delete;

  virtual ~lmf_app();

  bool start();
  void stop();

  void handle_determine_location(
      const oai::model::lmf::InputData& inputData, nlohmann::json& json_data,
      Pistache::Http::Code& code);
  bool handle_non_ue_n2info_nrppa_notification(NrppaPduShared nrppa);
  bool handle_n2info_nrppa_notification(std::string supi, NrppaPduShared nrppa);

  bool is_supi_2_context(const std::string& supi) const;
  std::shared_ptr<LocationDetermination> create_lmf_context(
      const std::string& supi);
  std::shared_ptr<LocationDetermination> supi_2_context(
      const std::string& supi) const;
  void set_supi_2_context(
      const std::string& supi,
      const std::shared_ptr<LocationDetermination>& lc);
  void del_supi_2_context(const std::string& supi);

  void create_n1n2subscription(const std::string& supi);
  void release_n1n2subscription(const std::string& supi);
  void release_all_n1n2subscriptions();

  void create_non_ue_subscription();
  void release_non_ue_subscription();

  static NrppaPduShared parse_n2_info_container_nrppa(
      oai::model::lmf::N2InformationNotification const&
          n2InformationNotification,
      mime_part const& nrppa_part);

  // for non-ue that actually refers to ue
  std::map<NRPPATransactionID_t, std::string> nrppaTxnId2supi;
  mutable std::shared_mutex m_nrppaTxnId2supi;
  void insert_nrppaTxnId2supi(
      NRPPATransactionID_t const& nrppaTxnId, std::string const& supi);
  std::string extract_nrppaTxnId2Supi(NRPPATransactionID_t const& nrppaTxnId);
  std::string get_nrppaTxnId2Supi(NRPPATransactionID_t const& nrppaTxnId);
  void erase_nrppaTxnId2Supi(NRPPATransactionID_t const& nrppaTxnId);

  oai::utils::uint_range_generator<Measurement_ID_t, 1, 65536>
      measurement_id_gen;
  oai::utils::uint_range_generator<NRPPATransactionID_t, 0, 32767>
      nrppa_tid_gen;

 private:
  std::map<std::string, std::shared_ptr<LocationDetermination>> supi2ctx;
  mutable std::shared_mutex m_supi2ctx;

  std::map<std::string, N1N2MessageSubscription> supi2n1n2subs;
  mutable std::shared_mutex m_supi2n1n2subs;

  mutable std::mutex m_non_ue_subs;
  std::unique_ptr<NonUeN2MessageSubscription> nonUeN2MessageSubscription;

  void trp_information(std::shared_ptr<LocationDetermination> const& ctx);
  void trp_information_request(
      std::shared_ptr<LocationDetermination> const& ctx,
      NRPPATransactionID_t const& nrppatransactionID);
  void handle_trp_information_response(
      NrppaPduShared nrppaPdu, NRPPATransactionID_t const& tId,
      TRPInformationResponse_t const& trpInformation);
  lmf_event& event_sub;

  bool _is_supi_2_context(const std::string& supi) const;

  // NRPPATransactionID_t nrppa_tid_trp_information;

  // NG_RAN_CGI_t / NG_RANCell_t / NRCellIdentifier_t /
  // std::map<GNB_ID, std::vector<TRP_ID_t>> trps = {{1, {1}}};

  // globalRanNodeList
  std::map<GnbId, Gnb> gnb;
  mutable std::mutex cv_m_gnb;
  std::condition_variable cv_gnb;
  auto numTrps() {
    return std::accumulate(
        this->gnb.cbegin(), this->gnb.cend(), std::size_t{0},
        [](auto const& a, auto const& b) { return a + b.second.trp.size(); });
  }

  std::vector<CauseError> trp_info_err;
};
}  // namespace oai::lmf::app

extern oai::lmf::app::lmf_app* lmf_app_inst;

#endif /* FILE_LMF_APP_HPP_SEEN */
