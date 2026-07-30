/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef FILE_LMF_TRP_SEEN
#define FILE_LMF_TRP_SEEN

#include "CoordinateID.h"
#include "RelativeCartesianLocation.h"

namespace oai::lmf::app {

class Trp {
 public:
  CoordinateID_t relativeCoordinateID                   = {};
  RelativeCartesianLocation_t relativeCartesianLocation = {};
};

}  // namespace oai::lmf::app

#endif  // FILE_LMF_TRP_SEEN
