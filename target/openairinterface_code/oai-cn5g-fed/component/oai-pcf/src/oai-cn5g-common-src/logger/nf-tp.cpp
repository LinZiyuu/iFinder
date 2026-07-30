/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */
/*
This file acts as a bridge between the tracepoint definitions specified in the
"nf-tp.hpp" file and the actual generation of tracepoints in our project. It
includes the tracepoint definitions to generate the necessary code for LTTng to
trace the events when the code runs.
*/

#define TRACEPOINT_CREATE_PROBES
#define TRACEPOINT_DEFINE

#include "nf-tp.hpp"
