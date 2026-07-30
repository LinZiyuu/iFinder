/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */
/*
This header file contains LTTng tracepoint definitions. The NF_TRACE_EVENT macro
is used to define tracepoints for different log types within a specified Network
Function (NF_TRACE). The events are defined for log types like warn, info,
error, trace, debug, and startup.
*/

#ifdef LOGGER_CAN_USE_LTTNG

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER NF_TRACE

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./nf-tp.hpp"

#if !defined(_NF_TP_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _NF_TP_H

#include <lttng/tracepoint.h>

// #define NF_TRACE_EVENT(nf, tp, log_string) TRACEPOINT_EVENT(nf, tp, \
//     						TP_ARGS(const char*, log_string), \
//     						TP_FIELDS(ctf_string(log, log_string)) \
//   						)

// NF_TRACE_EVENT(NF_TRACE, warn, log_string)
// NF_TRACE_EVENT(NF_TRACE, info, log_string)
// NF_TRACE_EVENT(NF_TRACE, error, log_string)
// NF_TRACE_EVENT(NF_TRACE, trace, log_string)
// NF_TRACE_EVENT(NF_TRACE, debug, log_string)
// NF_TRACE_EVENT(NF_TRACE, startup, log_string)

#endif /* _NF_TP_H */

#include <lttng/tracepoint-event.h>
#include <lttng/tracelog.h>

#endif /* LOGGER_CAN_USE_LTTNG */
