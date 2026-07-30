# SPDX-License-Identifier: LicenseRef-CSSL-1.0

SET(EVENT_HANDLING_DIR ${SRC_TOP_DIR}/${MOUNTED_COMMON}/event_handling)

## Logger used in NF_TARGET (main)
if (TARGET ${NF_TARGET})
target_include_directories(${NF_TARGET} PUBLIC ${EVENT_HANDLING_DIR})
target_sources(${NF_TARGET} PRIVATE
        ${EVENT_HANDLING_DIR}/nf_event.cpp
        ${EVENT_HANDLING_DIR}/task_manager.cpp
        )
endif()
