# SPDX-License-Identifier: LicenseRef-CSSL-1.0

SET(HTTP_DIR ${SRC_TOP_DIR}/${MOUNTED_COMMON}/http)

include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger/logger.cmake)
#include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils/utils.cmake)
include(${SRC_TOP_DIR}/${MOUNTED_COMMON}/common/common.cmake)

include_directories(${HTTP_DIR})

SET(HTTP_SRC_FILES
        ${HTTP_DIR}/http_client.cpp
)

## CONFIG used in NF_TARGET (main)
if (TARGET ${NF_TARGET})
    target_include_directories(${NF_TARGET} PUBLIC ${HTTP_DIR})
    target_sources(${NF_TARGET} PRIVATE
            ${HTTP_SRC_FILES}
    )
endif ()
