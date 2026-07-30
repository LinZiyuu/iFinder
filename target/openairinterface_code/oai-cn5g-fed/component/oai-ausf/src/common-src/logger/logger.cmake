# SPDX-License-Identifier: LicenseRef-CSSL-1.0

SET(LOGGER_DIR ${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger)

include_directories(${LOGGER_DIR})

## Logger used in NF_TARGET (main)
if (TARGET ${NF_TARGET})
target_include_directories(${NF_TARGET} PUBLIC ${LOGGER_DIR})
target_sources(${NF_TARGET} PRIVATE
        ${LOGGER_DIR}/nf-tp.cpp
        ${LOGGER_DIR}/lttng_logger_base.cpp
        ${LOGGER_DIR}/spd_logger_base.cpp
        ${LOGGER_DIR}/logger_base.cpp
        )
endif()
