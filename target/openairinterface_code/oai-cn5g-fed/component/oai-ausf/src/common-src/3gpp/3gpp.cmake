# SPDX-License-Identifier: LicenseRef-CSSL-1.0

SET(3GPP_DIR ${SRC_TOP_DIR}/${MOUNTED_COMMON}/3gpp)
include_directories(${3GPP_DIR})

file(GLOB 3GPP_SRC_FILES
        ${3GPP_DIR}/*.cpp
        )

if (TARGET ${NF_TARGET})
target_include_directories(${NF_TARGET} PUBLIC ${3GPP_DIR})
target_sources(${NF_TARGET} PRIVATE
        ${3GPP_SRC_FILES}
        )
endif()
