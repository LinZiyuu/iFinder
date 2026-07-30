# SPDX-License-Identifier: LicenseRef-CSSL-1.0

SET(COMMON_DIR ${SRC_TOP_DIR}/${MOUNTED_COMMON}/common)
include_directories(${COMMON_DIR})
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/common_model)

file(GLOB COMMON_SRC_FILES
        ${COMMON_DIR}/*.cpp
        )

if (TARGET ${NF_TARGET})
target_include_directories(${NF_TARGET} PUBLIC ${COMMON_DIR})
target_sources(${NF_TARGET} PRIVATE
        ${COMMON_SRC_FILES}
        )
endif()
