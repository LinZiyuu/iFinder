# SPDX-License-Identifier: LicenseRef-CSSL-1.0

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${SRC_TOP_DIR}/udm_app)
include_directories(${SRC_TOP_DIR}/udm_app/event_handling)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/utils)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/common)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/config)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/3gpp)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/common_model)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils/bstr)

add_library(3GPP_COMMON_TYPES STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/options.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/udm_sbi_helper.cpp  
)
