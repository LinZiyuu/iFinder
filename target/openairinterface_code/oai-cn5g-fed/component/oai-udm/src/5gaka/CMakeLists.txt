# SPDX-License-Identifier: LicenseRef-CSSL-1.0

set(5GAKA_DIR "${SRC_TOP_DIR}/5gaka")

include_directories(${SRC_TOP_DIR}/udm_app)
include_directories(${SRC_TOP_DIR}/udm_app/event_handling)
include_directories(${SRC_TOP_DIR}/common)
include_directories(${SRC_TOP_DIR}/5gaka)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/3gpp)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/common)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/config)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/logger)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/ngap/libngap)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils/bstr)

file(GLOB 5GAKA_src_files
    ${SRC_TOP_DIR}/${MOUNTED_COMMON}/ngap/libngap/*.c
    ${5GAKA_DIR}/*.cpp
)
 
add_library(5GAKA STATIC
           ${5GAKA_src_files})        
