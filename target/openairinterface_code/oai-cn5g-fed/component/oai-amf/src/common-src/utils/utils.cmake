# SPDX-License-Identifier: LicenseRef-CSSL-1.0

SET(UTILS_DIR ${SRC_TOP_DIR}/${MOUNTED_COMMON}/utils)
include_directories(${UTILS_DIR})
include_directories(${UTILS_DIR}/bstr)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/ngap/libngap)
include_directories(${SRC_TOP_DIR}/${MOUNTED_COMMON}/3gpp)

file(GLOB UTILS_SRC_FILES
        ${UTILS_DIR}/*.cpp
        ${UTILS_DIR}/backtrace.c
        ${UTILS_DIR}/bstr/bstrlib.c 
        )

if (TARGET ${NF_TARGET})
target_include_directories(${NF_TARGET} PUBLIC ${UTILS_DIR})
target_sources(${NF_TARGET} PRIVATE
        ${UTILS_SRC_FILES}
        )
endif()
