# SPDX-License-Identifier: LicenseRef-CSSL-1.0

SET(COMMON_MODEL_DIR ${SRC_TOP_DIR}/${MOUNTED_COMMON}/model/common_model)

include_directories(${COMMON_MODEL_DIR})

list(REMOVE_DUPLICATES USED_COMMON_MODEL_SRC_FILES)

# Here, we expect that in NF build directory or in other models (e.g. NRF) selected common_models are written to
# ${USED_COMMON_MODEL_SRC_FILES} to speed up the build (more performant than just adding all models)
if (TARGET ${NF_TARGET})
    target_include_directories(${NF_TARGET} PUBLIC ${COMMON_MODEL_DIR})
    target_sources(${NF_TARGET} PRIVATE
            ${USED_COMMON_MODEL_SRC_FILES}
            )
endif()
