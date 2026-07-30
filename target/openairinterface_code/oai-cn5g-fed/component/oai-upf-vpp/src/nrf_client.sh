#!/bin/bash

#"""
#/*
# * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
# * contributor license agreements.  See the NOTICE file distributed with
# * this work for additional information regarding copyright ownership.
# * The OpenAirInterface Software Alliance licenses this file to You under
# * the OAI Public License, Version 1.1  (the "License"); you may not use this
# * file except in compliance with the License. You may obtain a copy of the
# * License at
# *
# *      http://www.openairinterface.org/?page_id=698
# *
# * Unless required by applicable law or agreed to in writing, software
# * distributed under the License is distributed on an "AS IS" BASIS,
# * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# * See the License for the specific language governing permissions and
# * limitations under the License.
# *-------------------------------------------------------------------------------
# * For more information about the OpenAirInterface (OAI) Software Alliance:
# *      contact@openairinterface.org
# */
#
#/*! \file nrf_client.py
#   \author  Rohan KHARADE
#   \date 2022
#   \email: rohan.kharade@openairinterface.org
#*/
#"""

if [ ! -v CONFIG_DIR ]; then
        CONFIG_DIR=/openair-upf/etc
fi
UPF_PROFILE=$CONFIG_DIR/upf_profile.json

if [ ! -v UUID ]; then
        echo "UUID is not defined"
        UUID=`grep nfInstanceId ${UPF_PROFILE} | sed -e 's@    "nfInstanceId": "@@' -e 's@",@@'`
else
        echo "UUID is exported: ${UUID}"
fi
NRF_URL=$NRF_IP_ADDR:$NRF_PORT/nnrf-nfm/v1/nf-instances/$UUID
echo "NRF_URL is ${NRF_URL}"

##### Variables #####
DUMP_STATUS_CODE=$(echo '--write-out %{http_code} --silent --output /dev/null')
PATCH_DATA=$(echo '[{"op":"replace","path":"/nfStatus","value":"REGISTERED"}]')
CONTENT_TYPE=$(echo 'Content-Type: application/json')
HTTP2=--http2-prior-knowledge
NF_HEARTBEAT_TIMER=10
NF_HEARTBEAT_START=5

##### NF Registration #####
echo "Sending NF Registration Request (HTTP Version $HTTP_VERSION)"
if [[ ${HTTP_VERSION} == 2 ]];then
        echo "curl command options are: ${HTTP2} ${DUMP_STATUS_CODE} -X PUT ${NRF_URL} -d @${UPF_PROFILE} -H \"${CONTENT_TYPE}\" -H \"Expect:\""
        response=$(curl $HTTP2 $DUMP_STATUS_CODE -X PUT $NRF_URL -d @$UPF_PROFILE -H "$CONTENT_TYPE" -H "Expect:")
else
        echo "curl command options are: ${DUMP_STATUS_CODE} -X PUT ${NRF_URL} -d @${UPF_PROFILE} -H \"${CONTENT_TYPE}\" -H \"Expect:\""
        response=$(curl $DUMP_STATUS_CODE -X PUT $NRF_URL -d @$UPF_PROFILE -H "$CONTENT_TYPE" -H "Expect:")
fi

##### NF Heartbeat #####
DISPLAY_CMD=1
if [[ ${response} == 201 || ${response} == 200 ]];then
        echo -e "Received NF registration response (HTTP_STATUS_CODE_200/201)\n"
        sleep $NF_HEARTBEAT_START
        while true
        do
                echo "Sending NF heartbeat request"
                if [[ ${HTTP_VERSION} == 2 ]]; then
                        if [ $DISPLAY_CMD -eq 1 ]; then
                                echo "curl command options are: ${HTTP2} ${DUMP_STATUS_CODE} -X PATCH ${NRF_URL} -d ${PATCH_DATA} -H \"${CONTENT_TYPE}\" -H \"Expect:\""
                        fi
                        response=$(curl $HTTP2 $DUMP_STATUS_CODE -X PATCH  $NRF_URL -d $PATCH_DATA -H "$CONTENT_TYPE" -H "Expect:")
                else
                        if [ $DISPLAY_CMD -eq 1 ]; then
                                echo "curl command options are: ${DUMP_STATUS_CODE} -X PATCH ${NRF_URL} -d ${PATCH_DATA} -H \"${CONTENT_TYPE}\" -H \"Expect:\""
                        fi
                        response=$(curl $DUMP_STATUS_CODE -X PATCH  $NRF_URL -d $PATCH_DATA -H "$CONTENT_TYPE" -H "Expect:")
                fi
                DISPLAY_CMD=0
                if [[ ${response} == 204 ]];then
                        echo -e "Received NF heartbeat response (HTTP_STATUS_CODE_204)\n"
                fi
                sleep $NF_HEARTBEAT_TIMER
        done
else
        echo -e "\nNF Registration Procedure Failed (response is ${response}) ........!!!!"
fi

