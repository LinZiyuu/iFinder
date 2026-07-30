#!/bin/bash

##########################
#
# usage:
# ./api-udr-ti-data-action.sh <action>
#
# e.g. ./api-udr-ti-data-action.sh [put|get|delete]
#
##########################

set -e

# ti data request
case "$1" in
    "put")
        curl -X PUT -H "Content-Type: application/json" --data @json/ti-data.json \
            http://udr.free5gc.org:8000/nudr-dr/v1/application-data/influenceData/1
        ;;
    "get")
        curl -X GET -H "Content-Type: application/json" \
            http://udr.free5gc.org:8000/nudr-dr/v1/application-data/influenceData/
        ;;
    "delete")
        curl -X DELETE -H "Content-Type: application/json" \
            http://udr.free5gc.org:8000/nudr-dr/v1/application-data/influenceData/1
        ;;
    *)
        echo "error: invalid parameter"
        echo "usage: $0 [put|get|delete]"
        exit 1
        ;;
esac
