#!/bin/bash

##########################
#
# usage:
# ./api-webconsole-charging-record.sh <action> <login_json_path>
#
# e.g. ./api-webconsole-charging-record.sh [get] json/webconsole-login-data.json
#
##########################

set -e

# get token
echo "Getting token..."

LOGIN_RESPONSE=$(curl -s -X POST http://webui:5000/api/login \
-H "Content-Type: application/json" \
-d @"$2")

TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.access_token')

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
    echo "Failed to get token!"
    echo "Server response: $LOGIN_RESPONSE"
    exit 1
fi

if [[ ! "$TOKEN" =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$ ]]; then
    echo "Invalid token format!"
    echo "Token: $TOKEN"
    exit 1
fi

echo "Token obtained successfully!"

# get charging record
echo "Getting charging record..."

TOKEN=$(echo -n "$TOKEN" | tr -d '\n' | tr -d ' ')

case "$1" in
    "get")
        CHARGING_RECORD_RESPONSE=$(curl -s -X GET "http://webui:5000/api/charging-record" \
        -H "Token: $TOKEN")
        ;;
    *)
        echo "error: invalid parameter"
        echo "usage: $0 [get]"
        exit 1
        ;;
esac

echo "Charging record obtained successfully!"
echo "$CHARGING_RECORD_RESPONSE"