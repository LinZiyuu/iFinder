#!/bin/bash

##########################
#
# usage:
# ./api-webconsole-subscribtion-data-action.sh <action> <json_file>
#
# e.g. ./api-webconsole-subscribtion-data-action.sh [post|delete] json/webconsole-subscription-data-[offline|online].json
#
##########################

set -e

# get token
echo "Getting token..."

LOGIN_RESPONSE=$(curl -s -X POST http://webui:5000/api/login \
-H "Content-Type: application/json" \
-d @json/webconsole-login-data.json)

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

# send subscription request (post)
echo "Sending subscription request..."

TOKEN=$(echo -n "$TOKEN" | tr -d '\n' | tr -d ' ')

case "$1" in
    "post")
        SUBSCRIBE_RESPONSE=$(curl -s -X POST "http://webui:5000/api/subscriber/imsi-208930000000001/20893" \
        -H "Content-Type: application/json" \
        -H "Token: $TOKEN" \
        -d @"$2")
        ;;
    "delete")
        SUBSCRIBE_RESPONSE=$(curl -s -X DELETE "http://webui:5000/api/subscriber/imsi-208930000000001/20893" \
        -H "Content-Type: application/json" \
        -H "Token: $TOKEN" \
        -d @"$2")
        ;;
    *)
        echo "error: invalid parameter"
        echo "usage: $0 [post|delete]"
        exit 1
        ;;
esac

echo "Subscription request finished:"
echo "$SUBSCRIBE_RESPONSE"