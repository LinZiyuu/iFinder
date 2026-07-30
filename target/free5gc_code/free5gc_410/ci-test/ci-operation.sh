#! /bin/bash

##########################
#
# This script is used for quickly testing the function
#
##########################
#
# usage:
# ./ ci-operation.sh [action]
#
# e.g. ./ci-test-ulcl.sh test
#
##########################

usage() {
    echo "usage: ./ci-operation.sh []"
    echo "  - pull: remove the existed free5gc repo under base/ and clone a new free5gc with its NFs"
    echo "  - build: build the necessary images"
    echo "  - up: bring up the compose"
    echo "  - down: shut down the compose"
    echo "  - test: run ULCL TI test"
    echo "  - exec: enter the ci container"
}

main() {
    if [ $# -ne 1 ]; then
        usage
    fi

    case "$1" in
        "pull")
            cd base
            rm -rf free5gc
            git clone -j `nproc` --recursive https://github.com/free5gc/free5gc
        ;;
        "build")
            make ulcl
        ;;
        "up")
            docker compose -f docker-compose-ulcl.yaml up
        ;;
        "down")
            docker compose -f docker-compose-ulcl.yaml down
        ;;
        "test")
            docker exec ci /bin/bash -c "cd /root/test && ./test-ulcl.sh TestULCLTrafficInfluence"
        ;;
        "exec")
            docker exec -it ci bash
        ;;
    esac
}

main "$@"