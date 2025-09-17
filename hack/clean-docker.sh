#!/bin/bash
# Copyright 2025 Marcelo Parisi (github.com/feitnomore)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.



# Function to print the spinning bar
spin() {
    local i
    local chars=( "/" "-" "\\" "|" )
    local interval=0.2
    for i in "${!chars[@]}"; do
        cr
        printf "[${chars[$i]}] Cleaning $1    "
        sleep "$interval"
    done
}

finish() {
    cr
    printf "[+] Cleaning $1: DONE!"
    local m
    for m in {1..64}; do
        printf " "
    done
    echo ""
}

cr() {
    local j
    for j in {1..64}; do
        printf "\r"
    done
}

clean_images() {
    docker images -a | grep -v REPOSITORY | grep -vi kind | grep -vi worker | while read image
    do
        spin "images"
        THIS_ID=`echo $image | awk '{print $3}'`
        docker rmi ${THIS_ID} --force > /dev/null 2>&1
    done
    finish "images" 
}

clean_containers() {
    docker ps -a | grep -v CONTAINER | grep -vi kind | grep -vi control | while read container
    do
        spin "containers"
        THIS_ID=`echo $container | awk '{print $1}'`
        docker rm ${THIS_ID} --force > /dev/null 2>&1
    done
    finish "containers" 
}

clean_containers
clean_images
