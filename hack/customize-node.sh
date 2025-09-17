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

apt-get update && apt-get install -y bridge-utils net-tools
mkdir -p /opt/cni/bin && rm -rf /opt/cni/bin/*
tar -xzf /opt/cni-plugins.tgz -C /opt/cni/bin

chmod +x /opt/cni/bin/*
chown -R root:root /opt/cni

/usr/sbin/ip link add link eth0 name eth0.999 type vlan id 999
/usr/sbin/brctl addbr br0
/usr/sbin/brctl addif br0 eth0.999

ifconfig br0 192.168.200.1 netmask 255.255.255.0
