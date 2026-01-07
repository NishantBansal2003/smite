#!/bin/bash -eu

sudo modprobe -r kvm-intel
sudo modprobe -r kvm
sudo modprobe  kvm enable_vmware_backdoor=y
sudo modprobe  kvm-intel
cat /sys/module/kvm/parameters/enable_vmware_backdoor | grep -q Y && echo OK || echo KVM module problem
