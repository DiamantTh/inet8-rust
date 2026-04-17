# SPDX-License-Identifier: GPL-3.0
#
# Kbuild file for the inet8 Rust kernel module.
#
# Usage (from the kernel source tree or out-of-tree):
#   make -C /path/to/linux M=$(pwd) modules
#
# The kernel build system compiles each .rs file listed below as a Rust
# translation unit and links them into inet8.ko.

obj-m := inet8.o

inet8-objs := \
	src/lib.o    \
	src/addr.o   \
	src/header.o \
	src/route.o  \
	src/device.o \
	src/socket.o \
	src/netlink.o

# Pass --features kernel so that the no_std / kernel-binding paths are chosen.
KBUILD_RUSTFLAGS += --cfg 'feature="kernel"'
