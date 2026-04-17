# SPDX-License-Identifier: GPL-3.0
#
# Top-level Makefile for the inet8 IPv8 kernel module.
#
# Targets
# -------
# make                – build as a kernel module (requires KDIR)
# make KDIR=<path>    – specify kernel source / headers directory
# make check          – run `cargo check` without kernel headers
# make test           – run `cargo test` without kernel headers
# make clean          – remove build artefacts

KDIR ?= /lib/modules/$(shell uname -r)/build

.PHONY: all modules check test clean

all: modules

modules:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules

modules_install:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules_install

# Run Rust unit tests (no kernel headers required).
check:
	cargo check

test:
	cargo test

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
	cargo clean
