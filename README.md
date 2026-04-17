# inet8-rust

A minimal IPv8 Layer-3 network stack implemented as a Linux kernel module in Rust.

## Requirements

| Requirement | Minimum version |
|-------------|----------------|
| Linux kernel | **6.11** (Rust support officially stabilised) |
| Kernel config | `CONFIG_RUST=y` must be enabled |
| Rust toolchain | **1.85.0** (see [`rust-toolchain.toml`](rust-toolchain.toml)) |

> **Note:** Starting with kernel 7.1 the minimum required Rust version is
> expected to be raised to 1.85.0 (the version shipped with Debian 13
> "Trixie").  This repository already targets that baseline.

## Building

### Against the running kernel

```sh
make
```

### Against a specific kernel

```sh
make KDIR=/lib/modules/<version>/build
```

### Without kernel headers (unit tests / `cargo check`)

```sh
make check   # cargo check
make test    # cargo test
```

## Installation

```sh
sudo make modules_install
sudo depmod -a
sudo modprobe inet8
```

## DKMS (automatic rebuild on kernel updates)

[DKMS](https://github.com/dell/dkms) automates recompiling the module
whenever a new kernel is installed.  The repository ships a ready-to-use
`dkms.conf`.

```sh
# Register the module source with DKMS
sudo dkms add .

# Build and install for the running kernel
sudo dkms install inet8/0.1.0

# Verify
dkms status
```

**DKMS requirements:**
- The target kernel must be built with `CONFIG_RUST=y`
- The kernel build directory (`/lib/modules/<version>/build`) must contain
  the Rust metadata generated at kernel build time
- Rust ≥ 1.85.0 must be available on the build machine

## Kernel version notes

| Kernel | Rust support | Notes |
|--------|-------------|-------|
| < 6.1  | none        | Not supported |
| 6.1 – 6.10 | experimental | Unstable ABI, not recommended |
| **6.11 – 6.x** | official | Minimum supported version |
| **7.0+** | stable / first-class | Recommended |

## License

GPL-3.0 — see [LICENSE](LICENSE).