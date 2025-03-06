#!/bin/bash

CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=~/.cargo/zig_cc_x86_64-linux-gnu cargo build --target x86_64-unknown-linux-gnu --bin gpt --release