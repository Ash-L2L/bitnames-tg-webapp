# Bitnames Telegram Web App

# Requirements

1. Rustc & Cargo, version 1.85.0 or higher. Installing via Rustup is
   recommended.

# Getting started

Building/running:

```bash
# Checkout submodules
$ git submodule update --init --recursive

# Install wasm-pack
$ cargo install wasm-pack

# Build web app app
$ wasm-pack build webapp --target web --out-dir "$(pwd)/dist"

# Compiles the project
$ cargo build
```