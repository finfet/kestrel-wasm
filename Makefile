all: build

build:
	wasm-bindgen --out-dir dist --target web --no-typescript target/wasm32-unknown-unknown/release/kestrel_wasm.wasm

clean:
	rm -rf dist

.PHONY: all build clean
