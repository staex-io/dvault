fmt:
	cargo +nightly fmt

lint: fmt
	cargo clippy --tests --all-targets --all-features -- -D warnings

run:
	cargo run -- run

device_1:
	cargo run -- run \
		--device-owner-public-key 4ny6d-muect-mutto-ny7jl-eyfuo-6vtb5-wbugl-vaacu-4vugg-jjgag-bae \
		--secret-key-file secret_key_1.txt
