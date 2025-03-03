fmt:
	cargo +nightly fmt

lint: fmt
	cargo clippy --tests --all-targets --all-features -- -D warnings

run_device:
	cargo run -- \
		--dvault-private-key-file data/dvault_private_key_$(number).txt \
		--dvault-public-key-file data/dvault_public_key_$(number).txt \
		--sc-owner-public-key jy2p2-3v7up-eyuzb-66rjx-ijazo-tyvvw-mbbyb-ritst-coaqx-2cukv-oae \
		--sc-device-private-key-file data/sc_private_key_$(number).txt \
		run

run_ipfs:
	docker run --rm --name ipfs_host \
		-p 4001:4001 -p 4001:4001/udp -p 8080:8080 -p 5001:5001 \
		ipfs/kubo:v0.33.2
