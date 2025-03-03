fmt:
	cargo +nightly fmt

lint: fmt
	cargo clippy --tests --all-targets --all-features -- -D warnings

run_owner:
	cargo run -- run

run_device_1:
	cargo run -- run \
		--dvault-private-key-file data/dvault_private_key_1.txt \
		--dvault-public-key-file data/dvault_public_key_1.txt \
		--sc-owner-public-key o4xvx-uc2km-35uqh-gayve-jttup-lec54-f4isr-ixb7s-ur33j-vqoyx-zqe \
		--sc-device-private-key-file data/sc_private_key_1.txt \
