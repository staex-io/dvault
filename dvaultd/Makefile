fmt:
	cargo +nightly fmt

lint: fmt
	cargo clippy --tests --all-targets --all-features -- -D warnings

run_device:
	cargo run -- \
		--dvault-private-key-file data/dvault_private_key_$(n).txt \
		--dvault-public-key-file data/dvault_public_key_$(n).txt \
		--dvault-owner-public-key xUiLzrvBS+k17IzyvHI9LtSJfQj+th1GhzHolagfHbk= \
		--sc-owner-public-key 4ya5w-6ezo4-e23zo-amr2q-uoluc-wpdvs-7qtlp-btgfu-wifhy-3xdck-cqe \
		--sc-device-private-key-file data/sc_private_key_$(n).txt \
		--tag tag_$(n) \
		run
