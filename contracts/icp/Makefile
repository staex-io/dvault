fmt:
	cargo +nightly fmt

lint: fmt
	cargo clippy --tests --all-targets --all-features -- -D warnings

test:
	cargo test tests::unit_test --jobs 1 -- --nocapture --test-threads 1

test_e2e: export_identity
	cargo test --jobs 1 -- --nocapture --test-threads 1 $(name)

start:
	dfx start --clean --host 127.0.0.1:7777

pre_install:
	dfx canister create dvault

install: pre_install update_candid
	dfx canister install --async-call -y dvault --wasm ../../target/wasm32-unknown-unknown/release/dvault.wasm

reinstall: update_candid
	dfx canister install --mode reinstall --async-call -y dvault --wasm ../../target/wasm32-unknown-unknown/release/dvault.wasm

update_candid:
	cargo build --target wasm32-unknown-unknown --release -p dvault --locked
	candid-extractor ../../target/wasm32-unknown-unknown/release/dvault.wasm > dvault.did

export_identity:
	dfx identity export default >identity.pem
