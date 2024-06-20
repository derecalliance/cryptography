java_run: lib
	gradle run

.PHONY: lib
.PHONY: proto

lib:
	cd derec_crypto_bridge_lib && cargo build

clean:
	gradle clean
	cd derec_crypto_bridge_lib && cargo clean
