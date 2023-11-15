java_run: lib
	javac DerecCryptoBridge.java && java -Djava.library.path=derec_crypto_bridge_lib/target/debug/ DerecCryptoBridge

.PHONY: lib

javah:
	javah DerecCryptoBridge

lib:
	cd derec_crypto_bridge_lib && cargo build
