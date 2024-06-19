all: deps run

deps:
	mkdir -p native_libs libs
	cp ../jni/build/libs/derec-crypto-bridge-1.0-SNAPSHOT.jar libs/derec-crypto-bridge.jar
	cp ../jni/derec_crypto_bridge_lib/target/debug/libderec_crypto_bridge_lib.dylib native_libs/
	

run:
	mvn clean compile
	export MAVEN_OPTS=-Djava.library.path=$(pwd)/native_libs
	mvn exec:java -Dexec.mainClass=com.example.App -Dexec.classpathScope=compile

clean:
	mvn clean
	rm -rf libs native_libs
