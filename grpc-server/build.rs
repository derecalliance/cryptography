fn main() {
    tonic_build::configure()
        .build_server(true) // Generate server code
        .out_dir("src/protos") // Output directory
        .compile_protos(&["proto/service.proto"], &["proto"])
        .expect("Failed to compile Protobuf files");
}