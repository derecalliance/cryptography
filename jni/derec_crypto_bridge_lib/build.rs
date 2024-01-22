fn main() {
    protobuf_codegen::Codegen::new()
        .cargo_out_dir("bridgeproto")
        .include("src/proto/bridge")
        .input("src/proto/bridge/bridge.proto")
        .run_from_script();

    protobuf_codegen::Codegen::new()
        .cargo_out_dir("derecproto")
        .include("src/proto/protobufs")
        .input("src/proto/protobufs/storeshare.proto")
        .input("src/proto/protobufs/parameterrange.proto")
        .input("src/proto/protobufs/result.proto")
        .run_from_script();

}
