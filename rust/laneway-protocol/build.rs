fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_root = "../../api/proto";
    let protos = [
        "../../api/proto/laneway/v1/control.proto",
        "../../api/proto/laneway/v1/controller.proto",
        "../../api/proto/laneway/v1/policy.proto",
        "../../api/proto/laneway/v1/relay.proto",
        "../../api/proto/laneway/v1/routes.proto",
    ];
    for proto in protos {
        println!("cargo:rerun-if-changed={proto}");
    }
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc);
    config.compile_protos(&protos, &[proto_root])?;
    Ok(())
}
