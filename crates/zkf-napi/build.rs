fn main() {
    println!("cargo::rustc-check-cfg=cfg(zkf_pad_indirect)");
    napi_build::setup();
}
