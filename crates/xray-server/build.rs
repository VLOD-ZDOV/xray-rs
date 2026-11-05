fn main() {
    println!("cargo:rerun-if-changed=src/compat.c");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        cc::Build::new()
            .file("src/compat.c")
            .flag("-fno-stack-protector")
            .compile("xray_compat");
    }
}
