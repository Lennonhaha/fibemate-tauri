fn main() {
    // Build the Tauri app attributes WITHOUT the default Windows app manifest.
    //
    // Rationale: tauri_build embeds the manifest (a Common Controls v6 dependency
    // required by `tao`/comctl32) via `winres`, which only applies to the *main*
    // binary. Unit-test binaries (compiled from `lib.rs`) never receive it, so any
    // test that pulls in `tauri::Window`/`tauri::test::mock_builder` crashes at load
    // time with STATUS_ENTRYPOINT_NOT_FOUND (0xc0000139) on Windows.
    //
    // We instead embed the SAME manifest via `rustc-link-arg`, which applies to every
    // linkable artifact (bin + unit test). See tauri-apps/tauri#13419.
    let attributes = tauri_build::Attributes::new();

    #[cfg(windows)]
    let attributes =
        attributes.windows_attributes(tauri_build::WindowsAttributes::new_without_app_manifest());

    tauri_build::try_build(attributes).expect("failed to run tauri-build");

    #[cfg(windows)]
    {
        let manifest =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("windows-app-manifest.xml");
        println!("cargo:rerun-if-changed={}", manifest.display());
        println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", manifest.display());
    }
}
