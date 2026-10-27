// Embeds the icons, the manifest and the version in the exe

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

#[allow(dead_code)]
mod product {
    include!("src/product.rs");
}

// the resource IDs, the same as src/ui/icons.rs
const ICONS: [(u16, &str); 5] = [
    (1, "app.ico"),
    (2, "idle.ico"),
    (3, "attention.ico"),
    (4, "connected.ico"),
    (5, "refused.ico"),
];

fn quoted(path: &Path) -> String {
    format!("\"{}\"", path.display().to_string().replace('\\', "\\\\"))
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // the bundle of macOS has its own Info.plist, made by tools/dist-macos.sh
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let version = env::var("CARGO_PKG_VERSION").unwrap();
    let numbers: Vec<u16> = version
        .split(['.', '-', '+'])
        .take(3)
        .map(|part| part.parse().unwrap_or(0))
        .collect();
    let numeric = format!("{},{},{},0", numbers[0], numbers[1], numbers[2]);

    let mut rc = String::from("#pragma code_page(65001)\n#include <winver.h>\n");
    for (id, file) in ICONS {
        let path = root.join("assets").join(file);
        println!("cargo:rerun-if-changed={}", path.display());
        rc += &format!("{} ICON {}\n", id, quoted(&path));
    }
    let manifest = root.join("app.manifest");
    println!("cargo:rerun-if-changed={}", manifest.display());
    // CREATEPROCESS_MANIFEST_RESOURCE_ID, RT_MANIFEST
    rc += &format!("1 24 {}\n", quoted(&manifest));
    rc += &format!(
        r#"1 VERSIONINFO
FILEVERSION {numeric}
PRODUCTVERSION {numeric}
FILEOS VOS_NT_WINDOWS32
FILETYPE VFT_APP
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904b0"
    BEGIN
      VALUE "CompanyName", "{manufacturer}"
      VALUE "FileDescription", "{product}"
      VALUE "FileVersion", "{version}"
      VALUE "InternalName", "{exe}"
      VALUE "OriginalFilename", "{exe}"
      VALUE "ProductName", "{product}"
      VALUE "ProductVersion", "{version}"
      VALUE "LegalCopyright", "{license}"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
"#,
        product = product::PRODUCT,
        manufacturer = product::MANUFACTURER,
        exe = product::EXE_NAME,
        license = env::var("CARGO_PKG_LICENSE").unwrap_or_default(),
    );
    let rc_path = out.join("app.rc");
    fs::write(&rc_path, rc).unwrap();
    println!("cargo:rerun-if-changed=src/product.rs");
    // the tests too: the task dialog is in the controls of the manifest only
    embed_resource::compile_for_everything(&rc_path, embed_resource::NONE)
        .manifest_required()
        .unwrap();
}
