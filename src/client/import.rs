// The file of a VPN that the user adds: read and checked as the service does it, before it goes to the service

use std::fs;
use std::path::Path;

use crate::conf;
use crate::strings;

const MAX_FILE: u64 = 64 * 1024;

// UTF-8, with or without its mark, or the UTF-16 of Notepad
fn read_config(path: &Path) -> Result<String, String> {
    let size = fs::metadata(path).map_err(|error| error.to_string())?.len();
    if size > MAX_FILE {
        return Err("the file is too big".to_string());
    }
    let data = fs::read(path).map_err(|error| error.to_string())?;
    if let Some(rest) = data.strip_prefix(&[0xff, 0xfe]) {
        let text: Vec<u16> = rest.chunks_exact(2).map(|pair| u16::from_le_bytes([pair[0], pair[1]])).collect();
        return String::from_utf16(&text).map_err(|_| "the file isn't text".to_string());
    }
    let data = data.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(&data);
    String::from_utf8(data.to_vec()).map_err(|_| "the file isn't text".to_string())
}

// the name for a tunnel of the file: the name of the server, or of the file
pub fn name_for(config: &conf::Config, path: &Path) -> String {
    let stem = path.file_stem().map(|stem| stem.to_string_lossy().to_string()).unwrap_or_default();
    conf::name_from(config.server_name().unwrap_or(&stem))
}

// The configuration, with the text for the user if it isn't good
pub fn load(path: &Path) -> Result<(String, conf::Config), String> {
    let text = read_config(path).map_err(|error| strings::import_unreadable(&error))?;
    let config = conf::parse(&text).map_err(|error| strings::import_invalid(&error.to_string()))?;
    Ok((text, config))
}
