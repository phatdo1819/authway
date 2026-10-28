// The file of a VPN that the user adds: read and checked as the service does it, before it goes to the service

use std::fs;
use std::path::Path;

use crate::api::Page;
use crate::conf;
use crate::settings;
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

// The login given with --import ... --username <username> [--password <password>], saved as the login window saves
// it: for the login page of the configuration, so the window is filled in the first time
pub struct Login {
    pub username: String,
    pub password: Option<String>,
}

// the login page the login is for, or the text for the administrator
pub fn login_page(config: &conf::Config, login: &Login) -> Result<Page, String> {
    let page = config.login.as_deref().and_then(Page::parse).ok_or_else(|| strings::IMPORT_LOGIN_NO_PAGE.to_string())?;
    if login.password.is_some() && !settings::can_remember_password() {
        return Err(strings::IMPORT_LOGIN_NO_REMEMBER.to_string());
    }
    Ok(page)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(login: &str) -> conf::Config {
        let text = format!(
            "[Interface]\n{}PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.103.1.2\n\n[Peer]\n\
             PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 10.103.1.0/24\n\
             Endpoint = vpn.example.com:51820\n",
            login
        );
        conf::parse(&text).unwrap()
    }

    #[test]
    fn login_for_the_page_of_the_configuration() {
        let login = Login { username: "alice".to_string(), password: None };
        let page = login_page(&config("# Login = http://10.103.1.1:8181/\n"), &login).unwrap();
        assert_eq!((page.host.to_string().as_str(), page.port), ("10.103.1.1", 8181));
        // nothing to save it for
        assert_eq!(login_page(&config(""), &login).err().as_deref(), Some(strings::IMPORT_LOGIN_NO_PAGE));
    }
}
