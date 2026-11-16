// A secret of the user, a password: its bytes are overwritten with zeros when it's dropped, so they don't stay behind
// in the freed memory of the app. As far as this code goes: the windows, the system and the network have their copies.

use std::fmt;
use std::ops::Deref;
use std::ptr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Default, Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl From<String> for Secret {
    fn from(text: String) -> Secret {
        Secret(text)
    }
}

impl From<&str> for Secret {
    fn from(text: &str) -> Secret {
        Secret(text.to_string())
    }
}

impl Deref for Secret {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

// never in a log
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Secret(..)")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Secret, D::Error> {
        String::deserialize(deserializer).map(Secret)
    }
}

// Overwrites the bytes of the text with zeros, then empties it: its memory stays its own, until it's dropped
pub fn wipe(text: &mut String) {
    // SAFETY: zeros are valid UTF-8, and the text is emptied right after
    let bytes = unsafe { text.as_mut_vec() };
    for byte in bytes.iter_mut() {
        unsafe { ptr::write_volatile(byte, 0) };
    }
    bytes.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wiped() {
        let mut text = String::from("Secret,1234");
        let (pointer, length) = (text.as_ptr(), text.len());
        wipe(&mut text);
        assert!(text.is_empty());
        // the same memory, still the text's: zeros only
        let bytes = unsafe { std::slice::from_raw_parts(pointer, length) };
        assert!(bytes.iter().all(|&byte| byte == 0));
    }

    #[test]
    fn a_secret_reads_as_text() {
        let secret = Secret::from("Secret,1234");
        assert_eq!((&*secret, secret.len(), secret.as_str()), ("Secret,1234", 11, "Secret,1234"));
        assert_eq!(format!("{:?}", secret), "Secret(..)");
        // in the keychain item of macOS
        assert_eq!(serde_json::to_string(&secret).unwrap(), "\"Secret,1234\"");
        assert_eq!(serde_json::from_str::<Secret>("\"a\\\"b\"").unwrap().as_str(), "a\"b");
    }
}
