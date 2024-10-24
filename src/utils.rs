use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use std::path::Path;
use std::string::FromUtf8Error;

pub fn encode(s: &str) -> String {
    STANDARD_NO_PAD.encode(s)
}

pub fn decode(s: &str) -> Result<String, FromUtf8Error> {
    String::from_utf8(STANDARD_NO_PAD.decode(s).unwrap())
}

pub fn get_contents_vec<P: AsRef<Path>>(path: P) -> std::io::Result<Vec<String>> {
    let file = std::fs::read_to_string(path)?;
    Ok(file.split("\n").map(String::from).collect::<Vec<String>>())
}

#[test]
fn encode_test() {
    let val = "1143657502941122580";
    assert_eq!(&encode(val), "MTE0MzY1NzUwMjk0MTEyMjU4MA")
}

#[test]
fn decode_test() {
    let val = "MTE0MzY1NzUwMjk0MTEyMjU4MA";
    assert_eq!(&decode(val).unwrap(), "1143657502941122580")
}
