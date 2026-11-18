use super::*;

#[test]
fn utf16_round_trip_preserves_cyrillic_paths_and_nul_terminator() {
    let path = r#"file:///C:/Users/Иван Петров/AppData/Local/Zastava/proxy.pac"#;
    let units = encode_utf16_nul(path);
    assert_eq!(units.last(), Some(&0));

    let bytes = encode_utf16_le_bytes(path);
    assert_eq!(bytes.len(), units.len() * 2);
    assert_eq!(decode_utf16_le_string(&bytes).unwrap(), path);
}

#[test]
fn decode_utf16_handles_empty_extra_nuls_and_rejects_malformed() {
    assert_eq!(decode_utf16_le_string(&[]).unwrap(), "");
    assert_eq!(decode_utf16_le_string(&[0, 0]).unwrap(), "");
    assert_eq!(
        decode_utf16_le_string(&[0x41, 0x00, 0, 0, 0, 0]).unwrap(),
        "A"
    );
    // Odd byte length
    assert!(decode_utf16_le_string(&[0x41, 0x00, 0x42]).is_err());
    // Unpaired UTF-16 high surrogate
    assert!(decode_utf16_le_string(&[0x00, 0xD8, 0x00, 0x00]).is_err());
}

#[test]
fn decode_multi_sz_extracts_items_and_skips_empty_terminators() {
    let mut bytes = Vec::new();
    for item in ["ru-RU", "en-US", "  ", "de-DE"] {
        bytes.extend(encode_utf16_le_bytes(item));
    }
    bytes.extend([0, 0]);
    assert_eq!(
        decode_multi_sz(&bytes).unwrap(),
        vec![
            "ru-RU".to_string(),
            "en-US".to_string(),
            "de-DE".to_string()
        ]
    );
    assert!(decode_multi_sz(&[0x41]).is_err());
}

#[test]
fn decode_dword_requires_four_bytes() {
    assert_eq!(decode_dword(&3u32.to_le_bytes()).unwrap(), 3);
    assert_eq!(
        decode_dword(&0xdead_beefu32.to_le_bytes()).unwrap(),
        0xdead_beef
    );
    assert!(decode_dword(&[1, 2, 3]).is_err());
}

#[test]
fn not_found_statuses_and_root_names() {
    assert!(is_not_found_status(ERROR_FILE_NOT_FOUND));
    assert!(is_not_found_status(ERROR_PATH_NOT_FOUND));
    assert!(!is_not_found_status(ERROR_SUCCESS));
    assert!(!is_not_found_status(5));
    assert_eq!(RootKey::HkeyCurrentUser.as_str(), "HKCU");
    assert_eq!(RootKey::HkeyLocalMachine.as_str(), "HKLM");
}
