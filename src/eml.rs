pub fn qp_encode(decoded: &str) -> String {
    let mut encoded = String::new();
    let mut counter = 0;
    for char in decoded.chars() {
        if char.is_ascii() {
            let mut char_data = [0u8; 1];
            char.encode_utf8(&mut char_data);
            let encode = match char_data[0] {
                61 => true,
                33..=126 => false,
                b' ' => false,
                b'\t' => false,
                _ => true,
            };
            if encode {
                if counter > 75 - 3 {
                    encoded.push_str("=\n");
                    counter = 0;
                }
                counter += 3;
                encoded.push_str(&format!("={:02X}", char_data[0]));
            } else {
                if counter == 75 {
                    encoded.push_str("=\n");
                    counter = 0;
                }
                counter += 1;
                encoded.push(char);
            }
        } else {
            let mut buffer = [0u8; 4];
            let encoded_char = char.encode_utf8(&mut buffer);
            if counter > 75 - encoded_char.len() * 3 {
                encoded.push_str("=\n");
                counter = 0;
            }
            counter += encoded_char.len() * 3;
            for byte in encoded_char.as_bytes() {
                encoded.push_str(&format!("={:02X}", byte));
            }
        }
    }

    encoded
}

pub fn qp_decode(encoded: &str) -> String {
    let mut chars = encoded.chars();
    let mut decoded_raw = Vec::<u8>::with_capacity(encoded.len());
    while let Some(char) = chars.next() {
        if char == '=' {
            match chars.next() {
                Some('\n') => continue,
                Some(next_char) => {
                    let second_digit = chars.next().unwrap_or('0');
                    let hex = format!("{}{}", next_char, second_digit);
                    match u8::from_str_radix(&hex, 16) {
                        Ok(byte) => decoded_raw.push(byte),
                        Err(_) => continue,
                    }
                }
                None => continue,
            }
        } else {
            let mut buffer = [0u8; 4];
            let encoded_char = char.encode_utf8(&mut buffer);
            decoded_raw.extend_from_slice(&encoded_char.as_bytes());
        }
    }

    String::from_utf8_lossy(&decoded_raw).to_string()
}
