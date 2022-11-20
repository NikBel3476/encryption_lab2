const S_BOX_ROWS_AMOUNT: usize = 8;
const S_BOX_COLUMNS_AMOUNT: usize = 16;

// RFC 7836. id: id-tc26-gost-28147-param-Z
const S_BOX: [[u8; S_BOX_COLUMNS_AMOUNT]; S_BOX_ROWS_AMOUNT] = [
    [0x0C, 0x04, 0x06, 0x02, 0x0A, 0x05, 0x0B, 0x09, 0x0E, 0x08, 0x0D, 0x07, 0x00, 0x03, 0x0F, 0x01],
    [0x06, 0x08, 0x02, 0x03, 0x09, 0x0A, 0x05, 0x0C, 0x01, 0x0E, 0x04, 0x07, 0x0B, 0x0D, 0x00, 0x0F],
    [0x0B, 0x03, 0x05, 0x08, 0x02, 0x0F, 0x0A, 0x0D, 0x0E, 0x01, 0x07, 0x04, 0x0C, 0x09, 0x06, 0x00],
    [0x0C, 0x08, 0x02, 0x01, 0x0D, 0x04, 0x0F, 0x06, 0x07, 0x00, 0x0A, 0x05, 0x03, 0x0E, 0x09, 0x0B],
    [0x07, 0x0F, 0x05, 0x0A, 0x08, 0x01, 0x06, 0x0D, 0x00, 0x09, 0x03, 0x0E, 0x0B, 0x04, 0x02, 0x0C],
    [0x05, 0x0D, 0x0F, 0x06, 0x09, 0x02, 0x0C, 0x0A, 0x0B, 0x07, 0x08, 0x01, 0x04, 0x03, 0x0E, 0x00],
    [0x08, 0x0E, 0x02, 0x05, 0x06, 0x09, 0x01, 0x0C, 0x0F, 0x04, 0x0B, 0x00, 0x0D, 0x0A, 0x03, 0x07],
    [0x01, 0x07, 0x0E, 0x0D, 0x00, 0x05, 0x08, 0x03, 0x04, 0x0F, 0x0A, 0x06, 0x09, 0x0C, 0x0B, 0x02]
];

// encrypt 64-bit block with 256-bit key
fn encrypt_block(data: &[u8], key: &[u8]) -> [u8; 8] {
    // Keys sequence
    // K0..K7 K0..K7 K0..K7 K7..K0

    let mut hashed_block: Vec<u8> = Vec::from(data);

    // 1-24 rounds
    for _ in 0..3 {
        for i in 0..8 {
            // get 32-bit key part
            let key_part = &key[i * 4..i * 4 + 4];
            hashed_block = crypt_round(hashed_block, key_part, false);
        }
    }

    // 25-31 rounds
    for i in (1..8).rev() {
        // get 32-bit key part
        let key_part = &key[i * 4..i * 4 + 4];
        hashed_block = crypt_round(hashed_block, key_part, false);
    }

    // 32th round (without halves of block swap)
    // get 32-bit key part
    let key_part = &key[0..4];
    hashed_block = crypt_round(hashed_block, key_part, true);

    match hashed_block.try_into() {
        Ok(hashed_block) => hashed_block,
        Err(_) => panic!("Failed to encrypt block")
    }
}

// decrypt 64-bit block with 256-bit key
fn decrypt_block(data: &[u8], key: &[u8]) -> [u8; 8] {
    // Keys sequence
    // K0..K7 K7..K0 K7..K0 K7..K0

    let mut decrypted_block: Vec<u8> = Vec::from(data);

    // 1-8 rounds
    for i in 0..8 {
        // get 32-bit key part
        let key_part = &key[i * 4..i * 4 + 4];
        decrypted_block = crypt_round(decrypted_block, key_part, false);
    }

    // 9-24 rounds
    for _ in 0..2 {
        for i in (0..8).rev() {
            // get 32-bit key part
            let key_part = &key[i * 4..i * 4 + 4];
            decrypted_block = crypt_round(decrypted_block, key_part, false);
        }
    }

    // 25-31 rounds
    for i in (1..8).rev() {
        // get 32-bit key part
        let key_part = &key[i * 4..i * 4 + 4];
        decrypted_block = crypt_round(decrypted_block, key_part, false);
    }

    // 32th round (without halves of block swap)
    // get 32-bit key part
    let key_part = &key[0..4];
    decrypted_block = crypt_round(decrypted_block, key_part, true);

    match decrypted_block.try_into() {
        Ok(decrypted_block) => decrypted_block,
        Err(_) => panic!("Failed to decrypt block")
    }
}

fn crypt_round(block_to_encrypt: Vec<u8>, key_part: &[u8], is_last_step: bool) -> Vec<u8> {
    // apply encryption function to right half of block
    let hashed_prev_right_half = crypt_round_fn(&block_to_encrypt[4..8], key_part);

    // XOR left half with result of encryption right half of previous block
    let mut new_left_half = block_to_encrypt.iter().take(4).enumerate()
        .map(|(i, &x)| x ^ hashed_prev_right_half[i])
        .collect::<Vec<u8>>();

    // get right half of previous block
    let mut prev_right_half = block_to_encrypt.iter().cloned().skip(4).collect::<Vec<u8>>();

    if is_last_step {
        // concatenate halves without swapping
        new_left_half.append(&mut prev_right_half);
        new_left_half
    } else {
        // swap halves
        prev_right_half.append(&mut new_left_half);
        prev_right_half
    }
}

fn crypt_round_fn(data: &[u8], key_part: &[u8]) -> [u8; 4] {
    // (data + key_part) mod 2^32
    let data_plus_key = (
        u32::from_be_bytes(data.try_into().unwrap())
            .wrapping_add(u32::from_be_bytes(key_part.try_into().unwrap()))
        ).to_be_bytes();

    let mut encrypted_block = [0u8; 4];

    for (i, &x) in data_plus_key.iter().enumerate() {
        // split byte into 2 halves
        let high_4_bits = x >> 4;
        let low_4_bits = x & 0x0F;

        let result_byte =(S_BOX[i][high_4_bits as usize] << 4) | S_BOX[i + 1][low_4_bits as usize];
        // left circular shift by 11 bits
        encrypted_block[i] = result_byte.rotate_left(11);
    }

    encrypted_block
}

pub fn encrypt(data_to_encrypt: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    let bytes_to_encrypt = data_to_encrypt.len();
    if bytes_to_encrypt % 8 != 0 {
        return Err(format!(
            "Длина входящих данных должна быть кратна 8 байтам. Текущая длина: {} байт",
            bytes_to_encrypt
        ));
    }

    let mut encrypted_data: Vec<u8> = Vec::new();
    for i in 0..data_to_encrypt.len() / 8 {
        let data_block = &data_to_encrypt[i * 8..(i + 1) * 8];
        let encrypted_block = encrypt_block(data_block, key);
        encrypted_data.extend_from_slice(encrypted_block.as_slice());
    }

    Ok(encrypted_data)
}

pub fn decrypt(data_to_decrypt: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    let bytes_to_decrypt = data_to_decrypt.len();
    if bytes_to_decrypt % 8 != 0 {
        return Err(format!(
            "Количество байт должно быть кратно 8. Текущая длина: {} байт",
            bytes_to_decrypt
        ));
    }

    let mut decrypted_data: Vec<u8> = Vec::new();
    for i in 0..data_to_decrypt.len() / 8 {
        let data_block = &data_to_decrypt[i * 8..(i + 1) * 8];
        let encrypted_block = decrypt_block(data_block, key);
        decrypted_data.extend_from_slice(encrypted_block.as_slice());
    }

    Ok(decrypted_data)
}

pub fn str_to_bytes(data: &str) -> Result<Vec<u8>, String> {
    data.split(", ").map(|x| {
        match x.parse::<u8>() {
            Ok(x) => Ok(x),
            Err(_) => Err(String::from("Не удалось преобразовать массив байтов"))
        }
    }).collect::<Result<Vec<u8>, String>>()
}
