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
        for j in 0..8 {
            // get 32-bit key part
            let key_part = &key[j * 4..j * 4 + 4];

            // apply encryption function to right half of block
            let hashed_prev_right_half = encryption_step(&hashed_block[4..8], key_part);

            // XOR left half with result of encryption right half of previous block
            let mut new_left_half = hashed_block.iter().take(4).enumerate()
                .map(|(i, &x)| x ^ hashed_prev_right_half[i])
                .collect::<Vec<u8>>();

            // get right half of previous block
            let mut prev_right_half = hashed_block.iter().cloned().skip(4).collect::<Vec<u8>>();

            // swap halves
            prev_right_half.append(&mut new_left_half);

            hashed_block = prev_right_half;
        }
    }

    // 25-31 rounds
    for j in (1..8).rev() {
        // get 32-bit key part
        let key_part = &key[j * 4..j * 4 + 4];

        // apply encryption function to right half of block
        let hashed_prev_right_half = encryption_step(&hashed_block[4..8], key_part);

        // XOR left half with result of encryption right half of previous block
        let mut new_left_half = hashed_block.iter().take(4).enumerate()
            .map(|(i, &x)| x ^ hashed_prev_right_half[i])
            .collect::<Vec<u8>>();

        // get right half of previous block
        let mut prev_right_half = hashed_block.iter().cloned().skip(4).collect::<Vec<u8>>();

        // swap halves
        prev_right_half.append(&mut new_left_half);

        hashed_block = prev_right_half;
    }

    // 32th round (without halves swap)
    // get 32-bit key part
    let key_part = &key[0..4];

    // apply encryption function to right half of block
    let hashed_prev_right_half = encryption_step(&hashed_block[4..8], key_part);

    // XOR left half with result of encryption right half of previous block
    let mut new_left_half = hashed_block.iter().take(4).enumerate()
        .map(|(i, &x)| x ^ hashed_prev_right_half[i])
        .collect::<Vec<u8>>();

    // get right half of previous block
    let mut prev_right_half = hashed_block.iter().cloned().skip(4).collect::<Vec<u8>>();

    // concatenate halves without swapping
    new_left_half.append(&mut prev_right_half);

    hashed_block = new_left_half;

    match hashed_block.try_into() {
        Ok(hashed_block) => hashed_block,
        Err(_) => panic!("Failed to encrypt block")
    }
}

fn encryption_step(data: &[u8], key_part: &[u8]) -> [u8; 4] {
    // (data + key_part) mod 2^32
    let data_plus_key = (
        u32::from_be_bytes(data.try_into().unwrap())
            .wrapping_add(u32::from_be_bytes(key_part.try_into().unwrap()))
        ).to_be_bytes();

    let mut encrypted_block = [0u8; 4];

    for (i, &x) in data_plus_key.iter().enumerate() {
        // split byte into 2 parts
        let first_4_bits = x >> 4;
        let last_4_bits = x & 0x0F;
        let result_byte = (S_BOX[i][first_4_bits as usize] << 4) | S_BOX[i][last_4_bits as usize];
        encrypted_block[i] = result_byte;
    }

    encrypted_block
}

pub fn encrypt(data_to_encrypt: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    let bytes_to_encrypt = data_to_encrypt.len();
    if bytes_to_encrypt % 8 != 0 {
        return Err(format!("Длина входящих данных должна быть кратна 8. Текущая длина: {} байт", bytes_to_encrypt));
    }

    let mut encrypted_data: Vec<u8> = Vec::new();
    for i in 0..data_to_encrypt.len() / 8 {
        let data_block = &data_to_encrypt[i * 8..(i + 1) * 8];
        let encrypted_block = encrypt_block(data_block, key);
        encrypted_data.extend_from_slice(encrypted_block.as_slice());
    }

    Ok(encrypted_data)
}

pub fn decrypt(_hash: &str, _key: &str) -> String {
    String::new()
}
