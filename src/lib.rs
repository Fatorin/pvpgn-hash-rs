use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Error, ErrorKind, Seek, SeekFrom, Write};

pub fn get_hash_bytes(password: Vec<u8>) -> Result<Vec<u8>, ErrorKind> {
    let str_result = match std::str::from_utf8(&password) {
        Ok(s) => s,
        Err(_) => return Err(ErrorKind::InvalidData),
    };
    calculate_hash(&str_result)
}

pub fn get_hash_string(password: &str) -> Result<String, ErrorKind> {
    let bytes = match calculate_hash(password) {
        Ok(data) => data,
        Err(_) => return Err(ErrorKind::InvalidData),
    };

    let hex_string: String = bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<String>>()
        .join("");

    Ok(hex_string)
}

fn calculate_hash(data: &str) -> Result<Vec<u8>, ErrorKind> {
    let lower_case_data = data.to_lowercase();
    let utf8_bytes = lower_case_data.as_bytes();

    if utf8_bytes.len() > 1024 || utf8_bytes.len() == 0 {
        return Err(ErrorKind::InvalidData);
    }

    safe_hash(utf8_bytes).map_err(|_| ErrorKind::InvalidData)
}

fn safe_hash(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut cursor = Cursor::new(vec![0; 1024]);

    cursor.write(&input)?;

    let mut expr_ldata_i: u32;
    let mut expr_ldata_i_2: u32;
    let mut expr_ldata_i_8: u32;
    let mut expr_ldata_i_13: u32;
    for i in 0..64 {
        cursor.seek(SeekFrom::Start(i * 4))?;
        expr_ldata_i = cursor.read_u32::<LittleEndian>()?;
        cursor.seek(SeekFrom::Current(1 * 4))?;
        expr_ldata_i_2 = cursor.read_u32::<LittleEndian>()?;
        cursor.seek(SeekFrom::Current(5 * 4))?;
        expr_ldata_i_8 = cursor.read_u32::<LittleEndian>()?;
        cursor.seek(SeekFrom::Current(4 * 4))?;
        expr_ldata_i_13 = cursor.read_u32::<LittleEndian>()?;
        let shift_val = (expr_ldata_i ^ expr_ldata_i_8 ^ expr_ldata_i_2 ^ expr_ldata_i_13) & 0x1f;
        cursor.seek(SeekFrom::Current(2 * 4))?;
        cursor.write_u32::<LittleEndian>(rol(1, shift_val))?;
    }

    let mut a: u32 = 0x67452301;
    let mut b: u32 = 0xefcdab89;
    let mut c: u32 = 0x98badcfe;
    let mut d: u32 = 0x10325476;
    let mut e: u32 = 0xc3d2e1f0;
    let mut g: u32 = 0;

    cursor.seek(SeekFrom::Start(0))?;

    for _ in 0..20 {
        let temp = cursor.read_u32::<LittleEndian>()?;

        g = temp
            .wrapping_add(rol(a, 5))
            .wrapping_add(e)
            .wrapping_add((b & c) | (!b & d))
            .wrapping_add(0x5A82_7999);

        e = d;
        d = c;
        c = rol(b, 30);
        b = a;
        a = g;
    }

    for _ in 0..20 {
        let temp = cursor.read_u32::<LittleEndian>()?;
        g = (d ^ c ^ b)
            .wrapping_add(e)
            .wrapping_add(rol(g, 5))
            .wrapping_add(temp)
            .wrapping_add(0x6ed9eba1);

        e = d;
        d = c;
        c = rol(b, 30);
        b = a;
        a = g;
    }

    for _ in 0..20 {
        let temp = cursor.read_u32::<LittleEndian>()?;
        g = temp
            .wrapping_add(rol(g, 5))
            .wrapping_add(e)
            .wrapping_add((c & b) | (d & c) | (d & b))
            .wrapping_sub(0x70E44324);

        e = d;
        d = c;
        c = rol(b, 30);
        b = a;
        a = g;
    }

    for _ in 0..20 {
        let temp = cursor.read_u32::<LittleEndian>()?;
        g = (d ^ c ^ b)
            .wrapping_add(e)
            .wrapping_add(rol(g, 5))
            .wrapping_add(temp)
            .wrapping_sub(0x359d3e2a);

        e = d;
        d = c;
        c = rol(b, 30);
        b = a;
        a = g;
    }

    let mut result = Cursor::new(vec![0; 20]);
    a = a.wrapping_add(0x67452301);
    b = b.wrapping_add(0xefcdab89);
    c = c.wrapping_add(0x98badcfe);
    d = d.wrapping_add(0x10325476);
    e = e.wrapping_add(0xc3d2e1f0);
    result.write_u32::<BigEndian>(a)?;
    result.write_u32::<BigEndian>(b)?;
    result.write_u32::<BigEndian>(c)?;
    result.write_u32::<BigEndian>(d)?;
    result.write_u32::<BigEndian>(e)?;

    Ok(result.into_inner())
}

fn rol(val: u32, shift: u32) -> u32 {
    let shift = shift & 0x1f;
    (val.wrapping_shr(0x20 - shift)) | (val.wrapping_shl(shift))
}

#[cfg(test)]
mod tests {
    use crate::{get_hash_bytes, get_hash_string};
    use std::io::ErrorKind;

    #[test]
    fn test_empty_password_with_bytes() {
        let result = get_hash_bytes(vec![]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), ErrorKind::InvalidData);
    }

    #[test]
    fn test_valid_password_with_bytes() {
        let password = "12345";
        let lower_case_data = password.to_lowercase();
        let utf8_bytes = lower_case_data.as_bytes();

        let result = get_hash_bytes(utf8_bytes.to_vec());
        assert!(result.is_ok());

        let hex_string: String = result
            .unwrap()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<String>>()
            .join("");

        assert_eq!(hex_string, "460e0af6c1828a93fe887cbe103d6ca6ab97a0e4");
    }

    #[test]
    fn test_valid_password_with_string() {
        let password = "12345";
        let result = get_hash_string(&password);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "460e0af6c1828a93fe887cbe103d6ca6ab97a0e4");
    }
}
