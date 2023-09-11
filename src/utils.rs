use std::io::Cursor;

use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};

#[cfg(test)]
pub(crate) fn make_u32(value: u32) -> Vec<u8> {
    let out = vec![0; 4];
    let mut cursor = Cursor::new(out);
    cursor.write_u32::<LittleEndian>(value).unwrap();
    cursor.into_inner()
}

pub(crate) fn make_u64(value: u64) -> Vec<u8> {
    let out = vec![0; 8];
    let mut cursor = Cursor::new(out);
    cursor.write_u64::<LittleEndian>(value).unwrap();
    cursor.into_inner()
}

pub(crate) fn unmake_u32(value: &[u8]) -> Option<u32> {
    if value.len() != 4 {
        return None;
    }
    let mut cursor = Cursor::new(value);
    Some(cursor.read_u32::<LittleEndian>().unwrap())
}

pub(crate) fn unmake_u64(value: &[u8]) -> Option<u64> {
    if value.len() != 8 {
        return None;
    }
    let mut cursor = Cursor::new(value);
    Some(cursor.read_u64::<LittleEndian>().unwrap())
}

pub(crate) fn unmake_u64_be(value: &[u8]) -> Option<u64> {
    if value.len() != 8 {
        return None;
    }
    let mut cursor = Cursor::new(value);
    Some(cursor.read_u64::<BigEndian>().unwrap())
}
