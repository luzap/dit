struct PGPHeader {
    header: u8,
    size: Vec<u8>,
}

struct PGPSignature {
    header: PGPHeader,
    version: u8,
    sig_type: u8,
    public_key_algo: u8,
    hash_algo: u8,
    hashed_packet_size: u16,
    hashed_subpackets: Vec<SignatureSubpacket>,
    unhashed_packet_size: u16,
    unhashed_subpackets: Vec<SignatureSubpacket>,
    msb_hash: u16,
    r: Vec<u8>,
    s: Vec<u8>
}

enum SignatureSubpacket {
    CreationTime,
    ExpirationTime,
    Issuer,
    SignerID,
    IssuerFingerprint
}



fn peek() -> u32 {
    1
}


fn get_new_len(c: u8) -> u32
{
	if c < 192 {
        c as u32
    } else if c < 224 {
        ((c as u32 - 192) << 8) + peek() + 192
    } else {
        1 << ((c as u32) & 0x1f)
    }
}


enum TypeFlags {
    BinaryTag = 0x80,
}
const NewTag: u8 = 0x40;
const BINARY_TAG: u8 = 0x80;
const TAG_MASK: u8 = 0x3f;
const PARTIAL_MASK: u8 = 0x1f;
const TAG_COMPRESSED: u8 = 8;
const CRITICAL_BIT: u8 = 0x80;
const CRITICAL_MASK: u8 = 0x7f;

const OLD_TAG_SHIFT: u8 = 2;
const OLD_LEN_MASK: u8 = 0x03;


fn read_binary() {

}

fn read_radix64() {
    // Check for armor section
    // Then going until the end
    // Decode each as a base64 character
}


enum Format {
    Binary,
    Armor
}


enum Error{
    ParseError
}

fn get_old_length(bytes: &[u8]) -> u32 {
    let mut accum = bytes[0] as u32;
    for &byte in bytes[1..].iter() {
        accum |= (byte as u32) << 8;
    }
    accum
}


fn parse_packet(file: &[u8]) -> Result<(), Error>  {

    let (format_byte, bytes) = file.split_at(1);
    // TODO This is wrong: we need to check for nonzero
    let format = match format_byte[0] & BINARY_TAG {
       1  => Format::Binary,
        _ => Format::Armor
    };

    // TODO This is still pretty horrible
    for (i, byte) in bytes.iter().enumerate() {
        let mut tag = byte & TAG_MASK;
        let len = match byte & NewTag {
            1 => bytes[i+1] as u32,
            _ => {
                match  byte & OLD_LEN_MASK {
                    0 => bytes[i+1] as u32,
                    count if count < 3 => get_old_length(&bytes[i..(2 ^ count) as usize]),
                    3 => unimplemented!(),
                    _ => unreachable!(),
                }
            }
        };
        // TODO We have the length, but we don't have the proper packet
    

    }

    Ok(())
}
