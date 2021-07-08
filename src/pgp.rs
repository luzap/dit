use std::time::{Duration, SystemTime};
use std::ops::Index;

const BIN_TO_ASCII: [u8; 64] = [
    65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 
    85, 86, 87, 88, 89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 
    109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 48, 49, 50,
    51, 52, 53, 54, 55, 56, 57, 43, 47
];

pub fn data_to_radix64(buffer: &[u8]) -> Vec<u8> {
    let mut encoded: Vec<u8> = Vec::with_capacity((buffer.len()+2)/3 * 4 + 1);
    
    let rem = buffer.len() % 3;
    let len = buffer.len() - rem;

    for i in (0..len).step_by(3) {
        encoded.push(BIN_TO_ASCII[((buffer[i] >> 2) & 0o77) as usize]);
        encoded.push(BIN_TO_ASCII[((((buffer[i] << 4) & 0o60) |
                     ((buffer[i+1] >> 4) & 0o17)) & 0o77) as usize]);
        encoded.push(BIN_TO_ASCII[((((buffer[i+1] << 2) & 0o74) |
                    ((buffer[i+2] >> 6) & 0o3)) & 0o77) as usize]);
        encoded.push(BIN_TO_ASCII[(buffer[i+2] & 0o77) as usize]);
    }

    if rem == 2 {
        encoded.push(BIN_TO_ASCII[((buffer[len] >> 2) & 0o77) as usize]);
        encoded.push(BIN_TO_ASCII[((((buffer[len] << 4) & 0o60)|
                     ((buffer[len+1] >> 4) & 0o17)) & 0o77) as usize]);
        encoded.push(BIN_TO_ASCII[(((buffer[len+1] << 2) & 0o74)) as usize]);
        encoded.push('=' as u8);
    }

    if rem == 1 {
        encoded.push(BIN_TO_ASCII[((buffer[len] >> 2) & 0o77) as usize]);
        encoded.push(BIN_TO_ASCII[((buffer[len] << 4) & 0o60) as usize]);
        encoded.push('=' as u8);
        encoded.push('=' as u8);

    }

    encoded
}

fn get_mpi_bits(mpi: &[u8]) -> u16 {
    let mut count: u16 = 8u16 - mpi[0].leading_zeros() as u16;
    count += (mpi[1..].len() as u16) * 8;
    count
}


fn format_mpi(mpi: &[u8]) -> Vec<u8> { 
    let mut output: Vec<u8> = Vec::new();
    let bits = get_mpi_bits(mpi).to_be_bytes();
    output.extend(bits);
    output.extend(mpi);

    output
}


#[repr(u8)]
#[derive(Copy, Clone)]
enum Version {
    V3 = 3,
    V4 = 4,
    V5 = 5
}

#[repr(u8)]
#[derive(Copy, Clone)]
enum SigType {
    Binary = 0x00,
    CanonicalText = 0x01,
    Standalone = 0x02,
}


enum PKAlgo<'a> {
    DSA(&'a [u8], &'a [u8]),
    ECDSA(&'a [u8], &'a [u8]),
}


#[repr(u8)]
#[derive(Copy, Clone)]
enum HashAlgo {
    MD5= 1,
    SHA1 = 2, 
    RIPEMD160 = 3, 
    SHA2_256 = 8,
    SHA2_384 = 9,
    SHA2_512 = 10,
    SHA2_224 = 11,
    SHA3_256 = 12,
    Reserved = 13,
    SHA3_512 = 14
}

enum SignatureSubpackets<'a> {
    CreationTime(Duration),
    IssuerFingerprint(&'a [u8]),
    IssuerKeyID(&'a [u8])
}


pub trait Packet {
    fn serialize(&self) -> Vec<u8>;
}

struct SignaturePacket<'a> {
    version: Version, 
    sigtype: SigType,
    pubkey_algo: PKAlgo<'a>,
    hash_algo: HashAlgo,
    subpackets: Vec<SignatureSubpackets<'a>>,
    hash: u16
}

impl<'a> SignaturePacket<'a> {
    fn new(r: &'a [u8], s: &'a [u8]) -> SignaturePacket<'a> {
        // TODO Under what conditions does this fail
        let epoch = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(n) => n,
            Err(e) => panic!("Error: {}", e),
        };

        let mut signature = SignaturePacket {
            version: Version::V4,
            sigtype: SigType::Binary,
            pubkey_algo: PKAlgo::ECDSA(r, s),
            hash_algo: HashAlgo::SHA2_256,
            subpackets: Vec::new(),
            hash: 0
        };
        signature.subpackets.push(SignatureSubpackets::CreationTime(epoch));
        
        signature
    }
}

struct PKPacket<'a> { 
    version: Version,
    creation_time: Duration,
    days_until_expiration: u16,
    public_key: PublicKey<'a>       
}

#[derive(Copy, Clone)]
enum CurveOID {
    P256,
    P384,
    P521,
    BrainpoolP256r1,
    BrainpoolP512r1,
    Ed25519,
    Curve25519
}


struct CurveRepr([&'static [u8]; 7]);

const CURVE_REPR: CurveRepr = CurveRepr([
    &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
    &[0x2B, 0x81, 0x04, 0x00, 0x22],
    &[0x2B, 0x81, 0x04, 0x00, 0x23],
    &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07],
    &[0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D],
    &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01],
    &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01] 
]);

impl Index<CurveOID> for CurveRepr {
    type Output =  &'static [u8];

    fn index(&self, index: CurveOID) -> &Self::Output {
        match index {
            CurveOID::P256 => &self.0[0],
            CurveOID::P384 => &self.0[1],
            CurveOID::P521 => &self.0[2],
            CurveOID::BrainpoolP256r1 => &self.0[3],
            CurveOID::BrainpoolP512r1 => &self.0[4],
            CurveOID::Ed25519 => &self.0[5],
            CurveOID::Curve25519 => &self.0[6]
        }
    }
}


enum PublicKey<'a> {
    ECDSA(CurveOID, &'a [u8])
}


impl<'a> SignaturePacket<'a> {
    fn serialize_radix64(&self) -> Vec<u8> {
        let binary = self.serialize();
        let mut armor = Vec::new();

        // Armor header line, with a string surrounded by five dashes on either size of
        // the text line (Section 6.2)
        // The newline has to be part of the signature
        armor.extend(String::from("-----BEGIN PGP SIGNATURE-----\n").as_bytes());

        armor.extend(data_to_radix64(&binary));
        armor.extend(String::from("\n----END PGP SIGNATURE-----\n").as_bytes());

        armor
    }

/* A V4 signature hashes the packet body starting from its first field, the version number, through the end of the hashed subpacket data and a final extra trailer. Thus, the hashed fields are:

    the signature version (0x04),
    the signature type,
    the public-key algorithm,
    the hash algorithm,
    the hashed subpacket length,
    the hashed subpacket body,
    the two octets 0x04 and 0xFF,
    a four-octet big-endian number that is the length of the hashed data from the Signature packet stopping right before the 0x04, 0xff octets. */

    fn get_trailer(&self) -> Vec<u8> {
        let mut hashable = self.get_hashable();
        let len = hashable.len() as u64;

        hashable.extend(&[0x04, 0xFF]);
        hashable.extend(&len.to_be_bytes());

        hashable
    }



    fn get_hashable(&self) -> Vec<u8> {
        let mut contents: Vec<u8> = Vec::new();

        contents.push(self.version as u8);
        contents.push(self.sigtype as u8);
        
        let public_algo = match self.pubkey_algo {
            PKAlgo::DSA(_, _) => 0x11,
            PKAlgo::ECDSA(_, _) => 0x13,
        };
        contents.push(public_algo);

        contents.push(self.hash_algo as u8);
        
        let mut subpacket_count: u16 = 0;
        // TODO Need to go back and write these values if subpacket_count is greater than zero
       
        let mut temp: Vec<u8> = Vec::new();
        for subpacket in self.subpackets.iter() {
            match subpacket {
                SignatureSubpackets::CreationTime(time) => {
                    temp.push(0x05);
                    // Creation time packet tag
                    temp.push(0x02);
                    // Big-endian epoch time
                    temp.extend(time.as_secs().to_be_bytes());
                    subpacket_count += 6;
                }
                SignatureSubpackets::IssuerFingerprint(fingerprint) => {
                    temp.push(33);
                    temp.push(fingerprint.len() as u8);
                    temp.extend_from_slice(fingerprint)
                }
                _ => {}
            }
        }
        contents.extend(subpacket_count.to_be_bytes());
        contents.extend(&temp);
        contents
    }
    


}

#[allow(unused_variables)]
#[allow(unused_mut)]
impl<'a> Packet for SignaturePacket<'a> {
    fn serialize(&self) -> Vec<u8> {
        let mut contents = self.get_hashable();
        let mut size = contents.len();
        
        let mut unhashed: Vec<u8> = Vec::new();
        // TODO Match all of the hashable subpackets here
        for subpacket in self.subpackets.iter() {
            
        }

        contents.extend((unhashed.len() as u16).to_be_bytes());
        contents.extend(&unhashed);

        match self.pubkey_algo {
            PKAlgo::ECDSA(r, s) => {
                let r_len = get_mpi_bits(r);
                contents.extend_from_slice(&r_len.to_be_bytes());
                contents.extend_from_slice(r);
                size += (r_len as f32 / 8.0).ceil() as usize + 2;

                let s_len = get_mpi_bits(s);
                contents.extend(s_len.to_be_bytes());
                contents.extend(s);
                size += (s_len as f32 / 8.0).ceil() as usize + 2;
            },
            PKAlgo::DSA(r, s) => {
                let r_len = get_mpi_bits(r);
                contents.extend_from_slice(&r_len.to_be_bytes());
                contents.extend_from_slice(r);
                size += (r_len as f32 / 8.0).ceil() as usize + 2;

                let s_len = get_mpi_bits(s);
                contents.extend(s_len.to_be_bytes());
                contents.extend(s);
                size += (s_len as f32 / 8.0).ceil() as usize + 2;
            }
        }
        let mut temp = Vec::new();
        // TODO What is this value supposed to be?
        temp.push(0x80);
        contents
    }
}


impl Packet for PKPacket<'_> {
    fn serialize(&self) -> Vec<u8>{
        let mut binary = Vec::new();

        binary.push(self.version as u8);
        let creation_time = self.creation_time.as_secs().to_be_bytes();
        binary.extend(&creation_time);

        match self.public_key {
            PublicKey::ECDSA(oid, key) => {
                binary.push(CURVE_REPR[oid].len() as u8);
                binary.extend(CURVE_REPR[oid]);
                let y_len = get_mpi_bits(key);
                binary.extend(y_len.to_be_bytes());
            }
        }
        binary  
    }

}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn mpi_standard_bitlength() {
        // From the standard, multiprecision integers (MPIs) should be encoded with a two byte
        // header indicating its length in bits, followed by the big endian representation of the
        // integer.
        
        // Example from Section 3.2 of RFC 4480
        assert_eq!(1, get_mpi_bits(&[0x01]));

    }


    #[test]
    fn mpi_impl_bitlength() {
        // Taken from a correctly formed OpenPGP packet used for testing RFC compliance
        assert_eq!(255, get_mpi_bits(&[
                  0x6b, 0xee, 0x77, 0xd9, 0x82, 0xf2, 0x12, 0x82, 0xcb, 0x2e, 
                  0x68, 0x9a, 0x23, 0xf9, 0xff, 0xc8, 0x1d, 0xa2, 0x95, 0xae,
                  0x2f, 0x6d, 0x9a, 0x6b, 0xd2, 0xa5, 0x3f, 0x96, 0x56, 0xea, 
                  0x10, 0xae
        ]));
    }


    fn serialize_signature() {
        let signature = SignaturePacket {
            version: Version::V4,
            sigtype: SigType::Binary,
            pubkey_algo: PKAlgo::DSA(
                &[0x00],
                &[0x00]
            ),
            hash_algo: HashAlgo::SHA2_256,
            subpackets: vec![
                SignatureSubpackets::CreationTime(Duration::from_secs(0x60d985ae))

            ],
            hash: 0x0000,
        };
    }

    #[test]
    fn radix64_basic_conversion() {
        // Test basic conversion
        assert_eq!(vec![70, 80, 117, 99, 65, 57, 108, 43],
            data_to_radix64(&[0x14, 0xFB, 0x9C, 0x03, 0xD9, 0x7E]));
    }

    #[test]
    fn radix64_padded_conversion() {
        assert_eq!(vec![70, 80, 117, 99, 65, 57, 107, 61],
            data_to_radix64(&[0x14,0xFB,0x9C,0x03,0xD9]));
    }


}



