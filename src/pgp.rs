// TODOs:
// 1. Create a `Writer` struct that would take care of keeping track of the current
// writes. This should wrap a vector with some given capacity

use hex;
use sha1::{Digest, Sha1};
use std::ops::Index;
use std::time::{Duration, SystemTime};

const BIN_TO_ASCII: [u8; 64] = [
    65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88,
    89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114,
    115, 116, 117, 118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 43, 47,
];

pub fn binary_to_radix64(buffer: &[u8]) -> Vec<u8> {
    let mut encoded: Vec<u8> = Vec::with_capacity((buffer.len() + 2) / 3 * 4 + 1);
    let rem = buffer.len() % 3;
    let len = buffer.len() - rem;

    for i in (0..len).step_by(3) {
        encoded.push(BIN_TO_ASCII[((buffer[i] >> 2) & 0o77) as usize]);
        encoded.push(
            BIN_TO_ASCII
                [((((buffer[i] << 4) & 0o60) | ((buffer[i + 1] >> 4) & 0o17)) & 0o77) as usize],
        );
        encoded.push(
            BIN_TO_ASCII
                [((((buffer[i + 1] << 2) & 0o74) | ((buffer[i + 2] >> 6) & 0o3)) & 0o77) as usize],
        );
        encoded.push(BIN_TO_ASCII[(buffer[i + 2] & 0o77) as usize]);
    }

    if rem == 2 {
        encoded.push(BIN_TO_ASCII[((buffer[len] >> 2) & 0o77) as usize]);
        encoded.push(
            BIN_TO_ASCII
                [((((buffer[len] << 4) & 0o60) | ((buffer[len + 1] >> 4) & 0o17)) & 0o77) as usize],
        );
        encoded.push(BIN_TO_ASCII[((buffer[len + 1] << 2) & 0o74) as usize]);
        encoded.push(b'=');
    }

    if rem == 1 {
        encoded.push(BIN_TO_ASCII[((buffer[len] >> 2) & 0o77) as usize]);
        encoded.push(BIN_TO_ASCII[((buffer[len] << 4) & 0o60) as usize]);
        encoded.push(b'=');
        encoded.push(b'=');
    }

    encoded
}

/// Format an OpenPGP message into an ASCII-armored format.
///
/// Armor header line, with a string surrounded by five dashes on either size of
/// the text line (Section 6.2)
/// The newline has to be part of the signature
/// We add another newline to leave a blank space between the armor header
/// and the armored PGP, as that line is used for additional properties
fn armor_binary_output(buffer: &[u8]) -> Vec<u8> {
    let mut armor = Vec::new();

    armor.extend(String::from("-----BEGIN PGP SIGNATURE-----\n\n").as_bytes());

    armor.extend(binary_to_radix64(&buffer));
    armor.extend(String::from("\n----END PGP SIGNATURE-----\n").as_bytes());

    armor
}

#[repr(u8)]
enum PacketHeader {
    Signature = 0x02,
    PublicKey = 0x06,
    UserID = 0x0D,
}

const PACKET_TAG_OFFSET: u8 = 2;

/// Calculate the old style header for a packet.
///
/// The old-style header for a packet is a single "control" byte followed by
/// 1-4 (?) bytes denoting the size of the following packet. The control byte
/// always has the MSB set to 1. Bit 6 denotes the version of the header (
/// we will be ignoring this to avoid additional complexity). Bits 5-2 contain
/// the packet type, and the lower two bits contain the number of subsequent
/// bytes holding the size of the packet.
fn calculate_packet_header(buffer: &[u8], packet_type: PacketHeader) -> Vec<u8> {
    let mut hdr = Vec::new();

    let mut header: u8 = 0b1000_0000;
    header |= (packet_type as u8) << PACKET_TAG_OFFSET;

    // TODO Move this to a separate function
    let leading_zeroes = buffer.len().to_be_bytes().partition_point(|&x| x == 0);
    let size_bytes = &buffer.len().to_be_bytes()[leading_zeroes..];

    header |= match size_bytes.len() as u8 {
        1 => 0,
        2 => 1,
        4 => 2,
        _ => unreachable!(),
    };
    hdr.push(header);
    hdr.extend_from_slice(size_bytes);

    hdr
}

#[repr(u8)]
enum ECPointCompression {
    Uncompressed = 0x04,
    NativePointFormat = 0x40,
    OnlyXCoord = 0x41,
    OnlyYCoord = 0x42,
}

/// Get the number of bits contained in a multi-precision integer (MPIs) contained in
/// a slice.
///
/// OpenPGP represents MPIs as [size MPI], where the size consists of two bytes,
/// and holds the count of _bits_ of the MPI (as opposed to the standard byte count).
fn get_mpi_bits(mpi: &[u8]) -> u16 {
    let mut count: u16 = 8u16 - mpi[0].leading_zeros() as u16;
    count += (mpi[1..].len() as u16) * 8;
    count
}

fn format_subpacket_length(buffer: &mut [u8]) -> &[u8] {
    let fst_ind = buffer.partition_point(|&x| x == 0);
    let fst_byte = buffer[fst_ind];

    if fst_byte < 192 {
        &buffer[fst_ind..fst_ind + 1]
    } else if (192..255).contains(&fst_byte) {
        buffer[fst_ind] = fst_byte - 192;
        buffer[fst_ind + 1] += 192;
        &buffer[fst_ind..]
    } else {
        &buffer[..]
    }
}

pub enum Packet {
    PublicKey(PKPacket),
    Signature(SignaturePacket),
    UserID(UserID),
}

// TODO Remove this
pub struct PublicKeyMessage<'a> {
    public_key: PKPacket<'a>,
    user_id: UserID,
    signature: SignaturePacket<'a>,
}

impl<'a> PublicKeyMessage<'a> {
    pub fn new(
        public_key: PKPacket<'a>,
        user_id: UserID,
        signature: SignaturePacket<'a>,
    ) -> PublicKeyMessage<'a> {
        PublicKeyMessage {
            public_key,
            user_id,
            signature,
        }
    }

    pub fn get_signing_portion(&mut self) -> Vec<u8> {
        // TODO What does 'once the data body is hashed, then a trailer is hashed' mean in the
        // standard? Does it mean that the two are concatenated and then hashed, or do

        let mut buffer = vec![0x99];
        let pk = self.public_key.as_bytes();
        // TODO Strip header

        let len = self.user_id.user.len() + self.user_id.email.len() + 2;
        buffer.extend(&len.to_be_bytes()[4..]);
        buffer.extend(self.signature.get_trailer());

        buffer.extend(self.public_key.as_bytes());
        buffer.extend(self.user_id.as_bytes());
        buffer.extend(self.signature.get_trailer());

        buffer
    }

    fn finalize_signature(&mut self, sig: PKAlgo<'a>, hash: u16) {
        self.signature.hash = hash;
        self.signature.pubkey_algo = sig;
    }
}

#[repr(u8)]
#[derive(Copy, Clone)]
enum Version {
    V4 = 4,
}

#[repr(u8)]
#[derive(Copy, Clone)]
pub enum SigType {
    Binary = 0x00,
    CanonicalText = 0x01,
    Standalone = 0x02,
    UserIDPKCert = 0x10,
}

pub enum PKAlgo<'a> {
    None,
    DSA(&'a [u8], &'a [u8]),
    ECDSA(&'a [u8], &'a [u8]),
}

impl<'a> PKAlgo<'a> {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        match self {
            PKAlgo::None => unreachable!(),
            PKAlgo::ECDSA(r, s) => {
                let r_len = get_mpi_bits(r);
                buffer.extend_from_slice(&r_len.to_be_bytes());
                buffer.extend_from_slice(r);

                let s_len = get_mpi_bits(s);
                buffer.extend(s_len.to_be_bytes());
                buffer.extend_from_slice(s);
            }
            PKAlgo::DSA(r, s) => {
                let r_len = get_mpi_bits(r);
                buffer.extend_from_slice(&r_len.to_be_bytes());
                buffer.extend_from_slice(r);

                let s_len = get_mpi_bits(s);
                buffer.extend(s_len.to_be_bytes());
                buffer.extend_from_slice(s);
            }
        }
        buffer
    }
}

/// A trait for contextualizing OpenPGP object interpretation.
///
/// OpenPGP objects are serialized differently based on where they are used. For
/// instance, a Public Key packet can be interpreted differently when being written
/// to file versus when it needs to be signed. This is not only true for packets,
/// but for some subpackets as well.
pub trait ToPGPBytes {
    /// Get OpenPGP-formatted content without packet headers
    fn to_raw_bytes(&self) -> Vec<u8>;
    /// Get OpenPGP-formatted content with fully-formed packet headers
    fn to_formatted_bytes(&self) -> Vec<u8>;

    /// Get a buffer to be used in subsequent hashing operations.
    ///
    /// The output is not equivalent to that of `to_raw_bytes()`, as OpenPGP
    /// specifies that, depending on the version number, a lot of packets
    /// need to be outputted in a special way before hashing them.
    ///
    /// # Examples
    /// When signing a public key, the message has to contain a User ID packet and
    /// a Signature linking the public key with a User ID, but rather than having the
    /// UserID header, this signing procedure expects the UserID to be preceded with a
    /// 4 byte size header and nothing else.
    fn to_hashable_bytes(&self) -> Vec<u8>;
}

#[repr(u8)]
#[derive(Copy, Clone)]
enum HashAlgo {
    MD5 = 1,
    SHA1 = 2,
    RIPEMD160 = 3,
    SHA2_256 = 8,
    SHA2_384 = 9,
    SHA2_512 = 10,
    SHA2_224 = 11,
    SHA3_256 = 12,
    Reserved = 13,
    SHA3_512 = 14,
}

#[repr(u8)]
#[derive(Copy, Clone)]
enum SymmetricAlgos {
    Plaintext = 0x00,
    IDEA = 0x01,
    TripleDES = 0x02,
    AES128 = 0x07,
    AES192 = 0x08,
    AES256 = 0x09,
}

#[repr(u8)]
#[derive(Copy, Clone)]
enum CompressionAlgos {
    Uncompressed = 0x00,
    ZIP = 0x01,
    ZLIB = 0x02,
    BZip2 = 0x03,
}

#[repr(u8)]
#[derive(Copy, Clone)]
enum KeyFlags {
    CanCertifyKeys = 0x01,
    CanSign = 0x02,
    CanEncrypt = 0x04,
}

#[derive(Copy, Clone)]
pub enum CurveOID {
    P256,
    P384,
    P521,
    BrainpoolP256r1,
    BrainpoolP512r1,
    Ed25519,
    Curve25519,
    Secp256k1,
}

struct CurveRepr([&'static [u8]; 8]);

// These technically are encoded as string values that
// then have to go through some transformations that truncates
// the beginning, but it does not feel worth it to keep them,
// as the values feel arbitrary anyways
const CURVE_REPR: CurveRepr = CurveRepr([
    &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
    &[0x2B, 0x81, 0x04, 0x00, 0x22],
    &[0x2B, 0x81, 0x04, 0x00, 0x23],
    &[0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07],
    &[0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D],
    &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01],
    &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01],
    &[0x2B, 0x81, 0x04, 0x00, 0x0A],
]);

impl Index<CurveOID> for CurveRepr {
    type Output = &'static [u8];

    fn index(&self, index: CurveOID) -> &Self::Output {
        match index {
            CurveOID::P256 => &self.0[0],
            CurveOID::P384 => &self.0[1],
            CurveOID::P521 => &self.0[2],
            CurveOID::BrainpoolP256r1 => &self.0[3],
            CurveOID::BrainpoolP512r1 => &self.0[4],
            CurveOID::Ed25519 => &self.0[5],
            CurveOID::Curve25519 => &self.0[6],
            CurveOID::Secp256k1 => &self.0[7],
        }
    }
}

pub enum PublicKey<'a> {
    ECDSA(CurveOID, &'a [u8], &'a [u8]),
    RSA(&'a [u8], &'a [u8]),
}

// Note: we can compute the issuer fingerprint by computing the hash of the
// public key as specified in RFC 4880, Section 12.2
enum SignatureSubpackets<'a> {
    CreationTime {
        id: u8,
        hashable: bool,
        time: Duration,
    },
    IssuerFingerprint {
        id: u8,
        hashable: bool,
        version: Version,
        fingerprint: &'a [u8],
    },
    IssuerKeyID {
        id: u8,
        hashable: bool,
        keyid: &'a [u8],
    },
    PreferredHashAlgos {
        id: u8,
        hashable: bool,
        algos: Vec<HashAlgo>,
    },
    PreferredSymmetricAlgos {
        id: u8,
        hashable: bool,
        algos: Vec<SymmetricAlgos>,
    },
    PreferredCompressionAlgos {
        id: u8,
        hashable: bool,
        algos: Vec<CompressionAlgos>,
    },
    KeyServerPreference {
        id: u8,
        hashable: bool,
        flags: Vec<u8>,
    },
    KeyFlags {
        id: u8,
        hashable: bool,
        flags: KeyFlags,
    },
}

impl<'a> SignatureSubpackets<'a> {
    pub fn creation_time(time: Duration) -> SignatureSubpackets<'a> {
        SignatureSubpackets::CreationTime {
            id: 0x02,
            hashable: true,
            time,
        }
    }

    /// Create a fingerprint subpacket attached to a Signature packet.
    ///
    /// The fingerprint of a signature is the SHA1 hash of its hashed section.
    pub fn fingerprint(fingerprint: &'a [u8]) -> SignatureSubpackets<'a> {
        SignatureSubpackets::IssuerFingerprint {
            id: 0x21,
            version: Version::V4,
            hashable: true,
            fingerprint,
        }
    }

    /// Create a keyid subpacket attached to a Signature packet.
    ///
    /// The key ID of a signature is the lowest 64 bits of its SHA1 hash.
    pub fn issuer_keyid(keyid: &'a [u8]) -> SignatureSubpackets<'a> {
        SignatureSubpackets::IssuerKeyID {
            id: 0x10,
            hashable: false,
            keyid,
        }
    }

    pub fn others() -> Vec<SignatureSubpackets<'a>> {
        vec![
            SignatureSubpackets::KeyFlags {
                id: 0x1b,
                hashable: true,
                flags: KeyFlags::CanSign,
            },
            SignatureSubpackets::PreferredSymmetricAlgos {
                id: 0x0b,
                hashable: true,
                algos: vec![
                    SymmetricAlgos::AES256,
                    SymmetricAlgos::AES192,
                    SymmetricAlgos::AES128,
                    SymmetricAlgos::TripleDES,
                ],
            },
            SignatureSubpackets::PreferredHashAlgos {
                id: 0x15,
                hashable: true,
                algos: vec![HashAlgo::SHA1, HashAlgo::RIPEMD160, HashAlgo::MD5],
            },
            SignatureSubpackets::PreferredCompressionAlgos {
                id: 0x16,
                hashable: true,
                algos: vec![CompressionAlgos::BZip2],
            },
            SignatureSubpackets::KeyServerPreference {
                id: 0x17,
                hashable: true,
                flags: vec![0x80],
            },
        ]
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::<u8>::new();
        match self {
            SignatureSubpackets::IssuerFingerprint {
                id,
                hashable: _,
                version,
                fingerprint,
            } => {
                let mut bytes = (fingerprint.len() + 2).to_be_bytes();
                buffer.extend(format_subpacket_length(&mut bytes));
                buffer.push(*id);
                buffer.push(*version as u8);
                buffer.extend_from_slice(fingerprint);
            }
            SignatureSubpackets::CreationTime {
                id,
                hashable: _,
                time,
            } => {
                let time = duration_to_bytes(*time);
                buffer.extend(format_subpacket_length(&mut (time.len() + 1).to_be_bytes()));
                // Creation time packet tag
                buffer.push(*id);
                // Big-endian epoch time
                buffer.extend(time);
            }
            SignatureSubpackets::IssuerKeyID {
                id,
                hashable: _,
                keyid,
            } => {
                let mut len = (keyid.len() + 1).to_be_bytes();
                buffer.extend(format_subpacket_length(&mut len));
                buffer.push(*id);
                buffer.extend_from_slice(keyid);
            }
            SignatureSubpackets::KeyFlags {
                id,
                hashable: _,
                flags,
            } => {
                let mut len = (1 as usize + 1).to_be_bytes();
                buffer.extend(format_subpacket_length(&mut len));
                buffer.push(*id);
                buffer.push(*flags as u8);
            }
            SignatureSubpackets::PreferredSymmetricAlgos {
                id,
                hashable: _,
                algos,
            } => {
                let mut len = (algos.len() + 1).to_be_bytes();
                buffer.extend(format_subpacket_length(&mut len));
                buffer.push(*id);
                buffer.extend(algos.iter().map(|item| *item as u8));
            }
            SignatureSubpackets::PreferredHashAlgos {
                id,
                hashable: _,
                algos,
            } => {
                let mut len = (algos.len() + 1).to_be_bytes();
                buffer.extend(format_subpacket_length(&mut len));
                buffer.push(*id);
                buffer.extend(algos.iter().map(|item| *item as u8));
            }
            SignatureSubpackets::PreferredCompressionAlgos {
                id,
                hashable: _,
                algos,
            } => {
                let mut len = (algos.len() + 1).to_be_bytes();
                buffer.extend(format_subpacket_length(&mut len));
                buffer.push(*id);
                buffer.extend(algos.iter().map(|item| *item as u8));
            }
            SignatureSubpackets::KeyServerPreference {
                id,
                hashable: _,
                flags,
            } => {
                let mut len = (flags.len() + 1).to_be_bytes();
                buffer.extend(format_subpacket_length(&mut len));
                buffer.push(*id);
                buffer.extend(flags.iter().map(|item| *item as u8));
            }
        }
        buffer
    }

    pub fn hashable(&self) -> bool {
        match self {
            SignatureSubpackets::IssuerFingerprint {
                id: _,
                hashable,
                version: _,
                fingerprint: _,
            } => *hashable,
            SignatureSubpackets::CreationTime {
                id: _,
                hashable,
                time: _,
            } => *hashable,
            SignatureSubpackets::IssuerKeyID {
                id: _,
                hashable,
                keyid: _,
            } => *hashable,
            SignatureSubpackets::PreferredHashAlgos {
                id: _,
                hashable,
                algos: _,
            } => *hashable,
            SignatureSubpackets::PreferredSymmetricAlgos {
                id: _,
                hashable,
                algos: _,
            } => *hashable,
            SignatureSubpackets::PreferredCompressionAlgos {
                id: _,
                hashable,
                algos: _,
            } => *hashable,
            SignatureSubpackets::KeyServerPreference {
                id: _,
                hashable,
                flags: _,
            } => *hashable,
            SignatureSubpackets::KeyFlags {
                id: _,
                hashable,
                flags: _,
            } => *hashable,
        }
    }
}

impl<'a> PublicKey<'a> {
    fn as_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        match self {
            PublicKey::ECDSA(oid, key_x, key_y) => {
                buffer.push(CURVE_REPR[*oid].len() as u8);
                buffer.extend(CURVE_REPR[*oid]);

                // The MPI encoding of EC points is a little different. The point
                // contains metadata on its own compression level by way of its
                // first byte. This byte is concatenated with the x and y values
                // of the EC point. This whole bitstring is then treated as the
                // MPI and serialized into the key
                let mut mpi = Vec::new();
                mpi.push(0x04);
                mpi.extend_from_slice(key_x);
                mpi.extend_from_slice(key_y);

                let bit_count = get_mpi_bits(&mpi);
                buffer.extend(bit_count.to_be_bytes());
                buffer.extend(mpi);
            }
            PublicKey::RSA(n, e) => {
                let n_bits = get_mpi_bits(n);
                buffer.extend(n_bits.to_be_bytes());
                buffer.extend(*n);

                let e_bits = get_mpi_bits(e);
                buffer.extend(e_bits.to_be_bytes());
                buffer.extend(*e);
            }
        }
        buffer
    }
}

pub struct SignaturePacket<'a> {
    version: Version,
    sigtype: SigType,
    pubkey_algo: PKAlgo<'a>,
    hash_algo: HashAlgo,
    subpackets: Vec<SignatureSubpackets<'a>>,
    hash: u16,
}

impl<'a> SignaturePacket<'a> {
    pub fn new(sigtype: SigType, keyid: &'a str, time: Option<Duration>) -> SignaturePacket<'a> {
        // TODO Under what conditions does this fail
        let epoch = match time {
            Some(n) => n,
            None => match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                Ok(n) => n,
                Err(e) => panic!("Error: {}", e),
            },
        };

        let mut signature = SignaturePacket {
            version: Version::V4,
            sigtype,
            pubkey_algo: PKAlgo::None,
            hash_algo: HashAlgo::SHA2_256,
            subpackets: Vec::new(),
            hash: 0,
        };
        signature
            .subpackets
            .push(SignatureSubpackets::creation_time(epoch));
        signature
            .subpackets
            .push(SignatureSubpackets::issuer_keyid(keyid.as_bytes()));

        signature
    }

    ///  
    /// A V4 signature hashes the packet body starting from its first field, the
    /// version number, through the end of the hashed subpacket data and a final
    /// extra trailer. Thus, the hashed fields are:
    ///  - the signature version (0x04),
    ///  - the signature type,
    ///  - the public-key algorithm,
    ///  - the hash algorithm,
    ///  - the hashed subpacket length,
    ///  - the hashed subpacket body,
    ///  - the two octets 0x04 and 0xFF,
    ///  - a four-octet big-endian number that is the length of the hashed data from the
    /// Signature packet stopping right before the 0x04, 0xff octets. */
    fn get_trailer(&self) -> Vec<u8> {
        let mut hashable = self.get_hashable();
        let len = hashable.len() as u64;

        hashable.extend(&[0x04, 0xFF]);
        hashable.extend(&len.to_be_bytes());
        hashable
    }

    fn get_hashable(&self) -> Vec<u8> {
        let mut contents = vec![
            self.version as u8,
            self.sigtype as u8,
            match self.pubkey_algo {
                PKAlgo::None => unreachable!(),
                PKAlgo::DSA(_, _) => 0x11,
                PKAlgo::ECDSA(_, _) => 0x13,
            },
            self.hash_algo as u8,
        ];

        let mut subpacket_count: u16 = 0;
        let mut temp: Vec<u8> = Vec::new();
        for subpacket in self.subpackets.iter() {
            if subpacket.hashable() {
                let subpacket_bytes = subpacket.as_bytes();
                subpacket_count += subpacket_bytes.len() as u16;
                temp.extend(subpacket.as_bytes());
            }
        }

        contents.extend(subpacket_count.to_be_bytes());
        contents.extend(&temp);
        contents
    }
}

// TODO Add context
impl<'a> ToPGPBytes for SignaturePacket<'a> {
    fn to_hashable_bytes(&self) {
        let mut hashable = self.get_hashable();
        let len = hashable.len() as u64;

        hashable.extend(&[0x04, 0xFF]);
        hashable.extend(&len.to_be_bytes());
        hashable
    }

    fn to_formatted_bytes(&self) -> Vec<u8> {
        let mut contents = self.get_hashable();
        let mut unhashed: Vec<u8> = Vec::new();
        for subpacket in self.subpackets.iter() {
            if !subpacket.hashable() {
                unhashed.extend(subpacket.as_bytes());
            }
        }
        contents.extend((unhashed.len() as u16).to_be_bytes());
        contents.extend(&unhashed);
        contents.extend(self.hash.to_be_bytes());

        // Figuring out the proper MPI sizes to end off the signature packet
        let mpis = self.pubkey_algo.as_bytes();
        contents.extend(mpis);
        // TODO Figure out a nicer way of writing this
        let mut header = calculate_packet_header(&contents, PacketHeader::Signature);
        header.extend(contents);

        header
    }
}

fn duration_to_bytes<'a>(duration: Duration) -> Vec<u8> {
    duration.as_secs().to_be_bytes()[4..].to_vec()
}

// TODO Remove the pub!
pub struct UserID {
    pub user: String,
    pub email: String,
}

impl ToPGPBytes for UserID {
    fn to_formatted_bytes(&self) -> Vec<u8> {
        let body = format!("{} <{}>", self.user, self.email);
        let body_bytes = body.as_bytes();
        let mut header = calculate_packet_header(body_bytes, PacketHeader::UserID);
        header.extend(body_bytes);
        header
    }
}

pub struct PKPacket<'a> {
    version: Version,
    pub creation_time: Duration,
    days_until_expiration: u16,
    public_key: PublicKey<'a>,
}

// TODO RFC 4880 mentions that "A primary key capable of making signatures SHOULD be
// accompanied by either a certification signature (on a User ID or User Attribute) or
// a signature directly on the key.", which we are not doing for the sake of brevity
impl<'a> PKPacket<'a> {
    pub fn new(public_key: PublicKey<'a>, time: Option<Duration>) -> PKPacket<'a> {
        let epoch = match time {
            Some(n) => n,
            None => match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
                Ok(n) => n,
                Err(e) => panic!("Error: {}", e),
            },
        };

        PKPacket {
            version: Version::V4,
            creation_time: epoch,
            days_until_expiration: 0,
            public_key,
        }
    }

    fn get_hashed_subsection(&self) -> Vec<u8> {
        let mut buffer = vec![
            match self.version {
                Version::V4 => 0x99,
            },
            0x00,
            0x00,
            self.version as u8,
        ];
        buffer.extend(duration_to_bytes(self.creation_time));
        buffer.push(match self.public_key {
            PublicKey::ECDSA(_, _, _) => 0x13,
            PublicKey::RSA(_, _) => 0x01,
        });
        buffer.extend(self.public_key.as_bytes());
        // TODO Is there any better way of doing this?
        let total_len = ((buffer.len() - 3) as u16).to_be_bytes();
        buffer[1] = total_len[0];
        buffer[2] = total_len[1];

        let mut hasher = Sha1::new();
        hasher.update(buffer);
        let result = hasher.finalize();

        result.to_vec()
    }

    // The Key ID is unambiguously the lowest 64 bits of the key hash
    pub fn keyid(&self) -> String {
        let hash = self.get_hashed_subsection();
        let len = hash.len();
        hex::encode_upper(&hash[len - 8..])
    }

    pub fn fingerprint(&self) -> Vec<u8> {
        self.get_hashed_subsection()
    }
}

impl ToPGPBytes for PKPacket<'_> {
    fn to_formatted_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        match self.version {
            Version::V4 => {
                buffer.push(self.version as u8);
                buffer.extend(duration_to_bytes(self.creation_time));

                buffer.push(match self.public_key {
                    PublicKey::ECDSA(_, _, _) => 0x13,
                    PublicKey::RSA(_, _) => 0x01,
                });
                assert_eq!(buffer.len(), 6);

                buffer.extend(self.public_key.as_bytes());
            }
        }

        let mut header = calculate_packet_header(&buffer, PacketHeader::PublicKey);
        header.extend(buffer);

        header
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const RSA_PUBLIC_KEY: PublicKey = PublicKey::RSA(
        &[
            0xd9, 0x02, 0x41, 0x2a, 0xbf, 0xd6, 0x13, 0xf9, 0xed, 0x8a, 0xf0, 0xe1, 0x9e, 0x02,
            0x91, 0xd6, 0xee, 0x31, 0x7d, 0x82, 0xd3, 0x4f, 0x2e, 0xcd, 0x63, 0xa6, 0x5f, 0xeb,
            0xb3, 0x96, 0xb9, 0x45, 0x7b, 0x17, 0x01, 0x1c, 0x02, 0x8a, 0x55, 0xb6, 0x6e, 0xc4,
            0xac, 0x95, 0x23, 0xbe, 0xea, 0x48, 0xba, 0x09, 0xb8, 0x2e, 0xcd, 0xa0, 0x79, 0x86,
            0x23, 0x53, 0x63, 0x80, 0xc9, 0x8c, 0x8b, 0x38, 0x4c, 0xfd, 0xef, 0x4b, 0xd9, 0x57,
            0x81, 0x24, 0xfb, 0x21, 0xbf, 0x97, 0xa7, 0x9c, 0x5a, 0x84, 0x85, 0x2b, 0xc5, 0x57,
            0x40, 0x9e, 0x24, 0x57, 0x88, 0x77, 0xc6, 0xe3, 0xf9, 0xbc, 0x45, 0x6b, 0x49, 0x7e,
            0xa4, 0x5f, 0xa6, 0xc9, 0x9a, 0x59, 0xcb, 0xd5, 0x4f, 0x9c, 0xca, 0x62, 0xe0, 0x01,
            0x65, 0x77, 0x97, 0xd2, 0x74, 0x34, 0x8f, 0xb3, 0x8e, 0xdb, 0x2a, 0x22, 0x9c, 0xc7,
            0x4d, 0x52, 0x38, 0xb3, 0xc6, 0xb0, 0x45, 0xf2, 0x9e, 0x0e, 0xa7, 0xd0, 0x9b, 0x85,
            0x02, 0x74, 0x49, 0x52, 0x61, 0xfa, 0x33, 0x13, 0xd9, 0xb8, 0x95, 0x9c, 0x69, 0xfc,
            0x82, 0x12, 0x11, 0xeb, 0x93, 0x23, 0x79, 0x6d, 0x15, 0x7a, 0x99, 0x33, 0x51, 0x7d,
            0x0a, 0x51, 0x76, 0x76, 0x5f, 0x7f, 0xd6, 0x57, 0xf1, 0xfc, 0xc9, 0x75, 0x7c, 0x62,
            0xa1, 0x14, 0xef, 0x46, 0x6f, 0x13, 0xf3, 0x78, 0x3c, 0x36, 0x69, 0x69, 0x23, 0x75,
            0xd0, 0x10, 0xb4, 0x89, 0x4f, 0xeb, 0xbb, 0x20, 0x93, 0xf5, 0x0f, 0x3f, 0x13, 0x93,
            0x8b, 0x20, 0x10, 0x8c, 0xd4, 0x96, 0xe2, 0xa1, 0x9f, 0xc2, 0x8e, 0x88, 0x83, 0x18,
            0x16, 0x28, 0xb5, 0x55, 0x5d, 0x05, 0x99, 0x57, 0xd4, 0x55, 0x0b, 0x99, 0xf5, 0x73,
            0x94, 0xe4, 0xee, 0xf9, 0x12, 0x14, 0xac, 0xd3, 0xb0, 0x2b, 0x81, 0xb4, 0x3a, 0x3f,
            0x43, 0xb3, 0x43, 0xe8, 0x85, 0x04, 0x7e, 0x41, 0xd5, 0xc9, 0xd5, 0x83, 0xe5, 0x74,
            0x3d, 0x20, 0x24, 0x73, 0x5b, 0xee, 0x5e, 0xb4, 0xda, 0x0d, 0xad, 0xd6, 0x33, 0x7b,
            0x8f, 0x6b, 0x0d, 0xb2, 0x7d, 0x36, 0x32, 0x13, 0x94, 0xda, 0x5a, 0x84, 0x8c, 0xef,
            0xd8, 0x3c, 0x32, 0xa2, 0x93, 0x6c, 0x56, 0x3b, 0x58, 0xc9, 0x20, 0x85, 0x25, 0xf0,
            0xc5, 0x7a, 0xbe, 0xd9, 0xd9, 0x0e, 0x42, 0xf2, 0xb3, 0x4c, 0xaf, 0x76, 0x70, 0x4b,
            0x98, 0xb5, 0xd8, 0x47, 0xdf, 0x8f, 0x5b, 0xe2, 0x1f, 0xcb, 0x3f, 0x05, 0x1e, 0x2b,
            0xfe, 0xd2, 0x18, 0x12, 0x71, 0x3f, 0x94, 0xef, 0x4f, 0x03, 0x3e, 0xb4, 0x80, 0xb5,
            0x51, 0x50, 0x74, 0xad, 0xbc, 0x4b, 0xc0, 0xa2, 0x63, 0x54, 0xc3, 0x43, 0x8e, 0x76,
            0x26, 0x54, 0x86, 0x7a, 0x96, 0x7b, 0x58, 0x1c, 0x54, 0x12, 0xd7, 0x65, 0x95, 0x0a,
            0x4a, 0xe3, 0xa3, 0xd4, 0xcc, 0x97,
        ],
        &[0x01, 0x00, 0x01],
    );

    #[test]
    fn mpi_standard_bitlength() {
        // From the standard, multiprecision integers (MPIs) should be encoded with a two byte
        // header indicating its length in bits, followed by the big endian representation of the
        // integer.
        // Example from Section 3.2 of RFC 4480
        assert_eq!(1, get_mpi_bits(&[0x01]));
    }

    #[test]
    fn mpi_complex_bitlength() {
        // Taken from a correctly formed OpenPGP packet used for testing RFC compliance
        assert_eq!(
            255,
            get_mpi_bits(&[
                0x6b, 0xee, 0x77, 0xd9, 0x82, 0xf2, 0x12, 0x82, 0xcb, 0x2e, 0x68, 0x9a, 0x23, 0xf9,
                0xff, 0xc8, 0x1d, 0xa2, 0x95, 0xae, 0x2f, 0x6d, 0x9a, 0x6b, 0xd2, 0xa5, 0x3f, 0x96,
                0x56, 0xea, 0x10, 0xae
            ])
        );
    }

    #[test]
    fn public_key_serialization() {
        let public_key = PKPacket::new(RSA_PUBLIC_KEY, Some(Duration::from_secs(0x60fc16a7)));

        println!("{:X?}", public_key.to_formatted_bytes());
    }

    #[test]
    fn public_key_keyid() {
        let public_key = PKPacket::new(RSA_PUBLIC_KEY, Some(Duration::from_secs(0x60fc16a7)));

        assert_eq!(
            public_key.keyid(),
            String::from("D38B2AC81BA36FA3") // &[0xD3, 0x8B, 0x2A, 0xC8, 0x1B, 0xA3, 0x6F, 0xA3]
        );
    }

    #[test]
    fn public_key_fingerprint() {
        let public_key = PKPacket::new(RSA_PUBLIC_KEY, Some(Duration::from_secs(0x60fc16a7)));

        assert_eq!(
            public_key.fingerprint(),
            &[
                0xb6, 0x57, 0x58, 0x37, 0x9a, 0x42, 0x62, 0x5f, 0xc8, 0x44, 0xc4, 0x1a, 0xd3, 0x8b,
                0x2a, 0xc8, 0x1b, 0xa3, 0x6f, 0xa3
            ]
        );
    }

    #[test]
    fn signature_serialization() {
        let signature = SignaturePacket {
            version: Version::V4,
            sigtype: SigType::Binary,
            pubkey_algo: PKAlgo::DSA(
                &[
                    0x6a, 0x39, 0xfd, 0x93, 0x6c, 0xcb, 0xb6, 0x56, 0xd3, 0x2c, 0x39, 0x1a, 0xd8,
                    0xb0, 0xa1, 0x78, 0x7d, 0x89, 0x87, 0x19, 0xd7, 0x7f, 0x50, 0x54, 0xb2, 0xcf,
                    0x87, 0x6c, 0x00, 0x38, 0x72, 0x94,
                ],
                &[
                    0x6b, 0xee, 0x77, 0xd9, 0x82, 0xf2, 0x12, 0x82, 0xcb, 0x2e, 0x68, 0x9a, 0x23,
                    0xf9, 0xff, 0xc8, 0x1d, 0xa2, 0x95, 0xae, 0x2f, 0x6d, 0x9a, 0x6b, 0xd2, 0xa5,
                    0x3f, 0x96, 0x56, 0xea, 0x10, 0xae,
                ],
            ),
            hash_algo: HashAlgo::SHA2_256,
            subpackets: vec![
                SignatureSubpackets::fingerprint(&[
                    0x7d, 0x06, 0x3e, 0x54, 0xf2, 0xe9, 0xa3, 0x9e, 0x8f, 0x69, 0x7e, 0xcf, 0xe3,
                    0x54, 0x2a, 0xe0, 0x84, 0xdb, 0x79, 0x6c,
                ]),
                SignatureSubpackets::creation_time(Duration::from_secs(0x60d985ae)),
                SignatureSubpackets::issuer_keyid(&[
                    0xE3, 0x54, 0x2A, 0xE0, 0x84, 0xDB, 0x79, 0x6C,
                ]),
            ],
            hash: 0xfdcb,
        };

        let binary_signature = signature.to_formatted_bytes();
        let sample_signature = &[
            0x88, 0x75, 0x04, 0x00, 0x11, 0x08, 0x00, 0x1d, 0x16, 0x21, 0x04, 0x7d, 0x06, 0x3e,
            0x54, 0xf2, 0xe9, 0xa3, 0x9e, 0x8f, 0x69, 0x7e, 0xcf, 0xe3, 0x54, 0x2a, 0xe0, 0x84,
            0xdb, 0x79, 0x6c, 0x05, 0x02, 0x60, 0xd9, 0x85, 0xae, 0x00, 0x0a, 0x09, 0x10, 0xe3,
            0x54, 0x2a, 0xe0, 0x84, 0xdb, 0x79, 0x6c, 0xfd, 0xcb, 0x00, 0xff, 0x6a, 0x39, 0xfd,
            0x93, 0x6c, 0xcb, 0xb6, 0x56, 0xd3, 0x2c, 0x39, 0x1a, 0xd8, 0xb0, 0xa1, 0x78, 0x7d,
            0x89, 0x87, 0x19, 0xd7, 0x7f, 0x50, 0x54, 0xb2, 0xcf, 0x87, 0x6c, 0x00, 0x38, 0x72,
            0x94, 0x00, 0xff, 0x6b, 0xee, 0x77, 0xd9, 0x82, 0xf2, 0x12, 0x82, 0xcb, 0x2e, 0x68,
            0x9a, 0x23, 0xf9, 0xff, 0xc8, 0x1d, 0xa2, 0x95, 0xae, 0x2f, 0x6d, 0x9a, 0x6b, 0xd2,
            0xa5, 0x3f, 0x96, 0x56, 0xea, 0x10, 0xae,
        ];

        assert_eq!(binary_signature, sample_signature);
    }

    #[test]
    fn radix64_basic_conversion() {
        // Test basic conversion
        assert_eq!(
            vec![70, 80, 117, 99, 65, 57, 108, 43],
            binary_to_radix64(&[0x14, 0xFB, 0x9C, 0x03, 0xD9, 0x7E])
        );
    }

    #[test]
    fn radix64_padded_conversion() {
        assert_eq!(
            vec![70, 80, 117, 99, 65, 57, 107, 61],
            binary_to_radix64(&[0x14, 0xFB, 0x9C, 0x03, 0xD9])
        );
    }
}
