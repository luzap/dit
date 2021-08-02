use crate::utils;
use multi_party_ecdsa::protocols::multi_party_ecdsa::gg_2020::party_i::SignatureRecid;
use std::ops::Index;
use std::time::{Duration, SystemTime};

// TODO What does the Recid mean?
pub fn encode_sig_data(sig: SignatureRecid) -> SignatureData {
    use curv::arithmetic::traits::Converter;
    use curv::elliptic::curves::traits::ECScalar;
    SignatureData::ECDSA(sig.r.to_big_int().to_bytes(), sig.s.to_big_int().to_bytes())
}

fn sha160_hash(buffer: &[u8]) -> Vec<u8> {
    use sha1::{Digest, Sha1};

    let mut hasher = Sha1::new();
    hasher.update(buffer);
    hasher.finalize().to_vec()
}

pub fn sha512_hash(buffer: &[u8]) -> Vec<u8> {
    use curv::arithmetic::traits::Converter;
    use curv::cryptographic_primitives::hashing::hash_sha512::HSha512;
    use curv::cryptographic_primitives::hashing::traits::Hash;

    let mut hasher = HSha512::create_hash_from_slice(buffer);
    hasher.to_bytes()
}

const BIN_TO_ASCII: [u8; 64] = [
    65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88,
    89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114,
    115, 116, 117, 118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 43, 47,
];

/// Convert a byte buffer from a binary representation to radix64.
///
/// It should be noted that the radix64 representation mentioned in the standard
/// is equivalent to base64, but integrating yet another crate for the purpose
/// did not seem to be a great idea.
///
/// The implementation below has been ported from the [pgpdump](https://github.com/kazu-yamamoto/pgpdump)
/// project.
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

/// Return the first four bytes corresponding to a big-endian encoded time.
fn duration_to_bytes(duration: Duration) -> Vec<u8> {
    duration.as_secs().to_be_bytes()[4..].to_vec()
}

/// Format an OpenPGP message into an ASCII-armored format.
///
/// Armor header line, with a string surrounded by five dashes on either size of
/// the text line (Section 6.2)
/// The newline has to be part of the signature
/// We add another newline to leave a blank space between the armor header
/// and the armored PGP, as that line is used for additional properties
pub fn armor_binary_output(buffer: &[u8]) -> Vec<u8> {
    let mut armor = Vec::new();

    armor.extend(String::from("-----BEGIN PGP SIGNATURE-----\n\n").as_bytes());
    armor.extend(binary_to_radix64(buffer));
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

/// Format the length of a subpacket to comply with the standard specification.
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

/// Fill a buffer with an elliptic curve point formatted as an MPI.
///
/// The MPI encoding of EC points is a little different. The point
/// contains metadata on its own compression level by way of its
/// first byte. This byte is concatenated with the x and y values
/// of the EC point. This whole bitstring is then treated as the
/// MPI and serialized.
///
/// # Notes
/// Currently, we are not in full compliance with the spec. In some cases, the x
/// and y values might have to be padded to match the underlying field size
fn format_ec_point(buffer: &mut Vec<u8>, x: &[u8], y: &[u8]) {
    let length =
        get_mpi_bits(x) + get_mpi_bits(y) + get_mpi_bits(&[ECPointCompression::Uncompressed as u8]);
    buffer.extend_from_slice(&length.to_be_bytes());
    buffer.push(ECPointCompression::Uncompressed as u8);
    buffer.extend_from_slice(x);
    buffer.extend_from_slice(y);
}

/// A structure representing a fully formed OpenPGP message.
///
/// The internals of the structure will be completely opaque to the user, and the
/// corresponding messages can be constructed only with the corresponding messages.
/// This is to preserve the semantic ordering of packets.
///
/// # Supported packet combinations
/// Currently, we support only standalone `Signature` packets, and Public Key packets
/// (which have to either be followed by a `Signature` packet or a `UserID` packet
/// which is then followed by the `Signature` packet (thus attesting to either the
/// owner of the key or the key itself(?))
pub struct Message<'a> {
    packets: Vec<Packet<'a>>,
}

impl<'a> Message<'a> {
    pub fn new() -> Message<'a> {
        Message {
            packets: Vec::with_capacity(3),
        }
    }

    pub fn new_signature(&mut self, time: Duration) {
        self.packets
            .push(Packet::PartialSignature(PartialSignature::new(
                SigType::Binary,
                PublicKeyAlgorithm::ECDSA,
                Some(time),
            )));
    }
    pub fn finalize_signature(&mut self, hash: &[u8], sig: SignatureData) -> &Message {
        let hash = if hash.len() > 0 {
            let len = hash.len();
            [hash[len - 2], hash[len - 1]]
        } else {
            panic!("Something went wrong with the hash values!")
        };

        // We always have the (partial) signature as the last item, and absent
        // the GnuPG way of specifying the grammar of a message (via S-expressions),
        // this is probably a safe way of going about finalizing the signature
        if let Some(Packet::PartialSignature(partial)) = self.packets.pop() {
            // Having to use these sorts of match statements probably implies
            // that the layer of abstraction is incorrect, but I'm not sure
            // what a better way of expressing it would be (could always make separate structs for
            // them)
            let keyid = match &self.packets[0] {
                Packet::PublicKey(pubkey) => pubkey.keyid(),
                _ => unreachable!(),
            };

            let mut signature = Signature::new(partial, hash, sig);
            signature.subpackets.push(SigSubpacket::KeyID(keyid));
            self.packets.push(Packet::Signature(signature));
        } else {
            println!("The packet does not have a signature!");
        }

        self
    }

    pub fn new_public_key(
        &mut self,
        pubkey: PublicKey<'a>,
        user: String,
        email: String,
        time: Duration,
    ) -> &Message {
        let public_key_packet = PKPacket::new(pubkey, Some(time));
        let fingerprint = public_key_packet.fingerprint();

        self.packets.push(Packet::PublicKey(public_key_packet));
        self.packets.push(Packet::UserID(UserID { user, email }));
        let mut partial =
            PartialSignature::new(SigType::UserIDPKCert, PublicKeyAlgorithm::ECDSA, Some(time));
        // Both the subpackets and their order have been derived from a GnuPG created key
        // in order to conform as much as possible with any undocumented implementation
        // assumptions that we may or may not run into
        partial.subpackets.extend([
            HSigSubpacket::CreationTime(time),
            HSigSubpacket::Fingerprint(fingerprint),
            HSigSubpacket::KeyFlags(KeyFlags::CanSign),
            HSigSubpacket::PreferredSymmetricAlgos(vec![
                SymmetricAlgos::AES256,
                SymmetricAlgos::AES192,
                SymmetricAlgos::AES128,
                SymmetricAlgos::TripleDES,
            ]),
            HSigSubpacket::PreferredHashAlgos(vec![
                HashAlgo::SHA2_512,
                HashAlgo::SHA2_384,
                HashAlgo::SHA2_256,
                HashAlgo::SHA2_224,
            ]),
            HSigSubpacket::PreferredCompressionAlgos(vec![
                CompressionAlgos::ZLIB,
                CompressionAlgos::BZip2,
                CompressionAlgos::ZIP,
            ]),
            HSigSubpacket::KeyServerPreference(0x80),
        ]);

        self.packets.push(Packet::PartialSignature(partial));
        self
    }

    pub fn get_hashable(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        for packet in self.packets.iter() {
            match packet {
                Packet::PublicKey(pubkey) => buffer.extend(pubkey.to_hashable_bytes()),
                Packet::Signature(sig) => buffer.extend(sig.to_hashable_bytes()),
                Packet::PartialSignature(partial) => buffer.extend(partial.to_hashable_bytes()),
                Packet::UserID(userid) => buffer.extend(userid.to_hashable_bytes()),
            }
        }
        buffer
    }

    pub fn get_formatted_message(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        for packet in self.packets.iter() {
            match packet {
                Packet::PublicKey(pubkey) => buffer.extend(pubkey.to_formatted_bytes()),
                Packet::Signature(sig) => buffer.extend(sig.to_formatted_bytes()),
                Packet::UserID(userid) => buffer.extend(userid.to_formatted_bytes()),
                Packet::PartialSignature(_) => unreachable!(),
            }
        }
        buffer
    }
}

enum Packet<'a> {
    PublicKey(PKPacket<'a>),
    Signature(Signature),
    PartialSignature(PartialSignature),
    UserID(UserID),
}

#[repr(u8)]
#[derive(Copy, Clone)]
enum Version {
    V4 = 4,
}

#[repr(u8)]
#[derive(Copy, Clone)]
enum SigType {
    Binary = 0x00,
    UserIDPKCert = 0x10,
}

#[repr(u8)]
#[derive(Copy, Clone)]
enum PublicKeyAlgorithm {
    RSASE = 0x01,
    ECDSA = 0x13,
}

pub enum SignatureData {
    ECDSA(Vec<u8>, Vec<u8>),
}

impl ToPGPBytes for SignatureData {
    fn to_formatted_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        match self {
            SignatureData::ECDSA(r, s) => {
                let r_len = get_mpi_bits(r);
                buffer.extend(r_len.to_be_bytes());
                buffer.extend_from_slice(r);

                let s_len = get_mpi_bits(s);
                buffer.extend(s_len.to_be_bytes());
                buffer.extend_from_slice(s);
            }
        }
        buffer
    }

    fn to_raw_bytes(&self) -> Vec<u8> {
        self.to_formatted_bytes()
    }

    fn to_hashable_bytes(&self) -> Vec<u8> {
        self.to_formatted_bytes()
    }
}

/// A trait for contextualizing OpenPGP object interpretation.
///
/// OpenPGP objects are serialized differently based on where they are used. For
/// instance, a Public Key packet can be interpreted differently when being written
/// to file versus when it needs to be signed. This is not only true for packets,
/// but for some subpackets as well.
trait ToPGPBytes {
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
    SHA2_256 = 8,
    SHA2_384 = 9,
    SHA2_512 = 10,
    SHA2_224 = 11,
}

#[repr(u8)]
#[derive(Copy, Clone)]
enum SymmetricAlgos {
    TripleDES = 0x02,
    AES128 = 0x07,
    AES192 = 0x08,
    AES256 = 0x09,
}

#[repr(u8)]
#[derive(Copy, Clone)]
enum CompressionAlgos {
    ZIP = 0x01,
    ZLIB = 0x02,
    BZip2 = 0x03,
}

#[repr(u8)]
#[derive(Copy, Clone)]
enum KeyFlags {
    CanSign = 0x02,
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

enum HSigSubpacket {
    CreationTime(Duration),
    Fingerprint(Vec<u8>),
    KeyFlags(KeyFlags),
    PreferredSymmetricAlgos(Vec<SymmetricAlgos>),
    PreferredHashAlgos(Vec<HashAlgo>),
    PreferredCompressionAlgos(Vec<CompressionAlgos>),
    KeyServerPreference(u8),
}

enum SigSubpacket {
    KeyID(Vec<u8>),
}

#[repr(u8)]
enum SigSubpacketID {
    CreationTime = 0x02,
    PreferredSymmetricAlgos = 0x0b,
    KeyID = 0x10,
    PreferredHashAlgos = 0x15,
    PreferredCompressionAlgos = 0x16,
    KeyServerPreference = 0x17,
    KeyFlags = 0x1b,
    IssuerFingerprint = 0x21,
}

impl ToPGPBytes for HSigSubpacket {
    fn to_raw_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        match self {
            HSigSubpacket::CreationTime(duration) => buffer.extend(duration_to_bytes(*duration)),
            HSigSubpacket::Fingerprint(fingerprint) => buffer.extend(fingerprint),
            HSigSubpacket::KeyFlags(flags) => buffer.push(*flags as u8),
            HSigSubpacket::PreferredSymmetricAlgos(algos) => {
                buffer.extend(algos.iter().map(|algo| *algo as u8).collect::<Vec<u8>>())
            }
            HSigSubpacket::PreferredHashAlgos(algos) => {
                buffer.extend(algos.iter().map(|algo| *algo as u8).collect::<Vec<u8>>())
            }
            HSigSubpacket::PreferredCompressionAlgos(algos) => {
                buffer.extend(algos.iter().map(|algo| *algo as u8).collect::<Vec<u8>>())
            }
            HSigSubpacket::KeyServerPreference(pref) => buffer.push(*pref as u8),
        };
        buffer
    }

    fn to_formatted_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        match self {
            HSigSubpacket::CreationTime(duration) => {
                let duration = duration_to_bytes(*duration);
                let mut length = (duration.len() + 1).to_be_bytes();
                buffer.extend_from_slice(format_subpacket_length(&mut length));
                buffer.push(SigSubpacketID::CreationTime as u8);
                buffer.extend(duration);
            }
            HSigSubpacket::Fingerprint(fingerprint) => {
                let mut length = (fingerprint.len() + 2).to_be_bytes();
                buffer.extend_from_slice(format_subpacket_length(&mut length));
                buffer.push(SigSubpacketID::IssuerFingerprint as u8);
                buffer.push(Version::V4 as u8);
                buffer.extend(fingerprint)
            }
            HSigSubpacket::KeyFlags(flags) => {
                let mut length = 2_usize.to_be_bytes();
                buffer.extend_from_slice(format_subpacket_length(&mut length));
                buffer.push(SigSubpacketID::KeyFlags as u8);
                buffer.push(*flags as u8);
            }
            HSigSubpacket::PreferredSymmetricAlgos(algos) => {
                let mut length = (algos.len() + 1).to_be_bytes();
                buffer.extend_from_slice(format_subpacket_length(&mut length));
                buffer.push(SigSubpacketID::PreferredSymmetricAlgos as u8);
                buffer.extend(algos.iter().map(|algo| *algo as u8).collect::<Vec<u8>>())
            }
            HSigSubpacket::PreferredHashAlgos(algos) => {
                let mut length = (algos.len() + 1).to_be_bytes();
                buffer.extend_from_slice(format_subpacket_length(&mut length));
                buffer.push(SigSubpacketID::PreferredHashAlgos as u8);
                buffer.extend(algos.iter().map(|algo| *algo as u8).collect::<Vec<u8>>());
            }
            HSigSubpacket::PreferredCompressionAlgos(algos) => {
                let mut length = (algos.len() + 1).to_be_bytes();
                buffer.extend_from_slice(format_subpacket_length(&mut length));
                buffer.push(SigSubpacketID::PreferredCompressionAlgos as u8);
                buffer.extend(algos.iter().map(|algo| *algo as u8).collect::<Vec<u8>>())
            }
            HSigSubpacket::KeyServerPreference(pref) => {
                let mut length = 2_usize.to_be_bytes();
                buffer.extend_from_slice(format_subpacket_length(&mut length));
                buffer.push(SigSubpacketID::KeyServerPreference as u8);
                buffer.push(*pref as u8);
            }
        };
        buffer
    }

    fn to_hashable_bytes(&self) -> Vec<u8> {
        self.to_formatted_bytes()
    }
}

impl ToPGPBytes for SigSubpacket {
    fn to_raw_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        match self {
            SigSubpacket::KeyID(keyid) => buffer.extend(keyid),
        };
        buffer
    }

    fn to_formatted_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        match self {
            SigSubpacket::KeyID(keyid) => {
                let mut len = (keyid.len() + 1).to_be_bytes();
                buffer.extend(format_subpacket_length(&mut len));
                buffer.push(SigSubpacketID::KeyID as u8);
                buffer.extend(keyid)
            }
        };
        buffer
    }

    fn to_hashable_bytes(&self) -> Vec<u8> {
        let mut buffer = vec![0xb4];
        match self {
            SigSubpacket::KeyID(keyid) => {
                buffer.extend_from_slice(&(keyid.len() as u32).to_be_bytes());
                buffer.extend_from_slice(keyid);
            }
        };
        buffer
    }
}

pub enum PublicKey<'a> {
    ECDSA(CurveOID, &'a [u8], &'a [u8]),
    RSA(&'a [u8], &'a [u8]),
}

impl<'a> ToPGPBytes for PublicKey<'a> {
    fn to_raw_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        match self {
            PublicKey::ECDSA(oid, key_x, key_y) => {
                buffer.push(CURVE_REPR[*oid].len() as u8);
                buffer.extend(CURVE_REPR[*oid]);

                format_ec_point(&mut buffer, key_x, key_y);
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

    fn to_formatted_bytes(&self) -> Vec<u8> {
        self.to_raw_bytes()
    }

    fn to_hashable_bytes(&self) -> Vec<u8> {
        self.to_raw_bytes()
    }
}

/// A structure that holds signature metadata before the signature is computed.
///
/// While not mandated by the standard, we can view a Signature packet to be immutable,
/// as the data it holds has been signed. However, in our model, the data that needs
/// to be signed does not exist until we construct the signature, for which we need
/// the signed data, meaning separating the two structures is preferred.
struct PartialSignature {
    version: Version,
    sigtype: SigType,
    pubkey_algo: PublicKeyAlgorithm,
    hash_algo: HashAlgo,
    subpackets: Vec<HSigSubpacket>,
}

impl PartialSignature {
    fn new(
        sigtype: SigType,
        pubkey_algo: PublicKeyAlgorithm,
        time: Option<Duration>,
    ) -> PartialSignature {
        // TODO Move to a separate function
        let epoch = match time {
            Some(n) => n,
            None => utils::get_current_epoch(),
        };

        let mut partial_signature = PartialSignature {
            version: Version::V4,
            sigtype,
            pubkey_algo,
            hash_algo: HashAlgo::SHA2_256,
            subpackets: vec![],
        };

        partial_signature
            .subpackets
            .push(HSigSubpacket::CreationTime(epoch));

        partial_signature
    }
}

impl<'a> ToPGPBytes for PartialSignature {
    fn to_raw_bytes(&self) -> Vec<u8> {
        let mut buffer = vec![
            self.version as u8,
            self.sigtype as u8,
            self.pubkey_algo as u8,
            self.hash_algo as u8,
        ];
        let mut hashable_subpackets = self
            .subpackets
            .iter()
            .map(|subpkt| subpkt.to_formatted_bytes())
            .flatten()
            .collect::<Vec<u8>>();
        buffer.extend(&hashable_subpackets.len().to_be_bytes()[6..]);
        buffer.append(&mut hashable_subpackets);
        buffer
    }

    /// A V4 signature hashes the packet body starting from its first field, the
    /// version number, through the end of the hashed subpacket data and a final
    /// extra trailer. Thus, the hashed fields are:
    ///  - the signature version (0x04),
    ///  - the signature type,
    ///  - the public-key algorithm,
    ///  - the hash algorithm,
    ///  - the hashed subpacket length (two octets),
    ///  - the hashed subpacket body,
    ///  - the two octets 0x04 and 0xFF,
    ///  - a four-octet big-endian number that is the length of the hashed data from the
    /// Signature packet stopping right before the 0x04, 0xff octets. */
    fn to_hashable_bytes(&self) -> Vec<u8> {
        let mut contents = self.to_raw_bytes();
        let len = contents.len() as u32;

        contents.extend(&[0x04, 0xFF]);
        contents.extend(&len.to_be_bytes());
        contents
    }

    fn to_formatted_bytes(&self) -> Vec<u8> {
        let mut contents = self.to_hashable_bytes();

        let mut header = calculate_packet_header(&contents, PacketHeader::Signature);
        header.append(&mut contents);
        header
    }
}

pub struct Signature {
    partial: PartialSignature,
    subpackets: Vec<SigSubpacket>,
    hash: [u8; 2],
    signature: SignatureData,
}

impl<'a> Signature {
    fn new(partial: PartialSignature, hash: [u8; 2], signature: SignatureData) -> Signature {
        Signature {
            partial,
            subpackets: vec![],
            hash,
            signature,
        }
    }
}

impl ToPGPBytes for Signature {
    fn to_raw_bytes(&self) -> Vec<u8> {
        let mut partial_signature = self.partial.to_raw_bytes();

        let regular_subpackets = self
            .subpackets
            .iter()
            .map(|subpkt| subpkt.to_formatted_bytes())
            .flatten()
            .collect::<Vec<u8>>();
        let subpacket_len = regular_subpackets.len() as u16;
        partial_signature.extend(subpacket_len.to_be_bytes());
        partial_signature.extend(regular_subpackets);
        partial_signature.extend_from_slice(&self.hash);
        partial_signature.extend(self.signature.to_formatted_bytes());

        partial_signature
    }

    fn to_formatted_bytes(&self) -> Vec<u8> {
        let mut buffer = self.to_raw_bytes();
        let mut header = calculate_packet_header(&buffer, PacketHeader::Signature);
        header.append(&mut buffer);

        header
    }

    fn to_hashable_bytes(&self) -> Vec<u8> {
        self.partial.to_hashable_bytes()
    }
}

pub struct UserID {
    pub user: String,
    pub email: String,
}

impl ToPGPBytes for UserID {
    fn to_raw_bytes(&self) -> Vec<u8> {
        let body = format!("{} <{}>", self.user, self.email);
        body.as_bytes().to_vec()
    }

    fn to_formatted_bytes(&self) -> Vec<u8> {
        let body = self.to_raw_bytes();
        let mut header = calculate_packet_header(&body, PacketHeader::UserID);
        header.extend(body);
        header
    }
    /// A certification signature (type 0x10 through 0x13) hashes the User ID being
    /// bound to the key into the hash context after the above data. A V4 or V5
    /// certification hashes the constant 0xB4 for User ID certifications or the
    /// constant 0xD1 for User Attribute certifications, followed by a four-octet
    /// number giving the length of the User ID or User Attribute data, and then the
    /// User ID or User Attribute data.
    fn to_hashable_bytes(&self) -> Vec<u8> {
        let mut body = self.to_raw_bytes();
        let mut header = (body.len() as u32).to_be_bytes().to_vec();
        header.append(&mut body);
        header
    }
}

pub struct PKPacket<'a> {
    version: Version,
    pub creation_time: Duration,
    days_until_expiration: u16,
    public_key: PublicKey<'a>,
}

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

    // The Key ID is unambiguously the lowest 64 bits of the key hash
    pub fn keyid(&self) -> Vec<u8> {
        let hash = sha160_hash(&self.to_hashable_bytes());
        let len = hash.len();
        hash[len - 8..].to_vec()

        /* .iter()
        .map(|hex| format!("{:02X}", hex))
        .collect::<Vec<String>>()
        .join("") */
    }

    pub fn fingerprint(&self) -> Vec<u8> {
        sha160_hash(&self.to_hashable_bytes())
    }
}

impl ToPGPBytes for PKPacket<'_> {
    fn to_formatted_bytes(&self) -> Vec<u8> {
        let mut buffer = self.to_raw_bytes();
        let mut header = calculate_packet_header(&buffer, PacketHeader::PublicKey);
        header.append(&mut buffer);

        header
    }

    fn to_hashable_bytes(&self) -> Vec<u8> {
        let mut key = self.to_raw_bytes();
        let mut buffer = vec![0x99];
        buffer.extend((key.len() as u16).to_be_bytes());
        buffer.append(&mut key);
        buffer
    }

    fn to_raw_bytes(&self) -> Vec<u8> {
        let mut buffer = vec![self.version as u8];
        buffer.extend(duration_to_bytes(self.creation_time));
        buffer.push(match self.public_key {
            PublicKey::ECDSA(_, _, _) => PublicKeyAlgorithm::ECDSA,
            PublicKey::RSA(_, _) => PublicKeyAlgorithm::RSASE,
        } as u8);
        buffer.extend(self.public_key.to_raw_bytes());
        buffer
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

        // println!("{:X?}", public_key.to_formatted_bytes());
    }

    #[test]
    fn public_key_keyid() {
        let public_key = PKPacket::new(RSA_PUBLIC_KEY, Some(Duration::from_secs(0x60fc16a7)));

        assert_eq!(
            public_key.keyid(),
            &[0xD3, 0x8B, 0x2A, 0xC8, 0x1B, 0xA3, 0x6F, 0xA3]
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
        let partial_signature = PartialSignature {
            version: Version::V4,
            sigtype: SigType::Binary,
            pubkey_algo: PublicKeyAlgorithm::ECDSA,
            hash_algo: HashAlgo::SHA2_256,
            subpackets: vec![
                HSigSubpacket::Fingerprint(vec![
                    0xa1, 0xd5, 0x00, 0x04, 0x13, 0xa0, 0xb7, 0xff, 0x19, 0x34, 0xd2, 0x97, 0xd1,
                    0x1d, 0xdb, 0x06, 0x0e, 0x9b, 0xfa, 0xe6,
                ]),
                HSigSubpacket::CreationTime(Duration::from_secs(1627558312)),
            ],
        };
        let mut signature = Signature::new(
            partial_signature,
            [0x8a, 0x59],
            SignatureData::ECDSA(
                vec![
                    0x3c, 0xbc, 0xf8, 0x15, 0xb0, 0x81, 0x11, 0xb2, 0x44, 0xa0, 0x33, 0xc7, 0x41,
                    0x4a, 0x1b, 0xed, 0x66, 0x87, 0xb4, 0x5b, 0x37, 0xf7, 0x63, 0x53, 0x3f, 0x7d,
                    0xc2, 0x7f, 0xb2, 0x2c, 0x1a, 0xb0,
                ],
                vec![
                    0x56, 0x34, 0xc3, 0xfc, 0x3c, 0xc1, 0xe9, 0x99, 0xd1, 0xd4, 0x56, 0xcd, 0xac,
                    0x3e, 0xa9, 0xc5, 0x7b, 0x9b, 0x5a, 0x7b, 0xdd, 0xb8, 0xb5, 0x05, 0xb0, 0xb8,
                    0xc5, 0xcd, 0xf8, 0x6a, 0xaa, 0x86,
                ],
            ),
        );

        signature.subpackets.push(SigSubpacket::KeyID(vec![
            0xd1, 0x1d, 0xdb, 0x06, 0x0e, 0x9b, 0xfa, 0xe6,
        ]));

        let signature_bytes = signature.to_formatted_bytes();
        let sample_signature = &[
            0x88, 0x75, 0x04, 0x00, 0x13, 0x08, 0x00, 0x1d, 0x16, 0x21, 0x04, 0xa1, 0xd5, 0x00,
            0x04, 0x13, 0xa0, 0xb7, 0xff, 0x19, 0x34, 0xd2, 0x97, 0xd1, 0x1d, 0xdb, 0x06, 0x0e,
            0x9b, 0xfa, 0xe6, 0x05, 0x02, 0x61, 0x02, 0x91, 0xa8, 0x00, 0x0a, 0x09, 0x10, 0xd1,
            0x1d, 0xdb, 0x06, 0x0e, 0x9b, 0xfa, 0xe6, 0x8a, 0x59, 0x00, 0xfe, 0x3c, 0xbc, 0xf8,
            0x15, 0xb0, 0x81, 0x11, 0xb2, 0x44, 0xa0, 0x33, 0xc7, 0x41, 0x4a, 0x1b, 0xed, 0x66,
            0x87, 0xb4, 0x5b, 0x37, 0xf7, 0x63, 0x53, 0x3f, 0x7d, 0xc2, 0x7f, 0xb2, 0x2c, 0x1a,
            0xb0, 0x00, 0xff, 0x56, 0x34, 0xc3, 0xfc, 0x3c, 0xc1, 0xe9, 0x99, 0xd1, 0xd4, 0x56,
            0xcd, 0xac, 0x3e, 0xa9, 0xc5, 0x7b, 0x9b, 0x5a, 0x7b, 0xdd, 0xb8, 0xb5, 0x05, 0xb0,
            0xb8, 0xc5, 0xcd, 0xf8, 0x6a, 0xaa, 0x86,
        ];

        assert_eq!(signature_bytes, sample_signature);
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
