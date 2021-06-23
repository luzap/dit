
enum Hash {
    MD5 = 1,
    SHA1,
    RIPEMD,
    SHA256 = 8,
    SHA384,
    SHA512,
    SHA224
}







enum Literal {
    Binary = 'b',
    Text = 't',
    UTF8 = 'u',
    MIME = 'm'
}

enum OnePassSignature {
    Binary,
    Text,
    Standalone
}

enum Packet {
    Signature = 2,
    OnePassSignature = 4
    LiteralData(Literal),
    UserID(String, String, String, String,
    UserAttribute = 17
}




enum SignatureSubpacket {
    CreationTime = 2,
    ExpirationTime = 3,
    Exportable = 4,
    TrustSignature = 5,
    RegularExpression = 6,
    Revocable = 7,
    KeyExpirationTime = 9,
    PlaceholderBackwardsCompatibility = 10,
    PreferredSymmetricAlgorithms = 11,
    RevocationKey = 12,
    Issuer = 16,
    NotationData = 20,
    PreferredHashAlgorithms = 21,
    PreferredCompressionAlgorithms = 22,
    KeyServerPreferences = 23,
    PreferredKeyServer = 24,
    PrimaryUserID = 25,
    PolicyURI = 26,
    KeyFlags = 27,
    SignersUserID = 28,
    ReasonForRevocation = 29,
    Features = 30,
    SignatureTarget = 31,
    EmbeddedSignature = 32,
    IssuerFingerprint = 33,
    PreferredAEADAlgorithms = 34
}

enum KeyFlags {
    CertifyKeys = 1,
    SignData = 2,
    EncryptCommunications = 4, 
    EncryptStorage = 8,
    SplitPrivateKey = 16,
    Authentication = 32,
    SharedPrivateKey = 128
}

