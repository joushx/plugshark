#![allow(unused)]

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldDisplayType {
    BaseNone = 0,            // < none

    // Integral and float types
    BaseDec = 1,             // < decimal [integer, float]
    BaseHex = 2,             // < hexadecimal [integer, float]
    BaseOct = 3,             // < octal [integer]
    BaseDecHex = 4,          // < decimal (hexadecimal) [integer]
    BaseHexDec = 5,          // < hexadecimal (decimal) [integer]
    BaseCustom = 6,          // < call custom routine to format [integer, float]
    BaseExp = 7,             // < exponential [float]

    // Byte separators
    SepDot = 8,              // < hexadecimal bytes with a period (.) between each byte
    SepDash = 9,             // < hexadecimal bytes with a dash (-) between each byte
    SepColon = 10,           // < hexadecimal bytes with a colon (:) between each byte
    SepSpace = 11,           // < hexadecimal bytes with a space between each byte

    // Address types
    BaseNetmask = 12,        // < Used for IPv4 address that shouldn't be resolved (like for netmasks)

    // Port types
    BasePtUdp = 13,          // < UDP port
    BasePtTcp = 14,          // < TCP port
    BasePtDccp = 15,         // < DCCP port
    BasePtSctp = 16,         // < SCTP port

    // OUI types
    BaseOui = 17,            // < OUI resolution

    // Time types
    AbsoluteTimeLocal = 18,  // < local time in our time zone, with month and day
    AbsoluteTimeUtc = 19,    // < UTC, with month and day
    AbsoluteTimeDoyUtc = 20, // < UTC, with 1-origin day-of-year
    AbsoluteTimeNtpUtc = 21, // < UTC, with "NULL" when timestamp is all zeros
    AbsoluteTimeUnix = 22,   // < Unix time

    // String types
    BaseStrWsp = 23,         // < Replace all whitespace characters (newline, formfeed, etc) with "space".
}

impl FieldDisplayType {
    pub fn from_i32(value: i32) -> Option<FieldDisplayType> {
        match value {
            0 => Some(FieldDisplayType::BaseNone),
            1 => Some(FieldDisplayType::BaseDec),
            2 => Some(FieldDisplayType::BaseHex),
            3 => Some(FieldDisplayType::BaseOct),
            4 => Some(FieldDisplayType::BaseDecHex),
            5 => Some(FieldDisplayType::BaseHexDec),
            6 => Some(FieldDisplayType::BaseCustom),
            7 => Some(FieldDisplayType::BaseExp),
            8 => Some(FieldDisplayType::SepDot),
            9 => Some(FieldDisplayType::SepDash),
            10 => Some(FieldDisplayType::SepColon),
            11 => Some(FieldDisplayType::SepSpace),
            12 => Some(FieldDisplayType::BaseNetmask),
            13 => Some(FieldDisplayType::BasePtUdp),
            14 => Some(FieldDisplayType::BasePtTcp),
            15 => Some(FieldDisplayType::BasePtDccp),
            16 => Some(FieldDisplayType::BasePtSctp),
            17 => Some(FieldDisplayType::BaseOui),
            18 => Some(FieldDisplayType::AbsoluteTimeLocal),
            19 => Some(FieldDisplayType::AbsoluteTimeUtc),
            20 => Some(FieldDisplayType::AbsoluteTimeDoyUtc),
            21 => Some(FieldDisplayType::AbsoluteTimeNtpUtc),
            22 => Some(FieldDisplayType::AbsoluteTimeUnix),
            23 => Some(FieldDisplayType::BaseStrWsp),
            _ => None,
        }
    }

    pub fn to_i32(self) -> i32 {
        self as i32
    }
}


#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    None = 0,              // FT_NONE: used for text labels with no value
    Protocol = 1,          // FT_PROTOCOL
    Boolean = 2,           // FT_BOOLEAN: true and false come from <glib.h>
    Char = 3,              // FT_CHAR: 1-octet character as 0-255
    Uint8 = 4,             // FT_UINT8
    Uint16 = 5,            // FT_UINT16
    Uint24 = 6,            // FT_UINT24: really a UINT32, but displayed as 6 hex-digits if FD_HEX
    Uint32 = 7,            // FT_UINT32
    Uint40 = 8,            // FT_UINT40: really a UINT64, but displayed as 10 hex-digits if FD_HEX
    Uint48 = 9,            // FT_UINT48: really a UINT64, but displayed as 12 hex-digits if FD_HEX
    Uint56 = 10,           // FT_UINT56: really a UINT64, but displayed as 14 hex-digits if FD_HEX
    Uint64 = 11,           // FT_UINT64
    Int8 = 12,             // FT_INT8
    Int16 = 13,            // FT_INT16
    Int24 = 14,            // FT_INT24: same as for UINT24
    Int32 = 15,            // FT_INT32
    Int40 = 16,            // FT_INT40: same as for UINT40
    Int48 = 17,            // FT_INT48: same as for UINT48
    Int56 = 18,            // FT_INT56: same as for UINT56
    Int64 = 19,            // FT_INT64
    IEEE11073SFloat = 20,  // FT_IEEE_11073_SFLOAT
    IEEE11073Float = 21,   // FT_IEEE_11073_FLOAT
    Float = 22,            // FT_FLOAT
    Double = 23,           // FT_DOUBLE
    AbsoluteTime = 24,     // FT_ABSOLUTE_TIME
    RelativeTime = 25,     // FT_RELATIVE_TIME
    String = 26,           // FT_STRING: counted string, with no null terminator
    Stringz = 27,          // FT_STRINGZ: null-terminated string
    UintString = 28,       // FT_UINT_STRING: counted string, with count being the first part of the value
    Ether = 29,            // FT_ETHER
    Bytes = 30,            // FT_BYTES
    UintBytes = 31,        // FT_UINT_BYTES
    IPv4 = 32,             // FT_IPv4
    IPv6 = 33,             // FT_IPv6
    IPXNet = 34,           // FT_IPXNET
    Framenum = 35,         // FT_FRAMENUM: a UINT32, but if selected lets you go to frame with that number
    Guid = 36,             // FT_GUID
    Oid = 37,              // FT_OID: OBJECT IDENTIFIER
    Eui64 = 38,            // FT_EUI64
    Ax25 = 39,             // FT_AX25
    Vines = 40,            // FT_VINES
    RelOid = 41,           // FT_REL_OID: RELATIVE-OID
    SystemId = 42,         // FT_SYSTEM_ID
    StringzPad = 43,       // FT_STRINGZPAD: null-padded string
    FCWwn = 44,            // FT_FCWWN
    StringzTrunc = 45,     // FT_STRINGZTRUNC: null-truncated string
    NumTypes = 46,         // FT_NUM_TYPES: last item number plus one
    Scalar = 47,           // FT_SCALAR: Pseudo-type used only internally for certain arithmetic operations.
}

impl FieldType {
    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0 => Some(FieldType::None),
            1 => Some(FieldType::Protocol),
            2 => Some(FieldType::Boolean),
            3 => Some(FieldType::Char),
            4 => Some(FieldType::Uint8),
            5 => Some(FieldType::Uint16),
            6 => Some(FieldType::Uint24),
            7 => Some(FieldType::Uint32),
            8 => Some(FieldType::Uint40),
            9 => Some(FieldType::Uint48),
            10 => Some(FieldType::Uint56),
            11 => Some(FieldType::Uint64),
            12 => Some(FieldType::Int8),
            13 => Some(FieldType::Int16),
            14 => Some(FieldType::Int24),
            15 => Some(FieldType::Int32),
            16 => Some(FieldType::Int40),
            17 => Some(FieldType::Int48),
            18 => Some(FieldType::Int56),
            19 => Some(FieldType::Int64),
            20 => Some(FieldType::IEEE11073SFloat),
            21 => Some(FieldType::IEEE11073Float),
            22 => Some(FieldType::Float),
            23 => Some(FieldType::Double),
            24 => Some(FieldType::AbsoluteTime),
            25 => Some(FieldType::RelativeTime),
            26 => Some(FieldType::String),
            27 => Some(FieldType::Stringz),
            28 => Some(FieldType::UintString),
            29 => Some(FieldType::Ether),
            30 => Some(FieldType::Bytes),
            31 => Some(FieldType::UintBytes),
            32 => Some(FieldType::IPv4),
            33 => Some(FieldType::IPv6),
            34 => Some(FieldType::IPXNet),
            35 => Some(FieldType::Framenum),
            36 => Some(FieldType::Guid),
            37 => Some(FieldType::Oid),
            38 => Some(FieldType::Eui64),
            39 => Some(FieldType::Ax25),
            40 => Some(FieldType::Vines),
            41 => Some(FieldType::RelOid),
            42 => Some(FieldType::SystemId),
            43 => Some(FieldType::StringzPad),
            44 => Some(FieldType::FCWwn),
            45 => Some(FieldType::StringzTrunc),
            46 => Some(FieldType::NumTypes),
            47 => Some(FieldType::Scalar),
            _ => None,
        }
    }

    pub fn to_u32(self) -> u32 {
        self as u32
    }
}

#[repr(u32)]
pub enum FieldEncoding {
    LittleEndian = 0x80000000,
    BigEndian = 0x00000000,
}

impl FieldEncoding {
    pub fn to_u32(self) -> u32 {
        self as u32
    }

    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0x80000000 => Some(Self::LittleEndian),
            0x00000000 => Some(Self::BigEndian),
            _ => None,
        }
    }
}

#[repr(u32)]
pub enum StringFieldEncoding {
    Ascii = 0x00000000,
    Utf8 = 0x00000002,
    Utf16 = 0x00000004,
    Ucs2 = 0x00000006,
    Ucs4 = 0x00000008,
    Iso88591 = 0x0000000A,
    Iso88592 = 0x0000000C,
    Iso88593 = 0x0000000E,
    Iso88594 = 0x00000010,
    Iso88595 = 0x00000012,
    Iso88596 = 0x00000014,
    Iso88597 = 0x00000016,
    Iso88598 = 0x00000018,
    Iso88599 = 0x0000001A,
    Iso885910 = 0x0000001C,
    Iso885911 = 0x0000001E,
    // Iso885912 was abandoned
    Iso885912 = 0x00000020,
    Iso885913 = 0x00000022,
    Iso885914 = 0x00000024,
    Iso885915 = 0x00000026,
    Iso885916 = 0x00000028,
    Windows1250 = 0x0000002A,
    Ts230387BitsPacked = 0x0000002C,
    Ebcdic = 0x0000002E,
    MacRoman = 0x00000030,
    Cp437 = 0x00000032,
    Ascii7Bits = 0x00000034,
    T61 = 0x00000036,
    EbcdicCp037 = 0x00000038,
    Windows1252 = 0x0000003A,
    Windows1251 = 0x0000003C,
    Cp855 = 0x0000003E,
    Cp866 = 0x00000040,
    Iso646Basic = 0x00000042,
    // Packed BCD, digits 0-9
    BcdDigits09 = 0x00000044,
    // Keypad-with-a/b/c "telephony BCD" = 0-9, *, #, a, b, c
    KeypadAbcTbcd = 0x00000046,
    // Keypad-with-B/C "telephony BCD" = 0-9, B, C, *, #
    KeypadBcTbcd = 0x00000048,
    Ts230387BitsUnpacked = 0x0000004C,
    // ETSI TS 102 221 Annex A
    EtsiTs102221AnnexA = 0x0000004E,
    Gb18030 = 0x00000050,
    EucKr = 0x00000052,
    // The encoding the APN/DNN field follows 3GPP TS 23.003 [2] clause 9.1.
    ApnStr = 0x00000054,
    // DECT standard character set as defined in ETSI EN 300 175-5 Annex D
    DectStandard8Bits = 0x00000056,
    // DECT standard 4bits character set as defined in ETSI EN 300 175-5 Annex D (BCD with 0xb = SPACE)
    DectStandard4BitsTbcd = 0x00000058,
    EbcdicCp500 = 0x00000060,
}

impl StringFieldEncoding {
    pub fn to_u32(self) -> u32 {
        self as u32
    }

    pub fn from_u32(value: u32) -> Option<Self> {
        match value {
            0x00000000 => Some(Self::Ascii),
            0x00000002 => Some(Self::Utf8),
            0x00000004 => Some(Self::Utf16),
            0x00000006 => Some(Self::Ucs2),
            0x00000008 => Some(Self::Ucs4),
            0x0000000A => Some(Self::Iso88591),
            0x0000000C => Some(Self::Iso88592),
            0x0000000E => Some(Self::Iso88593),
            0x00000010 => Some(Self::Iso88594),
            0x00000012 => Some(Self::Iso88595),
            0x00000014 => Some(Self::Iso88596),
            0x00000016 => Some(Self::Iso88597),
            0x00000018 => Some(Self::Iso88598),
            0x0000001A => Some(Self::Iso88599),
            0x0000001C => Some(Self::Iso885910),
            0x0000001E => Some(Self::Iso885911),
            0x00000020 => Some(Self::Iso885912),
            0x00000022 => Some(Self::Iso885913),
            0x00000024 => Some(Self::Iso885914),
            0x00000026 => Some(Self::Iso885915),
            0x00000028 => Some(Self::Iso885916),
            0x0000002A => Some(Self::Windows1250),
            0x0000002C => Some(Self::Ts230387BitsPacked),
            0x0000002E => Some(Self::Ebcdic),
            0x00000030 => Some(Self::MacRoman),
            0x00000032 => Some(Self::Cp437),
            0x00000034 => Some(Self::Ascii7Bits),
            0x00000036 => Some(Self::T61),
            0x00000038 => Some(Self::EbcdicCp037),
            0x0000003A => Some(Self::Windows1252),
            0x0000003C => Some(Self::Windows1251),
            0x0000003E => Some(Self::Cp855),
            0x00000040 => Some(Self::Cp866),
            0x00000042 => Some(Self::Iso646Basic),
            0x00000044 => Some(Self::BcdDigits09),
            0x00000046 => Some(Self::KeypadAbcTbcd),
            0x00000048 => Some(Self::KeypadBcTbcd),
            0x0000004C => Some(Self::Ts230387BitsUnpacked),
            0x0000004E => Some(Self::EtsiTs102221AnnexA),
            0x00000050 => Some(Self::Gb18030),
            0x00000052 => Some(Self::EucKr),
            0x00000054 => Some(Self::ApnStr),
            0x00000056 => Some(Self::DectStandard8Bits),
            0x00000058 => Some(Self::DectStandard4BitsTbcd),
            0x00000060 => Some(Self::EbcdicCp500),
            _ => None,
        }
    }
}