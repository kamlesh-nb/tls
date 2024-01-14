const std = @import("std");
const assert = std.debug.assert;

pub const AlertLevel = enum(u8) {
    warning = 1,
    fatal = 2,
    _,
};

pub const AlertDescription = enum(u8) {
    pub const Error = error{
        TlsAlertUnexpectedMessage,
        TlsAlertBadRecordMac,
        TlsAlertRecordOverflow,
        TlsAlertHandshakeFailure,
        TlsAlertBadCertificate,
        TlsAlertUnsupportedCertificate,
        TlsAlertCertificateRevoked,
        TlsAlertCertificateExpired,
        TlsAlertCertificateUnknown,
        TlsAlertIllegalParameter,
        TlsAlertUnknownCa,
        TlsAlertAccessDenied,
        TlsAlertDecodeError,
        TlsAlertDecryptError,
        TlsAlertProtocolVersion,
        TlsAlertInsufficientSecurity,
        TlsAlertInternalError,
        TlsAlertInappropriateFallback,
        TlsAlertMissingExtension,
        TlsAlertUnsupportedExtension,
        TlsAlertUnrecognizedName,
        TlsAlertBadCertificateStatusResponse,
        TlsAlertUnknownPskIdentity,
        TlsAlertCertificateRequired,
        TlsAlertNoApplicationProtocol,
        TlsAlertUnknown,
    };

    close_notify = 0,
    unexpected_message = 10,
    bad_record_mac = 20,
    record_overflow = 22,
    handshake_failure = 40,
    bad_certificate = 42,
    unsupported_certificate = 43,
    certificate_revoked = 44,
    certificate_expired = 45,
    certificate_unknown = 46,
    illegal_parameter = 47,
    unknown_ca = 48,
    access_denied = 49,
    decode_error = 50,
    decrypt_error = 51,
    protocol_version = 70,
    insufficient_security = 71,
    internal_error = 80,
    inappropriate_fallback = 86,
    user_canceled = 90,
    missing_extension = 109,
    unsupported_extension = 110,
    unrecognized_name = 112,
    bad_certificate_status_response = 113,
    unknown_psk_identity = 115,
    certificate_required = 116,
    no_application_protocol = 120,
    _,

    pub fn toError(alert: AlertDescription) Error!void {
        return switch (alert) {
            .close_notify => {}, // not an error
            .unexpected_message => error.TlsAlertUnexpectedMessage,
            .bad_record_mac => error.TlsAlertBadRecordMac,
            .record_overflow => error.TlsAlertRecordOverflow,
            .handshake_failure => error.TlsAlertHandshakeFailure,
            .bad_certificate => error.TlsAlertBadCertificate,
            .unsupported_certificate => error.TlsAlertUnsupportedCertificate,
            .certificate_revoked => error.TlsAlertCertificateRevoked,
            .certificate_expired => error.TlsAlertCertificateExpired,
            .certificate_unknown => error.TlsAlertCertificateUnknown,
            .illegal_parameter => error.TlsAlertIllegalParameter,
            .unknown_ca => error.TlsAlertUnknownCa,
            .access_denied => error.TlsAlertAccessDenied,
            .decode_error => error.TlsAlertDecodeError,
            .decrypt_error => error.TlsAlertDecryptError,
            .protocol_version => error.TlsAlertProtocolVersion,
            .insufficient_security => error.TlsAlertInsufficientSecurity,
            .internal_error => error.TlsAlertInternalError,
            .inappropriate_fallback => error.TlsAlertInappropriateFallback,
            .user_canceled => {}, // not an error
            .missing_extension => error.TlsAlertMissingExtension,
            .unsupported_extension => error.TlsAlertUnsupportedExtension,
            .unrecognized_name => error.TlsAlertUnrecognizedName,
            .bad_certificate_status_response => error.TlsAlertBadCertificateStatusResponse,
            .unknown_psk_identity => error.TlsAlertUnknownPskIdentity,
            .certificate_required => error.TlsAlertCertificateRequired,
            .no_application_protocol => error.TlsAlertNoApplicationProtocol,
            _ => error.TlsAlertUnknown,
        };
    }
};

pub const ProtocolVersion = enum(u16) {
    Tls12 = 0x0303,
    Tls13 = 0x0304,
    _,
};

pub const RecordType = enum(u8) {
    Invalid = 0,
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
    _,
};

pub const HandshakeType = enum(u8) {
    HelloRequest = 0,
    ClientHello = 1,
    ServerHello = 2,
    HelloVerifyRequest = 3,
    NewSessionTicket = 4,
    ServerCertificate = 11,
    ServerKeyExchange = 12,
    CertificateRequest = 13,
    ServerHelloDone = 14,
    CertificateVerify = 15,
    ClientKeyExchange = 16,
    Finished = 20,
};

pub const NamedGroups = enum(u16) {
    x25519 = 0x001D,
    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
};

pub const SignatureAlgorithm = enum(u16) {
    rsa_pkcs1_sha256 = 0x0401,
    rsa_pkcs1_sha384 = 0x0501,
    rsa_pkcs1_sha512 = 0x0601,
};

pub const CipherSuite = enum(u16) {
    ECDHE_RSA_Chacha20_Poly1305 = 0xCCA8,
    ECDHE_RSA_AES128_GCM_SHA256 = 0xC02F,
};

pub const ExtensionType = enum(u16) {
    ServerName = 0,
    MaxFragmentLength = 1,
    ClientCertificateUrl = 2,
    TrustedCaKeys = 3,
    TruncatedHmac = 4,
    StatusRequest = 5,
    UserMapping = 6,
    ClientAuthz = 7,
    ServerAuthz = 8,
    CertType = 9,
    EllipticCurves = 10,
    EcPointFormats = 11,
    SCT = 12,
    SignatureAlgorithms = 13,
    UseSrtp = 14,
    ALPN = 16,
    SessionTicket = 35,
    RenegotiationInfo = 65281,
};

pub inline fn extension(comptime et: ExtensionType, bytes: anytype) [2 + 2 + bytes.len]u8 {
    return int2(@intFromEnum(et)) ++ array(1, bytes);
}

pub inline fn array(comptime elem_size: comptime_int, bytes: anytype) [2 + bytes.len]u8 {
    comptime assert(bytes.len % elem_size == 0);
    return int2(bytes.len) ++ bytes;
}

pub inline fn enum_array(comptime E: type, comptime tags: []const E) [2 + @sizeOf(E) * tags.len]u8 {
    assert(@sizeOf(E) == 2);
    var result: [tags.len * 2]u8 = undefined;
    for (tags, 0..) |elem, i| {
        result[i * 2] = @as(u8, @truncate(@intFromEnum(elem) >> 8));
        result[i * 2 + 1] = @as(u8, @truncate(@intFromEnum(elem)));
    }
    return array(2, result);
}

pub inline fn erray(comptime E: type, comptime tags: []const E) [@sizeOf(E) * tags.len]u8 {
    assert(@sizeOf(E) == 2);
    var result: [tags.len * 2]u8 = undefined;
    for (tags, 0..) |elem, i| {
        result[i * 2] = @as(u8, @truncate(@intFromEnum(elem) >> 8));
        result[i * 2 + 1] = @as(u8, @truncate(@intFromEnum(elem)));
    }
    return result;
}

pub inline fn int2(x: u16) [2]u8 {
    return .{
        @as(u8, @truncate(x >> 8)),
        @as(u8, @truncate(x)),
    };
}

pub inline fn int3(x: u24) [3]u8 {
    return .{
        @as(u8, @truncate(x >> 16)),
        @as(u8, @truncate(x >> 8)),
        @as(u8, @truncate(x)),
    };
}

pub const ciphersuites = &[2]u16{
    @intFromEnum(CipherSuite.ECDHE_RSA_AES128_GCM_SHA256),
    @intFromEnum(CipherSuite.ECDHE_RSA_Chacha20_Poly1305),
};

pub inline fn ciphers() [8]u8 {
    const cs = enum_array(CipherSuite, &.{
        .ECDHE_RSA_Chacha20_Poly1305,
        .ECDHE_RSA_AES128_GCM_SHA256,
    });

    const ciphersuite_bytes = 2 * 2 + 2;
    const x = int2(ciphersuite_bytes);

    return [8]u8{ x[0], x[1], 0x00, 0x0f, cs[2], cs[3], cs[4], cs[5] }; 
}


pub fn structToBytes(_struct: anytype, buff: *[1024] u8, pos: *u16 ) void {
   const info = @typeInfo(@TypeOf(_struct));
    inline for (info.Struct.fields) |field| {
        const value= @field(_struct,  field.name);
        const t = @typeInfo(@TypeOf(value));
        switch (t) {
            .Int => | iinfo | {
                switch (iinfo.bits) {
                    8 => {
                        buff[pos.*] = value;
                        pos.* += 1;
                    },
                    16 => {
                        const _len: u16 = 2;
                        @memcpy(buff[pos.*..(pos.* + _len)], &int2(value));
                        pos.* += _len;
                    },
                    else => {
                        std.debug.print("\nInt Type for field {s} Not supported\n", .{field.name});
                    }
                }
            },
            .Pointer => {
                const _len: u16 = @intCast(value.len);
                @memcpy(buff[pos.*..(pos.*+_len)], value[0.._len]);
                pos.* += _len;
            },
            else => {
                 std.debug.print("\nType for field {s} Not supported\n", .{field.name});
            }
        }
    }
}
 

test "structToBytes" {
    const _id:u16 = 219;

    const s = .{
        .id =  _id,
        .date = 9,
        .name = "kamlesh",
    };
    var pos: u16 = 0;
    var buffer: [1024]u8 = [1]u8{0x00} ** 1024;
    structToBytes(s, &buffer, &pos);

    std.debug.print("{any}", .{buffer[0..pos]});
    
}