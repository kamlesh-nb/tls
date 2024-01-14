const std = @import("std");
const cUtil = @import("crypto/certutil.zig");
const x509 = @import("crypto/x509.zig");
pub const @"pcks1v1.5" = @import("crypto/pcks1-1_5.zig");
const Extensions = @import("extensions.zig").Extensions;
const tls = @import("crypto/tls.zig");

const int2 = tls.int2;
const int3 = tls.int3;
const extension = tls.extension;
const array = tls.array;
const erray = tls.erray;
const enum_array = tls.enum_array;
const alpn = tls.alpn;
const sni = tls.sni;
const ciphers = tls.ciphers;

const CipherSuites = @import("crypto/ciphersuites.zig").CipherSuites;
const Cifers = @import("crypto/ciphersuites.zig");
const Curves = @import("crypto/curves.zig");
const HashSet = @import("crypto/hashset.zig");

const Sha224 = std.crypto.hash.sha2.Sha224;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Sha512 = std.crypto.hash.sha2.Sha512;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Hmac256 = std.crypto.auth.hmac.sha2.HmacSha256;

pub const RecTuple = std.meta.Tuple(&.{ u8, u8, u8, u16 });
pub const HsTuple = std.meta.Tuple(&.{ u8, u24 });

const ClientHandshake = @This();

stream: std.net.Stream = undefined,
allocator: std.mem.Allocator,
hostname: []const u8 = undefined,
hashset: HashSet = undefined,
client_random: [32]u8 = undefined,
server_random: [32]u8 = undefined,
server_version: [2]u8 = undefined,
server_session_id: [1]u8 = undefined,
server_name: []u8 = undefined,
csuite: u16 = 0,
certificates_length: u24 = 0,
certificate_public_key: x509.PublicKey = undefined,
curve_nv: u8 = 0,
curve_id: u16 = 0,
curve_id_buf: [3]u8 = undefined,
server_public_key: []u8 = undefined,
server_public_key_buf: [Curves.maxPubKeyLen(Curves.all)]u8 = undefined,
server_pub_key_len: u8 = 0,
sig_id: u16 = 0,
sig_len: u16 = 0,
sig_bytes: []u8 = undefined,
client_certificate: ?*const x509.ClientCertificateChain = null,
key_data: Cifers.KeyData(CipherSuites.all) = undefined,
master_secret: [48]u8 = undefined,
rand: std.rand.Random = undefined,
server_exts: Extensions = Extensions{},
client_exts: Extensions = Extensions{},
state: tls.HandshakeType = tls.HandshakeType.HelloRequest,

pub fn readRecord(reader: anytype) !RecTuple {
    const rt: u8 = try reader.readByte();
    const vmaj: u8 = try reader.readByte();
    const vmin: u8 = try reader.readByte();
    const len: u16 = try reader.readInt(u16, .big);
    return .{ rt, vmaj, vmin, len };
}

pub fn readHandshake(reader: anytype) !HsTuple {
    const ht: u8 = try reader.readByte();
    const len: u24 = try reader.readInt(u24, .big);
    return .{ ht, len };
}

fn createClientHello(clientHandshake: *ClientHandshake, hw: anytype) !void {
    clientHandshake.rand = std.crypto.random;
    clientHandshake.rand.bytes(&clientHandshake.client_random);

    clientHandshake.client_exts.encode(.ServerName, clientHandshake.hostname);
    clientHandshake.client_exts.encode(.ALPN, "http/1.1");
    clientHandshake.client_exts.encode(.EllipticCurves, &erray(tls.NamedGroups, &.{
        .x25519,
        .secp384r1,
        .secp256r1,
    }));
    clientHandshake.client_exts.encode(.EcPointFormats, &[1]u8{0x00});
    clientHandshake.client_exts.encode(.SignatureAlgorithms, &erray(tls.SignatureAlgorithm, &.{
        .rsa_pkcs1_sha256,
        .rsa_pkcs1_sha384,
        .rsa_pkcs1_sha512,
    }));
    clientHandshake.client_exts.encode(.SCT, &[2]u8{ 0x00, 0x00 });
    clientHandshake.client_exts.bytes();

    const client_hello = .{
        .version = &[2]u8{ 0x03, 0x03 },
        .client_random = &clientHandshake.client_random,
        .session_id = &[1]u8{0x00},
        .ciphers = &ciphers(),
        .compression_method = &[2]u8{ 0x01, 0x00 },
        .ext_len = &int2(clientHandshake.client_exts.pos),
    };

    var pos: u16 = 0;
    var buffer: [1024]u8 = [1]u8{0x00} ** 1024;
    tls.structToBytes(client_hello, &buffer, &pos);

    const rl = int2(pos + clientHandshake.client_exts.pos + 4);
    const hsl = int3(pos + clientHandshake.client_exts.pos);
    const record = [5]u8{ 0x16, 0x03, 0x03, rl[0], rl[1] };
    const handshake = [4]u8{ 0x01, hsl[0], hsl[1], hsl[2] };

    // std.debug.print("\nFields ({d}): {any}\n", .{ pos, buffer[0..pos] });
    // std.debug.print("\nExtensions ({d}): {any}\n", .{ clientHandshake.client_exts.pos, clientHandshake.client_exts.buffer[0..clientHandshake.client_exts.pos] });

    try clientHandshake.stream.writeAll(&record);
    try hw.writeAll(&handshake);
    try hw.writeAll(buffer[0..pos]);
    try hw.writeAll(clientHandshake.client_exts.buffer[0..clientHandshake.client_exts.pos]);
}

fn handleServerHello(self: *ClientHandshake, reader: anytype) !void {
    try reader.readNoEof(&self.server_version);
    try reader.readNoEof(&self.server_random);
    try reader.readNoEof(&self.server_session_id);
    if (self.server_session_id[0] != 0)
        try reader.skipBytes(self.server_session_id[0], .{});

    self.csuite = try reader.readInt(u16, .big);
    var csfound: bool = false;
    inline for (tls.ciphersuites) |cs| {
        if (self.csuite == cs) {
            csfound = true;
        }
    }
    if (!csfound)
        return error.ServerInvalidCipherSuite;

    if ((try reader.readByte()) != 0x00)
        return error.ServerInvalidCompressionMethod;

    try self.server_exts.decode(reader);
}

fn handleServerCertificate(self: *ClientHandshake, reader: anytype) !void {
    self.certificates_length = try reader.readInt(u24, .big);

    self.certificate_public_key = try cUtil.extractCertPublicKey(self.allocator, reader, self.certificates_length);
    // errdefer self.certificate_public_key.deinit(self.allocator);
}

fn handleServerKeyExchange(self: *ClientHandshake, reader: anytype) !void {
    var curve_id_buf: [3]u8 = undefined;
    try reader.readNoEof(&curve_id_buf);

    self.curve_nv = curve_id_buf[0];
    self.curve_id = std.mem.readInt(u16, curve_id_buf[1..], .big);

    var found = false;
    inline for (Curves.all) |curve| {
        if (curve.tag == self.curve_id) {
            found = true;
        }
    }
    if (!found)
        return error.ServerInvalidCurve;

    self.server_pub_key_len = try reader.readByte();

    inline for (Curves.all) |curve| {
        if (curve.tag == self.curve_id) {
            if (curve.pub_key_len != self.server_pub_key_len)
                return error.ServerMalformedResponse;
        }
    }

    // var server_public_key_buf: [Curves.maxPubKeyLen(Curves.all)]u8 = undefined;

    try reader.readNoEof(self.server_public_key_buf[0..self.server_pub_key_len]);
    self.server_public_key = self.server_public_key_buf[0..self.server_pub_key_len];

    if (self.curve_id != Curves.x25519.tag) {
        if (self.server_public_key_buf[0] != 0x04)
            return error.ServerMalformedResponse;
    }

    self.sig_id = try reader.readInt(u16, .big);
    self.sig_len = try reader.readInt(u16, .big);

    var hash_buf: [64]u8 = undefined;
    var hash: []const u8 = undefined;
    const signature_algoritm: x509.Certificate.SignatureAlgorithm = switch (self.sig_id) {
        // TODO: More
        // RSA/PKCS1/SHA256
        0x0401 => block: {
            var sha256 = Sha256.init(.{});
            sha256.update(&self.client_random);
            sha256.update(&self.server_random);
            sha256.update(&curve_id_buf);
            sha256.update(&[1]u8{self.server_pub_key_len});
            sha256.update(self.server_public_key_buf[0..self.server_pub_key_len]);
            sha256.final(hash_buf[0..32]);
            hash = hash_buf[0..32];
            break :block .{ .signature = .rsa, .hash = .sha256 };
        },
        // RSA/PKCS1/SHA512
        0x0601 => block: {
            var sha512 = Sha512.init(.{});
            sha512.update(&self.client_random);
            sha512.update(&self.server_random);
            sha512.update(&curve_id_buf);
            sha512.update(&[1]u8{self.server_pub_key_len});
            sha512.update(self.server_public_key);
            sha512.final(hash_buf[0..64]);
            hash = hash_buf[0..64];
            break :block .{ .signature = .rsa, .hash = .sha512 };
        },
        else => return error.ServerInvalidSignatureAlgorithm,
    };

    self.sig_bytes = try self.allocator.alloc(u8, self.sig_len);

    try reader.readNoEof(self.sig_bytes);

    const result = try @"pcks1v1.5".verify_signature(
        self.allocator,
        signature_algoritm,
        .{ .data = self.sig_bytes, .bit_len = self.sig_len * 8 },
        hash,
        self.certificate_public_key,
    );

    if (!result)
        return error.ServerInvalidSignature;

    self.certificate_public_key.deinit(self.allocator);
    self.certificate_public_key = x509.PublicKey.empty;
}

fn generateClientKeyAndExchange(self: *ClientHandshake, writer: anytype, hw: anytype) !void {
    // Generate keys for the session
    const client_key_pair = Curves.makeKeyPair(Curves.all, self.curve_id, self.rand);

    // Client key exchange
    try writer.writeAll(&[3]u8{ 0x16, 0x03, 0x03 });
    try writer.writeInt(u16, self.server_pub_key_len + 5, .big);
    try hw.writeAll(&[5]u8{ 0x10, 0x00, 0x00, self.server_pub_key_len + 1, self.server_pub_key_len });

    inline for (Curves.all) |curve| {
        if (curve.tag == self.curve_id) {
            const actual_len = @typeInfo(std.meta.fieldInfo(curve.Keys, .public_key).type).Array.len;
            if (self.server_pub_key_len == actual_len + 1) {
                try hw.writeByte(0x04);
            } else {
                std.debug.assert(self.server_pub_key_len == actual_len);
            }
            try hw.writeAll(&@field(client_key_pair, curve.name).public_key);
            break;
        }
    }

    var pre_master_secret_buf: [Curves.maxPreMasterSecretLen(Curves.all)]u8 = undefined;
    const pre_master_secret = try Curves.makePreMasterSecret(
        Curves.all,
        self.curve_id,
        client_key_pair,
        &pre_master_secret_buf,
        self.server_public_key_buf,
    );

    // var master_secret: [48]u8 = undefined;
    const seedlen = 77;
    var seed: [seedlen]u8 = undefined;
    seed[0..13].* = "master secret".*;
    seed[13..45].* = self.client_random;
    seed[45..77].* = self.server_random;

    var a1: [32 + seedlen]u8 = undefined;
    Hmac256.create(a1[0..32], &seed, pre_master_secret);
    var a2: [32 + seedlen]u8 = undefined;
    Hmac256.create(a2[0..32], a1[0..32], pre_master_secret);

    a1[32..].* = seed;
    a2[32..].* = seed;

    var p1: [32]u8 = undefined;
    Hmac256.create(&p1, &a1, pre_master_secret);
    var p2: [32]u8 = undefined;
    Hmac256.create(&p2, &a2, pre_master_secret);

    self.master_secret[0..32].* = p1;
    self.master_secret[32..48].* = p2[0..16].*;

    // Key expansion
    seed[0..13].* = "key expansion".*;
    seed[13..45].* = self.server_random;
    seed[45..77].* = self.client_random;
    a1[32..].* = seed;
    a2[32..].* = seed;

    const KeyExpansionState = struct {
        seed: *const [77]u8,
        a1: *[32 + seedlen]u8,
        a2: *[32 + seedlen]u8,
        master_secret: *const [48]u8,
    };

    const next_32_bytes = struct {
        inline fn f(
            state: *KeyExpansionState,
            comptime chunk_idx: comptime_int,
            chunk: *[32]u8,
        ) void {
            if (chunk_idx == 0) {
                Hmac256.create(state.a1[0..32], state.seed, state.master_secret);
                Hmac256.create(chunk, state.a1, state.master_secret);
            } else if (chunk_idx % 2 == 1) {
                Hmac256.create(state.a2[0..32], state.a1[0..32], state.master_secret);
                Hmac256.create(chunk, state.a2, state.master_secret);
            } else {
                Hmac256.create(state.a1[0..32], state.a2[0..32], state.master_secret);
                Hmac256.create(chunk, state.a1, state.master_secret);
            }
        }
    }.f;
    var state = KeyExpansionState{
        .seed = &seed,
        .a1 = &a1,
        .a2 = &a2,
        .master_secret = &self.master_secret,
    };

    self.key_data = Cifers.key_expansion(CipherSuites.all, self.csuite, &state, next_32_bytes);
}

fn clientChangeCipherSpec(self: *ClientHandshake, writer: anytype) !void {
    _ = self;
    try writer.writeAll(&[6]u8{
        // Client change cipher spec
        0x14, 0x03, 0x03,
        0x00, 0x01, 0x01,
    });
}

fn clientHandshakeFinished(self: *ClientHandshake, writer: anytype) !void {
    var verify_message: [16]u8 = undefined;
    verify_message[0..4].* = "\x14\x00\x00\x0C".*;
    {
        var seed: [47]u8 = undefined;
        seed[0..15].* = "client finished".*;
        // We still need to update the hash one time, so we copy
        // to get the current digest here.
        var hash_copy = self.hashset.sha256;
        hash_copy.final(seed[15..47]);

        var a1: [32 + seed.len]u8 = undefined;
        Hmac256.create(a1[0..32], &seed, &self.master_secret);
        a1[32..].* = seed;
        var p1: [32]u8 = undefined;
        Hmac256.create(&p1, &a1, &self.master_secret);
        verify_message[4..16].* = p1[0..12].*;
    }
    self.hashset.update(&verify_message);

    inline for (CipherSuites.all) |cs| {
        if (cs.tag == self.csuite) {
            try cs.raw_write(
                256,
                self.rand,
                &self.key_data,
                writer,
                [3]u8{ 0x16, 0x03, 0x03 },
                0,
                &verify_message,
            );
        }
    }
}

fn handleServerChangeCipherSpec(reader: anytype) !void {
    const rec = try readRecord(reader);
    const next_byte = try reader.readByte();
    if (rec.@"3" != 1 or next_byte != 0x01) {
        const alert = try reader.readByte();
        std.debug.print("\nSeverity: {d}, Alter: {d}\n", .{ next_byte, alert });
        return error.ServerMalformedResponse;
    }
}

fn handleServerHandshakeFinish(self: *ClientHandshake, reader: anytype) !void {
    const rec = try readRecord(reader);
    var verify_message: [16]u8 = undefined;
    verify_message[0..4].* = "\x14\x00\x00\x0C".*;
    {
        var seed: [47]u8 = undefined;
        seed[0..15].* = "server finished".*;
        self.hashset.sha256.final(seed[15..47]);
        var a1: [32 + seed.len]u8 = undefined;
        Hmac256.create(a1[0..32], &seed, &self.master_secret);
        a1[32..].* = seed;
        var p1: [32]u8 = undefined;
        Hmac256.create(&p1, &a1, &self.master_secret);
        verify_message[4..16].* = p1[0..12].*;
    }

    inline for (CipherSuites.all) |cs| {
        if (cs.tag == self.csuite) {
            if (!try cs.check_verify_message(&self.key_data, rec.@"3", reader, verify_message))
                return error.ServerInvalidVerifyData;
        }
    }
}

fn handShake(clientHandshake: *ClientHandshake) !void {
    const reader = clientHandshake.stream.reader();
    const writer = clientHandshake.stream.writer();
    const hwriter = HashSet.makeHashingWriter(&clientHandshake.hashset, clientHandshake.stream.writer());
    const hreader = HashSet.makeHashingReader(&clientHandshake.hashset, clientHandshake.stream.reader());

    try clientHandshake.createClientHello(hwriter);

    var bytes_read: u24 = 0;
    while (true) {
        const rec = try readRecord(reader);
        const ct: tls.RecordType = @enumFromInt(rec.@"0");
        switch (ct) {
            .Alert => {
                var alert: [2]u8 = undefined;
                try reader.readNoEof(&alert);
                std.log.err("\nSeverity: {d}, Alert Code: {d}\n", .{ alert[0], alert[1] });
                const alertDescription: tls.AlertDescription = @enumFromInt(alert[1]);
                try alertDescription.toError();
            },
            .Handshake => {
                while (clientHandshake.state != .ServerHelloDone) {
                    const hs = try readHandshake(hreader);
                    const ht: tls.HandshakeType = @enumFromInt(hs.@"0");
                    bytes_read += hs.@"1" + 4;
                    switch (ht) {
                        .ServerHello => {
                            try handleServerHello(clientHandshake, hreader);
                            clientHandshake.state = .ServerHello;
                        },
                        .ServerCertificate => {
                            try handleServerCertificate(clientHandshake, hreader);
                            clientHandshake.state = .ServerCertificate;
                        },
                        .ServerKeyExchange => {
                            try handleServerKeyExchange(clientHandshake, hreader);
                            clientHandshake.state = .ServerKeyExchange;
                        },
                        .CertificateRequest => {
                            //need to understand this first
                        },
                        .ServerHelloDone => {
                            if (hs.@"1" > 0)
                                return error.ServerMalformedResponse;
                            clientHandshake.state = .ServerHelloDone;
                        },
                        else => {},
                    }

                    if (rec.@"3" == bytes_read) {
                        bytes_read = 0;
                        break;
                    }
                }
            },
            else => {},
        }
        if (clientHandshake.state == .ServerHelloDone)
            break;
    }

    try generateClientKeyAndExchange(clientHandshake, writer, hwriter);
    try clientChangeCipherSpec(clientHandshake, writer);
    try clientHandshakeFinished(clientHandshake, writer);

    try handleServerChangeCipherSpec(reader);
    try handleServerHandshakeFinish(clientHandshake, reader);

    // std.debug.print("\nServer Hello Done\n", .{});
}

pub fn init(allocator: std.mem.Allocator, stream: std.net.Stream, host: []const u8) !ClientHandshake {
    var cli = ClientHandshake{
        .stream = stream,
        .allocator = allocator,
        .hostname = host,
        .hashset = HashSet{
            .sha224 = Sha224.init(.{}),
            .sha256 = Sha256.init(.{}),
            .sha384 = Sha384.init(.{}),
            .sha512 = Sha512.init(.{}),
        },
    };
    try handShake(&cli);
    return cli;
}

pub fn deinit(clientHandshake: *ClientHandshake) void {
    // clientHandshake.handshakes.deinit();
    clientHandshake.allocator.free(clientHandshake.sig_bytes);
    clientHandshake.certificate_public_key.deinit(clientHandshake.allocator);
}

test "client" {
    const host = "flokidb.documents.azure.com";
    // const host =  "jsonplaceholder.typicode.com";

    const port: u16 = 443;
    const allocator = std.testing.allocator;

    var conn = try std.net.tcpConnectToHost(allocator, host, port);
    defer conn.close();

    var tlsconn = try ClientHandshake.init(allocator, conn, host);
    defer tlsconn.deinit();
}
