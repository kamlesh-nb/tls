const std = @import("std");
const mem = std.mem;
const tls = @import("crypto/tls.zig");
const int2 = tls.int2;

pub const RenegotiationInfo = struct {
    tag: u16 = 0xFF01,
    len: u16 = 0x0001,
    renegotiation_indication: u8 = 0x00,

};

pub const ServerName = struct {
    tag: u16 = 0x0000,
    len: u16 = 0,
    server_name_list_len: u16 = 0,
    server_name_type: u8 = 0,
    server_name_len: u16 = 0,
    data: []const u8 = undefined,
};

pub const MaxFragmentLength = struct {
    tag: u16 = 0x0001,
    len: u16 = 0,
    max_frag_len: u8 = 0,
};

pub const StatusRequest = struct {
    tag: u16 = 0x0005,
    len: u16 = 0,
    status_type: u8 = 0,
    responder_id_list_len: u16 = 0,
    request_extension_len: u16 = 0,
    request_extensions: []const u8 = undefined,
};

pub const ApplicationLayerProtocolNegotiation = struct {
    tag: u16 = 0x0010,
    len: u16 = 0,
    proto_list_len: u16 = 0,
    proto_name_len: u8 = 0,
    data: []const u8 = undefined,
};

pub const SignedCertTS = struct {
    tag: u16 = 0x0012,
    len: u8 = 0,
    data: []const u8 = undefined,
};

pub const EllipticCurveCryptography = struct {
    tag: u16 = 0x000a,
    len: u16 = 0,
    curves_len: u16 = 0,
    data: []const u8 = undefined,
};

pub const ECPointFormats = struct {
    tag: u16 = 0x000b,
    len: u16 = 0,
    point_formats_len: u8 = 0,
    data: []const u8 = undefined,
};

pub const SignatureAlgorithms = struct {
    tag: u16 = 0x000d,
    len: u16 = 0,
    suppported_algo_len: u16 = 0,
    data: []const u8 = undefined,
};

pub const Extensions = struct {
    server_name: ServerName = ServerName{},
    alpn: ApplicationLayerProtocolNegotiation = ApplicationLayerProtocolNegotiation{},
    ecc: EllipticCurveCryptography = EllipticCurveCryptography{},
    epf: ECPointFormats = ECPointFormats{},
    sigalgos: SignatureAlgorithms = SignatureAlgorithms{},
    sct: SignedCertTS = SignedCertTS{},
    reneginf: RenegotiationInfo = RenegotiationInfo{},
    pos: u16 = 0,
    buffer: [1024]u8 = [1]u8{0x00} ** 1024,

    pub fn encode(self: *Extensions, et: tls.ExtensionType, data: []const u8) void {
        switch (et) {
            .ServerName => {
                const _len: u16 = @intCast(data.len);
                self.server_name.len = _len + 5;
                self.server_name.server_name_list_len = _len + 3;
                self.server_name.server_name_len = _len;
                self.server_name.server_name_type = 0x00;
                self.server_name.data = data;
            },
            .ALPN => {
                const _len: u8 = @intCast(data.len);
                const alpn_bytes = 6 + _len + 1;
                self.alpn.len = @intCast(alpn_bytes - 4);
                self.alpn.proto_list_len = @intCast(alpn_bytes - 6);
                self.alpn.proto_name_len = _len;
                self.alpn.data = data;
            },
            .EllipticCurves => {
                const _len: u16 = @intCast(data.len);
                self.ecc.len = _len + 2;
                self.ecc.curves_len = _len;
                self.ecc.data = data;
            },
            .EcPointFormats => {
                self.epf.len = 0x0002;
                self.epf.point_formats_len = 0x01;
                self.epf.data = data;
            },
            .SignatureAlgorithms => {
                const _len: u16 = @intCast(data.len);
                self.sigalgos.len = _len + 2;
                self.sigalgos.suppported_algo_len = _len;
                self.sigalgos.data = data;
            },
            .SCT => {
                self.sct.len = data[0];
                self.sct.data = data[1..];
            },
            .RenegotiationInfo => {
                std.log.info("Pre-encoded", .{});
            },
            else => {
                std.log.err("Extension not supported yet", .{});
            },
        }
    }

    pub fn decode(self: *Extensions, reader: anytype) !void {
        const ext_len = try reader.readInt(u16, .big);
        var ext_read: u16 = 2;
        while (ext_read < ext_len) {
            const tag: u16 = try reader.readInt(u16, .big);
            const ext_tag: tls.ExtensionType = @enumFromInt(tag);
            switch (ext_tag) {
                .RenegotiationInfo => {
                    ext_read += 5;
                    self.reneginf.len = try reader.readInt(u16, .big);
                    self.reneginf.renegotiation_indication = try reader.readByte();
                },
                .ALPN => {
                    ext_read += 15;
                    self.alpn.len = try reader.readInt(u16, .big);
                    self.alpn.proto_list_len = try reader.readInt(u16, .big);
                    self.alpn.proto_name_len = try reader.readInt(u8, .big);
                    var _alpn: [16]u8 = undefined;
                    _ = try reader.readAtLeast(_alpn[0..self.alpn.proto_name_len], self.alpn.proto_name_len);
                    self.alpn.data = _alpn[0..self.alpn.proto_name_len];
                },
                .ServerName => {
                    self.server_name.len = try reader.readInt(u16, .big);
                    ext_read += 2;
                    var _sni: [256]u8 = undefined;

                    if (self.server_name.len > 0) {
                        _ = try reader.readAtLeast(_sni[0..self.server_name.len], self.server_name.len);
                        self.server_name.data = _sni[0..self.server_name.len];
                    }
                },
                .EcPointFormats => {
                    ext_read += 6;
                    self.epf.len = try reader.readInt(u16, .big);
                    self.epf.point_formats_len = try reader.readByte();
                    const d = try reader.readByte();
                    self.epf.data = &[1]u8{d};
                },
                else => {},
            }
        }
    }
    
    pub fn bytes(self: *Extensions) void {
        tls.structToBytes(self.server_name, &self.buffer, &self.pos);
        tls.structToBytes(self.alpn, &self.buffer, &self.pos);
        tls.structToBytes(self.ecc, &self.buffer, &self.pos);
        tls.structToBytes(self.epf, &self.buffer, &self.pos);
        tls.structToBytes(self.sigalgos, &self.buffer, &self.pos);
        tls.structToBytes(self.sct, &self.buffer, &self.pos);
        tls.structToBytes(self.reneginf, &self.buffer, &self.pos);
    }

};

test "extensions" {
    var ext = Extensions{};

    ext.encode(.ServerName, "flokidb.documents.azure.com");
    ext.encode(.ALPN, "http/1.1");
    ext.encode(.EllipticCurves, &tls.erray(tls.NamedGroups, &.{
        .x25519,
        .secp384r1,
        .secp256r1,
    }));
    ext.encode(.SignatureAlgorithms, &tls.erray(tls.SignatureAlgorithm, &.{
        .rsa_pkcs1_sha256,
        .rsa_pkcs1_sha384,
        .rsa_pkcs1_sha512,
    }));
    ext.encode(.EcPointFormats, &[1]u8{0x00});
    ext.encode(.SCT, &[2]u8{ 0x01, 0x00 });
    ext.bytes();

    std.debug.print("\nBytes: {any}, \nPos: {d}\n", .{ ext.buffer[0..ext.pos], ext.pos });
}
