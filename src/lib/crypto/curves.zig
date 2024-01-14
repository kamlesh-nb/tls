const std = @import("std");
const crypto = @import("crypto.zig");

const Curves = @This();

pub const x25519 = struct {
    pub const name = "x25519";
    pub const tag = 0x001D;
    pub const pub_key_len = 32;
    pub const Keys = std.crypto.dh.X25519.KeyPair;

    inline fn makeKeyPair(rand: std.rand.Random) Keys {
        while (true) {
            var seed: [32]u8 = undefined;
            rand.bytes(&seed);
            return std.crypto.dh.X25519.KeyPair.create(seed) catch continue;
        } else unreachable;
    }

    inline fn makePreMasterSecret(
        key_pair: Keys,
        pre_master_secret_buf: []u8,
        server_public_key: *const [32]u8,
    ) ![]const u8 {
        pre_master_secret_buf[0..32].* = std.crypto.dh.X25519.scalarmult(
            key_pair.secret_key,
            server_public_key.*,
        ) catch return error.PreMasterGenerationFailed;
        return pre_master_secret_buf[0..32];
    }
};

pub const secp384r1 = struct {
    pub const name = "secp384r1";
    pub const tag = 0x0018;
    pub const pub_key_len = 97;
    pub const Keys = crypto.ecc.KeyPair(crypto.ecc.SECP384R1);

    inline fn makeKeyPair(rand: std.rand.Random) Keys {
        var seed: [48]u8 = undefined;
        rand.bytes(&seed);
        return crypto.ecc.make_key_pair(crypto.ecc.SECP384R1, seed);
    }

    inline fn makePreMasterSecret(
        key_pair: Keys,
        pre_master_secret_buf: []u8,
        server_public_key: *const [97]u8,
    ) ![]const u8 {
        pre_master_secret_buf[0..96].* = crypto.ecc.scalarmult(
            crypto.ecc.SECP384R1,
            server_public_key[1..].*,
            &key_pair.secret_key,
        ) catch return error.PreMasterGenerationFailed;
        return pre_master_secret_buf[0..48];
    }
};

pub const secp256r1 = struct {
    pub const name = "secp256r1";
    pub const tag = 0x0017;
    pub const pub_key_len = 65;
    pub const Keys = crypto.ecc.KeyPair(crypto.ecc.SECP256R1);

    inline fn makeKeyPair(rand: std.rand.Random) Keys {
        var seed: [32]u8 = undefined;
        rand.bytes(&seed);
        return crypto.ecc.make_key_pair(crypto.ecc.SECP256R1, seed);
    }

    inline fn makePreMasterSecret(
        key_pair: Keys,
        pre_master_secret_buf: []u8,
        server_public_key: *const [65]u8,
    ) ![]const u8 {
        pre_master_secret_buf[0..64].* = crypto.ecc.scalarmult(
            crypto.ecc.SECP256R1,
            server_public_key[1..].*,
            &key_pair.secret_key,
        ) catch return error.PreMasterGenerationFailed;
        return pre_master_secret_buf[0..32];
    }
};

// pub const all: [3]type = [3]type{ x25519, secp384r1, secp256r1 };
pub const all = &[_]type{ x25519, secp384r1, secp256r1 };

pub fn maxPubKeyLen(comptime list: anytype) usize {
    var max: usize = 0;
    for (list) |curve| {
        if (curve.pub_key_len > max)
            max = curve.pub_key_len;
    }
    return max;
}

pub fn maxPreMasterSecretLen(comptime list: anytype) usize {
    var max: usize = 0;
    for (list) |curve| {
        const curr = @typeInfo(std.meta.fieldInfo(curve.Keys, .public_key).type).Array.len;
        if (curr > max)
            max = curr;
    }
    return max;
}

pub fn KeyPair(comptime list: anytype) type {
    var fields: [list.len]std.builtin.Type.UnionField = undefined;
    for (list, 0..) |curve, i| {
        fields[i] = .{
            .name = curve.name,
            .type = curve.Keys,
            .alignment = @alignOf(curve.Keys),
        };
    }
    return @Type(.{
        .Union = .{
            .layout = .Auto,
            .tag_type = null,
            .fields = &fields,
            .decls = &[0]std.builtin.Type.Declaration{},
        },
    });
}

pub inline fn makeKeyPair(comptime list: anytype, curve_id: u16, rand: std.rand.Random) KeyPair(list) {
    inline for (list) |curve| {
        if (curve.tag == curve_id) {
            return @unionInit(KeyPair(list), curve.name, curve.makeKeyPair(rand));
        }
    }
    unreachable;
}

pub inline fn makePreMasterSecret(
    comptime list: anytype,
    curve_id: u16,
    key_pair: KeyPair(list),
    pre_master_secret_buf: *[maxPreMasterSecretLen(list)]u8,
    server_public_key: [maxPubKeyLen(list)]u8,
) ![]const u8 {
    inline for (list) |curve| {
        if (curve.tag == curve_id) {
            return try curve.makePreMasterSecret(
                @field(key_pair, curve.name),
                pre_master_secret_buf,
                server_public_key[0..curve.pub_key_len],
            );
        }
    }
    unreachable;
}
