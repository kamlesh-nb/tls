const std = @import("std");
const Allocator = std.mem.Allocator;
const H = @import("hashset.zig");
const x509 = @import("x509.zig");
const asn1 = @import("asn1.zig");
const @"pcks1v1.5" = @import("pcks1-1_5.zig");

const CertUtil = @This();


const ServerCertificate = struct {
    bytes: []const u8,
    dn: []const u8,
    common_name: []const u8,
    raw_subject_alternative_name: []const u8,
    public_key: x509.PublicKey,
    signature: asn1.BitString,
    signature_algorithm: x509.Certificate.SignatureAlgorithm,
    is_ca: bool,

    const GeneralName = enum(u5) {
        other_name = 0,
        rfc822_name = 1,
        dns_name = 2,
        x400_address = 3,
        directory_name = 4,
        edi_party_name = 5,
        uniform_resource_identifier = 6,
        ip_address = 7,
        registered_id = 8,
    };

    fn iterSAN(self: ServerCertificate, choice: GeneralName) NameIterator {
        return .{ .cert = self, .choice = choice };
    }

    const NameIterator = struct {
        cert: ServerCertificate,
        choice: GeneralName,
        pos: usize = 0,

        fn next(self: *NameIterator) ?[]const u8 {
            while (self.pos < self.cert.raw_subject_alternative_name.len) {
                const choice = self.cert.raw_subject_alternative_name[self.pos];
                std.debug.assert(choice >= 0x80);
                const len = self.cert.raw_subject_alternative_name[self.pos + 1];
                const start = self.pos + 2;
                const end = start + len;
                self.pos = end;
                if (@intFromEnum(self.choice) == choice - 0x80) {
                    return self.cert.raw_subject_alternative_name[start..end];
                }
            }
            return null;
        }
    };
};

const VerifierCaptureState = struct {
    list: std.ArrayListUnmanaged(ServerCertificate),
    allocator: Allocator,
    // Used in `add_server_cert` to avoid an extra allocation
    fbs: *std.io.FixedBufferStream([]const u8),
};

pub fn CertificateReaderState(comptime Reader: type) type {
    return struct {
        reader: Reader,
        length: usize,
        idx: usize = 0,
    };
}

pub fn CertificateReader(comptime Reader: type) type {
    const S = struct {
        pub fn read(state: *CertificateReaderState(Reader), buffer: []u8) Reader.Error!usize {
            const out_bytes = @min(buffer.len, state.length - state.idx);
            const res = try state.reader.readAll(buffer[0..out_bytes]);
            state.idx += res;
            return res;
        }
    };

    return std.io.Reader(*CertificateReaderState(Reader), Reader.Error, S.read);
}

pub const CertificateVerifier = union(enum) {
    none,
    function: ?*const anyopaque,
    default,
};

pub fn CertificateVerifierReader(comptime Reader: type) type {
    return CertificateReader(H.get(Reader));
}

pub fn extractCertPublicKey(allocator: Allocator, reader: anytype, length: usize) !x509.PublicKey {
    const CaptureState = struct {
        pub_key: x509.PublicKey,
        allocator: Allocator,
    };
    var capture_state = CaptureState{
        .pub_key = undefined,
        .allocator = allocator,
    };

    const schema = .{
        .sequence, .{
            // tbsCertificate
            .{
                .sequence,
                .{
                    .{ .context_specific, 0 }, // version
                    .{.int}, // serialNumber
                    .{.sequence}, // signature
                    .{.sequence}, // issuer
                    .{.sequence}, // validity
                    .{.sequence}, // subject
                    .{ .capture, 0, .sequence }, // subjectPublicKeyInfo
                    .{ .optional, .context_specific, 1 }, // issuerUniqueID
                    .{ .optional, .context_specific, 2 }, // subjectUniqueID
                    .{ .optional, .context_specific, 3 }, // extensions
                },
            },
            // signatureAlgorithm
            .{.sequence},
            // signatureValue
            .{.bit_string},
        },
    };
    const captures = .{
        &capture_state, struct {
            fn f(state: *CaptureState, tag: u8, _length: usize, subreader: anytype) !void {
                _ = tag;
                _ = _length;
                state.pub_key = x509.parse_public_key(state.allocator, subreader) catch |err| switch (err) {
                    error.MalformedDER => return error.ServerMalformedResponse,
                    else => |e| return e,
                };
            }
        }.f,
    };

    const cert_length = try reader.readInt(u24, .big);
    asn1.der.parse_schema(schema, captures, reader) catch |err| switch (err) {
        error.InvalidLength,
        error.InvalidTag,
        error.InvalidContainerLength,
        error.DoesNotMatchSchema,
        => return error.ServerMalformedResponse,
        else => |e| return e,
    };
    errdefer capture_state.pub_key.deinit(allocator);

    try reader.skipBytes(length - cert_length - 3, .{});
    return capture_state.pub_key;
}

fn unixTimeStampFromCivilDate(year: u16, month: u8, day: u8) i64 {
    var y: i64 = year;
    if (month <= 2) y -= 1;
    const era = @divTrunc(y, 400);
    const yoe = y - era * 400; // [0, 399]
    const doy = @divTrunc((153 * (month + (if (month > 2) @as(i64, -3) else 9)) + 2), 5) + day - 1; // [0, 365]
    const doe = yoe * 365 + @divTrunc(yoe, 4) - @divTrunc(yoe, 100) + doy; // [0, 146096]
    return (era * 146097 + doe - 719468) * 86400;
}

fn readDerUTCTimeStamp(reader: anytype) !i64 {
    var buf: [17]u8 = undefined;

    const tag = try reader.readByte();
    if (tag != 0x17)
        return error.CertificateVerificationFailed;
    const len = try asn1.der.parse_length(reader);
    if (len > 17)
        return error.CertificateVerificationFailed;

    try reader.readNoEof(buf[0..len]);
    const year = std.fmt.parseUnsigned(u16, buf[0..2], 10) catch
        return error.CertificateVerificationFailed;
    const month = std.fmt.parseUnsigned(u8, buf[2..4], 10) catch
        return error.CertificateVerificationFailed;
    const day = std.fmt.parseUnsigned(u8, buf[4..6], 10) catch
        return error.CertificateVerificationFailed;

    var time = unixTimeStampFromCivilDate(2000 + year, month, day);
    time += (std.fmt.parseUnsigned(i64, buf[6..8], 10) catch
        return error.CertificateVerificationFailed) * 3600;
    time += (std.fmt.parseUnsigned(i64, buf[8..10], 10) catch
        return error.CertificateVerificationFailed) * 60;

    if (buf[len - 1] == 'Z') {
        if (len == 13) {
            time += std.fmt.parseUnsigned(u8, buf[10..12], 10) catch
                return error.CertificateVerificationFailed;
        } else if (len != 11) {
            return error.CertificateVerificationFailed;
        }
    } else {
        if (len == 15) {
            if (buf[10] != '+' and buf[10] != '-')
                return error.CertificateVerificationFailed;

            var additional = (std.fmt.parseUnsigned(i64, buf[11..13], 10) catch
                return error.CertificateVerificationFailed) * 3600;
            additional += (std.fmt.parseUnsigned(i64, buf[13..15], 10) catch
                return error.CertificateVerificationFailed) * 60;

            time += if (buf[10] == '+') -additional else additional;
        } else if (len == 17) {
            if (buf[12] != '+' and buf[12] != '-')
                return error.CertificateVerificationFailed;
            time += std.fmt.parseUnsigned(u8, buf[10..12], 10) catch
                return error.CertificateVerificationFailed;

            var additional = (std.fmt.parseUnsigned(i64, buf[13..15], 10) catch
                return error.CertificateVerificationFailed) * 3600;
            additional += (std.fmt.parseUnsigned(i64, buf[15..17], 10) catch
                return error.CertificateVerificationFailed) * 60;

            time += if (buf[12] == '+') -additional else additional;
        } else return error.CertificateVerificationFailed;
    }
    return time;
}

fn checkCertTimeStamp(time: i64, tag_byte: u8, length: usize, reader: anytype) !void {
    _ = tag_byte;
    _ = length;
    if (time < (try readDerUTCTimeStamp(reader)))
        return error.CertificateVerificationFailed;
    if (time > (try readDerUTCTimeStamp(reader)))
        return error.CertificateVerificationFailed;
}

fn addDNField(state: *VerifierCaptureState, tag: u8, length: usize, reader: anytype) !void {
    _ = length;
    _ = tag;

    const seq_tag = try reader.readByte();
    if (seq_tag != 0x30)
        return error.CertificateVerificationFailed;
    const seq_length = try asn1.der.parse_length(reader);
    _ = seq_length;

    const oid_tag = try reader.readByte();
    if (oid_tag != 0x06)
        return error.CertificateVerificationFailed;

    const oid_length = try asn1.der.parse_length(reader);
    if (oid_length == 3 and (try reader.isBytes("\x55\x04\x03"))) {
        // Common name
        const common_name_tag = try reader.readByte();
        if (common_name_tag != 0x04 and common_name_tag != 0x0c and common_name_tag != 0x13 and common_name_tag != 0x16)
            return error.CertificateVerificationFailed;
        const common_name_len = try asn1.der.parse_length(reader);
        state.list.items[state.list.items.len - 1].common_name = state.fbs.buffer[state.fbs.pos .. state.fbs.pos + common_name_len];
    }
}

fn addCertSubjectDN(state: *VerifierCaptureState, tag: u8, length: usize, reader: anytype) !void {
    state.list.items[state.list.items.len - 1].dn = state.fbs.buffer[state.fbs.pos .. state.fbs.pos + length];
    const schema = .{
        .sequence_of,
        .{
            .capture, 0, .set,
        },
    };
    const captures = .{
        state, addDNField,
    };
    try asn1.der.parse_schema_tag_len(tag, length, schema, captures, reader);
}

fn addCertPublicKey(state: *VerifierCaptureState, tag: u8, length: usize, reader: anytype) !void {
    _ = tag;
    _ = length;

    state.list.items[state.list.items.len - 1].public_key = x509.parse_public_key(
        state.allocator,
        reader,
    ) catch |err| switch (err) {
        error.MalformedDER => return error.CertificateVerificationFailed,
        else => |e| return e,
    };
}

fn addCertExtensions(state: *VerifierCaptureState, tag: u8, length: usize, reader: anytype) !void {
    _ = tag;
    _ = length;

    const schema = .{
        .sequence_of,
        .{ .capture, 0, .sequence },
    };
    const captures = .{
        state, addCertExtension,
    };

    try asn1.der.parse_schema(schema, captures, reader);
}

fn addCertExtension(state: *VerifierCaptureState, tag: u8, length: usize, reader: anytype) !void {
    _ = tag;

    const start = state.fbs.pos;

    // The happy path is allocation free
    // TODO: add a preflight check to mandate a specific tag
    const object_id = try asn1.der.parse_value(state.allocator, reader);
    defer object_id.deinit(state.allocator);
    if (object_id != .object_identifier) return error.DoesNotMatchSchema;
    if (object_id.object_identifier.len != 4)
        return;

    const data = object_id.object_identifier.data;
    // Prefix == id-ce
    if (data[0] != 2 or data[1] != 5 or data[2] != 29)
        return;

    switch (data[3]) {
        17 => {
            const san_tag = try reader.readByte();
            if (san_tag != @intFromEnum(asn1.Tag.octet_string)) return error.DoesNotMatchSchema;

            const san_length = try asn1.der.parse_length(reader);
            _ = san_length;

            const body_tag = try reader.readByte();
            if (body_tag != @intFromEnum(asn1.Tag.sequence)) return error.DoesNotMatchSchema;

            const body_length = try asn1.der.parse_length(reader);
            const total_read = state.fbs.pos - start;
            if (total_read + body_length > length) return error.DoesNotMatchSchema;

            state.list.items[state.list.items.len - 1].raw_subject_alternative_name = state.fbs.buffer[state.fbs.pos .. state.fbs.pos + body_length];

            // Validate to make sure this is iterable later
            const ref = state.fbs.pos;
            while (state.fbs.pos - ref < body_length) {
                const choice = try reader.readByte();
                if (choice < 0x80) return error.DoesNotMatchSchema;

                const chunk_length = try asn1.der.parse_length(reader);
                _ = try reader.skipBytes(chunk_length, .{});
            }
        },
        else => {},
    }
}

fn addServerCert(state: *VerifierCaptureState, tag_byte: u8, length: usize, reader: anytype) !void {
    const is_ca = state.list.items.len != 0;

    // TODO: Some way to get tag + length buffer directly in the capture callback?
    const encoded_length = asn1.der.encode_length(length).slice();
    // This is not errdefered since default_cert_verifier call takes care of cleaning up all the certificate data.
    // Same for the signature.data
    const cert_bytes = try state.allocator.alloc(u8, length + 1 + encoded_length.len);
    cert_bytes[0] = tag_byte;
    std.mem.copy(u8, cert_bytes[1 .. 1 + encoded_length.len], encoded_length);

    try reader.readNoEof(cert_bytes[1 + encoded_length.len ..]);
    (try state.list.addOne(state.allocator)).* = .{
        .is_ca = is_ca,
        .bytes = cert_bytes,
        .dn = undefined,
        .common_name = &[0]u8{},
        .raw_subject_alternative_name = &[0]u8{},
        .public_key = x509.PublicKey.empty,
        .signature = asn1.BitString{ .data = &[0]u8{}, .bit_len = 0 },
        .signature_algorithm = undefined,
    };

    const schema = .{
        .sequence,
        .{
            .{ .context_specific, 0 }, // version
            .{.int}, // serialNumber
            .{.sequence}, // signature
            .{.sequence}, // issuer
            .{ .capture, 0, .sequence }, // validity
            .{ .capture, 1, .sequence }, // subject
            .{ .capture, 2, .sequence }, // subjectPublicKeyInfo
            .{ .optional, .context_specific, 1 }, // issuerUniqueID
            .{ .optional, .context_specific, 2 }, // subjectUniqueID
            .{ .capture, 3, .optional, .context_specific, 3 }, // extensions
        },
    };

    const captures = .{
        std.time.timestamp(), checkCertTimeStamp,
        state,                addCertSubjectDN,
        state,                addCertPublicKey,
        state,                addCertExtensions,
    };

    var fbs = std.io.fixedBufferStream(@as([]const u8, cert_bytes[1 + encoded_length.len ..]));
    state.fbs = &fbs;

    asn1.der.parse_schema_tag_len(tag_byte, length, schema, captures, fbs.reader()) catch |err| switch (err) {
        error.InvalidLength,
        error.InvalidTag,
        error.InvalidContainerLength,
        error.DoesNotMatchSchema,
        => return error.CertificateVerificationFailed,
        else => |e| return e,
    };
}

fn setSignatureAlgorithm(state: *VerifierCaptureState, tag: u8, length: usize, reader: anytype) !void {
    _ = tag;
    _ = length;

    const cert = &state.list.items[state.list.items.len - 1];
    cert.signature_algorithm = (try x509.get_signature_algorithm(reader)) orelse return error.CertificateVerificationFailed;
}

fn setSignatureValue(state: *VerifierCaptureState, tag: u8, length: usize, reader: anytype) !void {
    _ = tag;

    const unused_bits = try reader.readByte();
    const bit_count = (length - 1) * 8 - unused_bits;
    const signature_bytes = try state.allocator.alloc(u8, length - 1);
    errdefer state.allocator.free(signature_bytes);
    try reader.readNoEof(signature_bytes);
    state.list.items[state.list.items.len - 1].signature = .{
        .data = signature_bytes,
        .bit_len = bit_count,
    };
}

const ReverseSplitIterator = struct {
    buffer: []const u8,
    index: ?usize,
    delimiter: []const u8,

    pub fn next(self: *ReverseSplitIterator) ?[]const u8 {
        const end = self.index orelse return null;
        const start = if (std.mem.lastIndexOfLinear(u8, self.buffer[0..end], self.delimiter)) |delim_start| blk: {
            self.index = delim_start;
            break :blk delim_start + self.delimiter.len;
        } else blk: {
            self.index = null;
            break :blk 0;
        };
        return self.buffer[start..end];
    }
};

fn reverseSplit(buffer: []const u8, delimiter: []const u8) ReverseSplitIterator {
    std.debug.assert(delimiter.len != 0);
    return .{
        .index = buffer.len,
        .buffer = buffer,
        .delimiter = delimiter,
    };
}

fn certNameMatches(cert_name: []const u8, hostname: []const u8) bool {
    var cert_name_split = reverseSplit(cert_name, ".");
    var hostname_split = reverseSplit(hostname, ".");
    while (true) {
        const cn_part = cert_name_split.next();
        const hn_part = hostname_split.next();

        if (cn_part) |cnp| {
            if (hn_part == null and cert_name_split.index == null and std.mem.eql(u8, cnp, "www"))
                return true
            else if (hn_part) |hnp| {
                if (std.mem.eql(u8, cnp, "*"))
                    continue;
                if (!std.mem.eql(u8, cnp, hnp))
                    return false;
            }
        } else return hn_part == null;
    }
}

pub fn defaultCertVerifier(
    allocator: Allocator,
    reader: anytype,
    certs_bytes: usize,
    trusted_certificates: []const x509.Certificate,
    hostname: []const u8,
) !x509.PublicKey {
    var capture_state = VerifierCaptureState{
        .list = try std.ArrayListUnmanaged(ServerCertificate).initCapacity(allocator, 3),
        .allocator = allocator,
        .fbs = undefined,
    };
    defer {
        for (capture_state.list.items) |cert| {
            cert.public_key.deinit(allocator);
            allocator.free(cert.bytes);
            allocator.free(cert.signature.data);
        }
        capture_state.list.deinit(allocator);
    }

    const schema = .{
        .sequence, .{
            // tbsCertificate
            .{ .capture, 0, .sequence },
            // signatureAlgorithm
            .{ .capture, 1, .sequence },
            // signatureValue
            .{ .capture, 2, .bit_string },
        },
    };
    const captures = .{
        &capture_state, addServerCert,
        &capture_state, setSignatureAlgorithm,
        &capture_state, setSignatureValue,
    };

    var bytes_read: u24 = 0;
    while (bytes_read < certs_bytes) {
        const cert_length = try reader.readInt(u24, .big);

        asn1.der.parse_schema(schema, captures, reader) catch |err| switch (err) {
            error.InvalidLength,
            error.InvalidTag,
            error.InvalidContainerLength,
            error.DoesNotMatchSchema,
            => return error.CertificateVerificationFailed,
            else => |e| return e,
        };

        bytes_read += 3 + cert_length;
    }
    if (bytes_read != certs_bytes)
        return error.CertificateVerificationFailed;

    const chain = capture_state.list.items;
    if (chain.len == 0) return error.CertificateVerificationFailed;
    // Check if the hostname matches one of the leaf certificate's names
    name_matched: {
        if (certNameMatches(chain[0].common_name, hostname)) {
            break :name_matched;
        }

        var iter = chain[0].iterSAN(.dns_name);
        while (iter.next()) |cert_name| {
            if (certNameMatches(cert_name, hostname)) {
                break :name_matched;
            }
        }

        return error.CertificateVerificationFailed;
    }

    var i: usize = 0;
    while (i < chain.len - 1) : (i += 1) {
        if (!try @"pcks1v1.5".certificate_verify_signature(
            allocator,
            chain[i].signature_algorithm,
            chain[i].signature,
            chain[i].bytes,
            chain[i + 1].public_key,
        )) {
            return error.CertificateVerificationFailed;
        }
    }

    for (chain) |cert| {
        for (trusted_certificates) |trusted| {
            // Try to find an exact match to a trusted certificate
            if (cert.is_ca == trusted.is_ca and std.mem.eql(u8, cert.dn, trusted.dn) and
                cert.public_key.eql(trusted.public_key))
            {
                const key = chain[0].public_key;
                chain[0].public_key = x509.PublicKey.empty;
                return key;
            }

            if (!trusted.is_ca)
                continue;

            if (try @"pcks1v1.5".certificate_verify_signature(
                allocator,
                cert.signature_algorithm,
                cert.signature,
                cert.bytes,
                trusted.public_key,
            )) {
                const key = chain[0].public_key;
                chain[0].public_key = x509.PublicKey.empty;
                return key;
            }
        }
    }
    return error.CertificateVerificationFailed;
}


