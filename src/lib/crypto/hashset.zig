const std = @import("std");

const Sha224 = std.crypto.hash.sha2.Sha224;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Sha512 = std.crypto.hash.sha2.Sha512;
const Sha256 = std.crypto.hash.sha2.Sha256;

const HashSet = @This();

sha224: Sha224,
sha256: Sha256,
sha384: Sha384,
sha512: Sha512,

pub fn update(self: *@This(), buf: []const u8) void {
    self.sha224.update(buf);
    self.sha256.update(buf);
    self.sha384.update(buf);
    self.sha512.update(buf);
}
fn HashingReader(comptime Reader: anytype) type {
    const State = struct {
        hash_set: *HashSet,
        reader: Reader,
    };
    const S = struct {
        pub fn read(state: State, buffer: []u8) Reader.Error!usize {
            const amt = try state.reader.read(buffer);
            if (amt != 0) {
                state.hash_set.update(buffer[0..amt]);
            }
            return amt;
        }
    };
    return std.io.Reader(State, Reader.Error, S.read);
}

pub fn makeHashingReader(hash_set: *HashSet, reader: anytype) HashingReader(@TypeOf(reader)) {
    return .{ .context = .{ .hash_set = hash_set, .reader = reader } };
}

fn HashingWriter(comptime Writer: anytype) type {
    const State = struct {
        hash_set: *HashSet,
        writer: Writer,
    };
    const S = struct {
        pub fn write(state: State, buffer: []const u8) Writer.Error!usize {
            const amt = try state.writer.write(buffer);
            if (amt != 0) {
                state.hash_set.update(buffer[0..amt]);
            }
            return amt;
        }
    };
    return std.io.Writer(State, Writer.Error, S.write);
}

pub fn makeHashingWriter(hash_set: *HashSet, writer: anytype) HashingWriter(@TypeOf(writer)) {
    return .{ .context = .{ .hash_set = hash_set, .writer = writer } };
}

pub fn get(comptime Reader: anytype) type {
    return HashingReader(Reader);
}
