const std = @import("std");

pub const RecordHeader = struct {
    data: [5]u8,

    pub inline fn tag(self: @This()) u8 {
        return self.data[0];
    }

    pub inline fn len(self: @This()) u16 {
        return std.mem.readInt(u16, self.data[3..], .big);
    }
};

pub fn readRecordHeader(reader: anytype) !RecordHeader {
    var header: [5]u8 = undefined;
    try reader.readNoEof(&header);

    if (!std.mem.eql(u8, header[1..3], "\x03\x03") and !std.mem.eql(u8, header[1..3], "\x03\x01"))
        return error.ServerInvalidVersion;

    return RecordHeader{
        .data = header,
    };
}
