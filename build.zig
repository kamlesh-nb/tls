const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    _ = b.addModule("tls", .{
        .root_source_file = .{ .path = "src/main.zig" },
    });

    const lib = b.addStaticLibrary(.{
        .name = "tls",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });

    b.installArtifact(lib);
}
