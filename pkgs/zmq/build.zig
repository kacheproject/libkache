const std = @import("std");
const autopkg = @import("autopkg/autopkg.zig");

pub fn package(name: []const u8, path: []const u8) autopkg.AutoPkgI {
    return autopkg.genExport(.{
        .name = name,
        .path = path,
        .rootSrc = "zmq.zig",
        .linkLibC = true,
        .linkSystemLibs = &.{"libzmq"},
    });
}

pub fn build(b: *std.build.Builder) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{});

    var mainPackage = autopkg.accept(package("zmq", "."));
    defer mainPackage.deinit();
    var resolvedPackage = mainPackage.resolve(".", b.allocator) catch unreachable;
    defer resolvedPackage.deinit();

    const lib = resolvedPackage.addBuild(b);
    lib.setBuildMode(mode);
    lib.install();

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(resolvedPackage.addTest(b, mode, &target));
}
