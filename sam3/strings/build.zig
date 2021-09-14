const std = @import("std");
const autopkg = @import("autopkg/autopkg.zig");

pub fn package(name: []const u8, dirPath: []const u8) autopkg.AutoPkgI {
    return autopkg.genExport(autopkg.AutoPkg {
        .name = name,
        .path = dirPath,
        .rootSrc = "strings.zig",
    });
}

pub fn build(b: *std.build.Builder) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const mainPackage = autopkg.accept(package("strings", "."));
    var resolvedPackage = mainPackage.resolve(".", b.allocator) catch unreachable;
    const lib = resolvedPackage.addBuild(b);
    lib.setBuildMode(mode);
    lib.install();

    var main_tests = b.addTest("strings.zig");
    main_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);
}