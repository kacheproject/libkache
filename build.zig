const std = @import("std");
const autopkg = @import("autopkg/autopkg.zig");

pub fn package(name: []const u8, path: []const u8) autopkg.AutoPkgI {
    const sam3 = @import("sam3/build.zig");
    return autopkg.genExport(autopkg.AutoPkg{
        .name = name,
        .path = path,
        .rootSrc = "src/kache.zig",
        .dependencies = &.{
            autopkg.accept(sam3.package("sam3", "sam3")),
        },
        .linkLibC = true,
    });
}

pub fn build(b: *std.build.Builder) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    var mainPackage = autopkg.accept(package("kache", "."));
    var resolvedPackage = mainPackage.resolve(".", b.allocator) catch unreachable;
    defer resolvedPackage.deinit();
    const lib = resolvedPackage.addBuild(b);
    lib.setBuildMode(mode);
    lib.install();

    var main_tests = b.addTest("src/kache.zig");
    main_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);
}
