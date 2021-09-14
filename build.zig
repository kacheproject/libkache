const std = @import("std");
const autopkg = @import("autopkg/autopkg.zig");

pub fn package(name: []const u8, path: []const u8) autopkg.AutoPkgI {
    var sam3 = @import("sam3/build.zig").package("sam3", "sam3");
    var sqlite = @import("pkgs/sqlite.zig").package("sqlite", "pkgs/sqlite");
    return autopkg.genExport(autopkg.AutoPkg{
        .name = name,
        .path = path,
        .rootSrc = "src/kache.zig",
        .dependencies = &.{
            autopkg.accept(sam3),
            autopkg.accept(sqlite),
        },
        .linkLibC = true,
    });
}

pub fn build(b: *std.build.Builder) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    var mainPackage = autopkg.accept(package("kache", "."));
    defer mainPackage.deinit();
    var resolvedPackage = mainPackage.resolve(".", b.allocator) catch unreachable;
    const lib = resolvedPackage.addBuild(b);
    lib.setBuildMode(mode);
    lib.install();

    var main_tests = b.addTest("src/kache.zig");
    main_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);
}
