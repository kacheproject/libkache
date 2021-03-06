const std = @import("std");
const autopkg = @import("autopkg/autopkg.zig");

pub fn package(name: []const u8, path: []const u8) autopkg.AutoPkgI {
    return selfPackage(name, path, true);
}

fn selfPackage(name: []const u8, path: []const u8, skipTest: bool) autopkg.AutoPkgI {
    const sqlite = @import("pkgs/sqlite/build.zig");
    return autopkg.genExport(autopkg.AutoPkg{
        .name = name,
        .path = path,
        .rootSrc = "kache.zig",
        .dependencies = &.{
            autopkg.accept(sqlite.package("sqlite", "pkgs/sqlite", .{
                .useBundledSQLite = true,
            })),
        },
        .linkLibC = true,
        .doNotTest = skipTest,
        .testSrcs = &.{
            "wg.zig",
        },
        .linkSystemLibs = &.{
            "sodium",
        },
    });
}

pub fn build(b: *std.build.Builder) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{});

    var mainPackage = autopkg.accept(selfPackage("kache", ".", false));
    defer mainPackage.deinit();
    var resolvedPackage = mainPackage.resolve(".", b.allocator) catch unreachable;

    const lib = resolvedPackage.addBuild(b);
    lib.setBuildMode(mode);
    lib.install();

    var packages_tests = resolvedPackage.addTest(b, mode, &target);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(packages_tests);
}
