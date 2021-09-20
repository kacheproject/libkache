const std = @import("std");
const Allocator = std.mem.Allocator;
const autopkg = @import("autopkg/autopkg.zig");



pub fn package(name: []const u8, dirPath: []const u8) autopkg.AutoPkgI {
    const strings = @import("strings/build.zig");
    return autopkg.genExport(autopkg.AutoPkg {
        .name = name,
        .path = dirPath,
        .rootSrc = "src/sam3.zig",
        .dependencies = &.{
            autopkg.accept(strings.package("strings", "strings")),
        },
        .linkLibC = true,
        .cSrcFiles = &.{"./libsam3/src/libsam3/libsam3.c"},
        .includeDirs = &.{"./libsam3/src/libsam3"},
        .ccflags = &.{"-Wall", "-g", "-std=gnu99"},
    });
}

pub fn build(b: *std.build.Builder) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{});

    const CCFLAGS = [_][]const u8{"-Wall", "-g", "-std=gnu99"};
    const LIBSAM3_INCLUDE = "./libsam3/src/libsam3/";
    const LIBSAM3_SRC = "./libsam3/src/libsam3/libsam3.c";

    var mainPackage = autopkg.accept(package("sam3", "."));
    defer mainPackage.deinit();
    var resolvedPackage = mainPackage.resolve(".", b.allocator) catch unreachable;
    
    const lib = resolvedPackage.addBuild(b);
    lib.setBuildMode(mode);
    lib.install();

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(resolvedPackage.addTest(b, mode, &target));
}