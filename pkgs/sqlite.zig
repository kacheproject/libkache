const autopkg = @import("autopkg/autopkg.zig");

pub fn package(name: []const u8, path: []const u8) autopkg.AutoPkgI {
    return autopkg.genExport(autopkg.AutoPkg {
        .name = name,
        .path = path,
        .rootSrc = "sqlite.zig",
        .cSrcFiles = &.{"./c/sqlite3.c"},
        .ccflags = &.{"-std=c99", "-g"},
        .linkLibC = true,
    });
}
