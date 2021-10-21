const std = @import("std");
const sam3 = @import("sam3");
const sqlite = @import("sqlite");

pub const profile = @import("./profile.zig");

test "Profile" {
    const _t = std.testing;
    var db = try sqlite.Db.init(.{
        .mode = .Memory,
        .open_flags = .{
            .write = true,
            .create = true,
        }
    });
    defer db.deinit();
    var person = profile.Profile.init(&db, _t.allocator);
    defer person.deinit();
}

pub const Kache = struct {
    user: *profile.Profile,
};
