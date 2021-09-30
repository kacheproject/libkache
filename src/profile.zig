/// Zig
const std = @import("std");
const sqlite = @import("sqlite");

const Allocator = std.mem.Allocator;

const Error = error{
    Unknown,
    KVFailed,
} || Allocator.Error;

const SqliteKV = struct {
    db: *sqlite.Db,
    name: []const u8,
    alloc: *Allocator,

    const Self = @This();

    pub fn init(db: *sqlite.Db, name: []const u8, alloc: *Allocator) Self {
        return Self{
            .db = db,
            .name = name,
            .alloc = alloc,
        };
    }

    pub fn ensure(self: *Self) Allocator.Error!void {
        const query = std.fmt.allocPrintZ(
            self.alloc,
            "CREATE TABLE IF NOT EXISTS {s} (id INTEGER PRIMARY KEY, key TEXT, value TEXT, created_at INTEGER);",
            .{self.name}) catch |e| switch (e) {
            std.fmt.AllocPrintError.OutOfMemory => return @errSetCast(Allocator.Error, e),
            else => unreachable,
        };
        defer self.alloc.free(query);
        var s = self.db.prepareDynamic(query) catch unreachable;
        defer s.deinit();
        s.exec(.{}, .{}) catch unreachable;
    }

    pub fn get(self: *Self, k: []const u8) Allocator.Error!?[]const u8 {
        return self.getAlloc(k, self.alloc);
    }

    pub fn free(self: *Self, val: anytype) void {
        self.alloc.free(val);
    }

    pub fn getAlloc(self: *Self, k: []const u8, alloc: *Allocator) Allocator.Error!?[]const u8 {
        const query = std.fmt.allocPrintZ(
            self.alloc,
            "SELECT value FROM {s} WHERE key = $key ORDER BY created_at DESC, id DESC LIMIT 1;",
            .{self.name}) catch |e| switch (e) {
            error.OutOfMemory => return @errSetCast(Allocator.Error, e),
            else => unreachable,
        };
        defer self.free(query);
        var s = self.db.prepareDynamic(query) catch unreachable;
        defer s.deinit();
        var row = s.oneAlloc([]const u8, alloc, .{}, .{ .key = k }) catch unreachable;
        return row;
    }

    pub fn set(self: *Self, k: []const u8, v: []const u8) Allocator.Error!void {
        const query = std.fmt.allocPrintZ(
            self.alloc,
            "INSERT INTO {s} (key, value, created_at) VALUES ($key, $val, strftime('%s', 'now'));",
            .{self.name},
        ) catch |e| switch (e) {
            error.OutOfMemory => return @errSetCast(Allocator.Error, e),
            else => unreachable,
        };
        defer self.free(query);
        var s = self.db.prepareDynamic(query) catch unreachable;
        defer s.deinit();
        s.exec(.{}, .{
            .key = k,
            .val = v,
        }) catch unreachable;
    }
};

test "SqliteKV can get and set value" {
    const _t = std.testing;
    var db = try sqlite.Db.init(.{
        .mode = .Memory,
        .open_flags = .{
            .write = true,
            .create = true,
        },
    });
    var kv = SqliteKV.init(&db, "test_table", _t.allocator);
    try kv.ensure();
    try kv.set("test", "beautiful");
    const val = (try kv.get("test")).?;
    defer kv.free(val);
    try _t.expectEqualStrings("beautiful", val);
}

test "SqliteKV return the latest value when the key set multiple times" {
    const _t = std.testing;
    var db = try sqlite.Db.init(.{
        .mode = .Memory,
        .open_flags = .{
            .write = true,
            .create = true,
        },
    });
    var kv = SqliteKV.init(&db, "test_table", _t.allocator);
    try kv.ensure();
    try kv.set("test", "value0");
    try kv.set("test", "value1");
    const value = (try kv.get("test")).?;
    defer kv.free(value);
    try _t.expectEqualStrings("value1", value);
}

pub const Profile = struct {
    db: *sqlite.Db,
    usrlets: SqliteKV([]const u8),
    syslets: SqliteKV([]const u8),
    alloc: *Allocator,
};
