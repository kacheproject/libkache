/// Zig
const std = @import("std");
const sqlite = @import("pkgs/sqlite/sqlite.zig");
const kssid = @import("./kssid.zig");

const ArrayList = std.ArrayList;
const Allocator = std.mem.Allocator;

const Error = error{
    Unknown,
    InvalidVersion,
    ResourceExists,
} || Allocator.Error;

/// Key-value pair store on sqlite3.
/// 0-length strings will be seen as null.
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
        const query = std.fmt.allocPrintZ(self.alloc, "CREATE TABLE IF NOT EXISTS {s} (id INTEGER PRIMARY KEY, key TEXT, value TEXT, created_at INTEGER);", .{self.name}) catch |e| switch (e) {
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
        const query = std.fmt.allocPrintZ(self.alloc, "SELECT value FROM {s} WHERE key = $key ORDER BY created_at DESC, id DESC LIMIT 1;", .{self.name}) catch |e| switch (e) {
            error.OutOfMemory => return @errSetCast(Allocator.Error, e),
            else => unreachable,
        };
        defer self.free(query);
        var s = self.db.prepareDynamic(query) catch unreachable;
        defer s.deinit();
        var row = s.oneAlloc([]const u8, alloc, .{}, .{ .key = k }) catch unreachable;
        if (row) |r| {
            if (r.len != 0) {
                return r;
            } else {
                defer alloc.free(r);
                return null;
            }
        } else {
            return null;
        }
    }

    pub fn set(self: *Self, k: []const u8, v: ?[]const u8) Allocator.Error!void {
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

    pub fn setDetail(self: *Self, k: []const u8, v: ?[]const u8, created_at: u64) Allocator.Error!void {
        const query = std.fmt.allocPrintZ(
            self.alloc,
            "INSERT INTO {s} (key, value, created_at) VALUES ($key, $val, $created_at);",
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
            .created_at = created_at,
        }) catch unreachable;
    }

    pub fn exists(self: *Self) !bool {
        const query = "SELECT 1 FROM sqlite_master WHERE type=? AND name=?;";
        var s = try self.db.prepare(query);
        defer s.deinit();
        var value = try s.one(c_int, .{}, .{ self.name, self.name });
        if (value) |val| {
            return val == 1;
        } else {
            return false;
        }
    }

    pub fn keysAlloc(self: *Self, alloc: *Allocator) !ArrayList([]const u8) {
        const query = std.fmt.allocPrintZ(
            self.alloc,
            "SELECT DISTINCT key FROM {s} ORDER BY created_at ASC, id ASC;",
            .{self.name},
        ) catch |e| switch (e) {
            error.OutOfMemory => return @errSetCast(Allocator.Error, e),
            else => unreachable,
        };
        defer self.free(query);
        var s = try self.db.prepareDynamic(query);
        defer s.deinit();
        var value = try s.all([]const u8, alloc, .{}, .{});
        return ArrayList([]const u8).fromOwnedSlice(alloc, value);
    }

    pub fn keys(self: *Self) !ArrayList([]const u8) {
        return self.keysAlloc(self.alloc);
    }

    pub fn keysCount(self: *Self) !u64 {
        var allKeys = try self.keys(); // TODO: better proformance impl in sql
        defer {
            for (allKeys.items) |k| self.free(k);
            allKeys.deinit();
        }
        return allKeys.items.len;
    }
};

fn createMemoryDatabase() !sqlite.Db {
    return try sqlite.Db.init(.{ .mode = .Memory, .open_flags = .{
        .write = true,
        .create = true,
    } });
}

test "SqliteKV can get and set value" {
    const _t = std.testing;
    var db = try createMemoryDatabase();
    var kv = SqliteKV.init(&db, "test_table", _t.allocator);
    try kv.ensure();
    try kv.set("test", "beautiful");
    const val = (try kv.get("test")).?;
    defer kv.free(val);
    try _t.expectEqualStrings("beautiful", val);
}

test "SqliteKV return the latest value when the key set multiple times" {
    const _t = std.testing;
    var db = try createMemoryDatabase();
    var kv = SqliteKV.init(&db, "test_table", _t.allocator);
    try kv.ensure();
    try kv.set("test", "value0");
    try kv.set("test", "value1");
    const value = (try kv.get("test")).?;
    defer kv.free(value);
    try _t.expectEqualStrings("value1", value);
}

test "SqliteKV.keys return all keys in store" {
    const _t = std.testing;
    var db = try createMemoryDatabase();
    var kv = SqliteKV.init(&db, "test_table", _t.allocator);
    const KEYS = .{ "name0", "name1", "name2" };
    try kv.ensure();
    inline for (KEYS) |k| {
        try kv.set(k, "value");
    }
    var keysInStore = try kv.keys();
    defer keysInStore.deinit();
    defer for (keysInStore.items) |k| kv.free(k);
    inline for (KEYS) |k, i| {
        try _t.expectEqualStrings(k, keysInStore.items[i]);
    }
}

test "SqliteKV.setDetail can set created_at column" {
    const _t = std.testing;
    var db = try createMemoryDatabase();
    var kv = SqliteKV.init(&db, "test_table", _t.allocator);
    const KEYS = .{ "name0", "name2", "name3" };
    try kv.ensure();
    inline for (KEYS) |k, i| {
        try kv.setDetail(k, "value", 3 - i);
    }
    var keysInStore = try kv.keys();
    defer keysInStore.deinit();
    defer for (keysInStore.items) |k| kv.free(k);
    const NEW_ORDER_KEYS = .{ "name3", "name2", "name0" };
    inline for (NEW_ORDER_KEYS) |k, i| {
        try _t.expectEqualStrings(k, keysInStore.items[i]);
    }
}

test "SqliteKV.set can hide the value by set null" {
    const _t = std.testing;
    var db = try createMemoryDatabase();
    defer db.deinit();
    var kv = SqliteKV.init(&db, "test_table", _t.allocator);
    try kv.ensure();
    try kv.set("k", "v");
    try kv.set("k", null);
    const val = try kv.get("k");
    defer if (val) |v| kv.free(v);
    try _t.expect(val == null);
}

test "SqliteKV.keysCount counts all keys in store" {
    const _t = std.testing;
    var db = try createMemoryDatabase();
    var kv = SqliteKV.init(&db, "test_table", _t.allocator);
    const KEYS = .{ "name0", "name1", "name2", "name0" };
    try kv.ensure();
    inline for (KEYS) |k| {
        try kv.set(k, "value");
    }
    try _t.expectEqual(@as(u64, 3), try kv.keysCount());
}

pub const Keys = enum {
    username,
    host,
    version,
    alt_username,

    pub fn getName(self: *const Keys) []const u8 {
        return switch (self) {
            else => @tagName(self.*),
        };
    }
};

pub const Profile = struct {
    db: *sqlite.Db,
    usrlets: SqliteKV,
    syslets: SqliteKV,
    vaultNames: SqliteKV,
    alloc: *Allocator,
    kssidGen: kssid.Generator,

    const Self = @This();
    const CURRENT_VERSION = @as(u32, 1);

    pub fn init(db: *sqlite.Db, alloc: *Allocator) Self {
        return Self{
            .db = db,
            .usrlets = SqliteKV.init(db, "usrlets", alloc),
            .syslets = SqliteKV.init(db, "syslets", alloc),
            .vaultNames = SqliteKV.init(db, "vault_names", alloc),
            .alloc = alloc,
            .kssidGen = kssid.Generator.init(),
        };
    }

    pub fn free(self: *Self, val: anytype) void {
        self.alloc.free(val);
    }

    pub fn deinit(self: *Self) void {
        self.db.deinit();
    }

    pub fn ensure(self: *Self) !void {
        if (try self.getVersion()) |version| {
            if (version < CURRENT_VERSION) {
                _ = try self.updateDatabase();
            }
        } else {
            _ = try self.updateDatabase();
        }
    }

    fn updateDatabase(self: *Self) !u32 {
        if (try self.getVersion()) |version| {
            if (version < 1) {
                try self.createLayoutLayer1();
            }
        } else {
            try self.createLayoutLayer1();
        }
        return CURRENT_VERSION;
    }

    fn createLayoutLayer1(self: *Self) !void {
        try self.usrlets.ensure();
        try self.syslets.ensure();
        try self.vaultNames.ensure();
        try self.setVersion(1);
    }

    pub fn setupEmpty(self: *Self, username: []const u8, host: []const u8) !void {
        try self.set(Keys.username, username);
        try self.set(Keys.host, host);
    }

    pub fn set(self: *Self, key: Keys, value: []const u8) !void {
        try self.usrlets.set(key.getName(), value);
    }

    pub fn get(self: *Self, key: Keys) !?[]const u8 {
        return self.usrlets.get(key.getName());
    }

    fn setVersion(self: *Self, comptime version: u64) !void {
        try self.syslets.set("version", std.fmt.comptimePrint("{}", .{version}));
    }

    pub fn getVersion(self: *Self) !?u64 {
        if (try self.syslets.exists()) {
            if (try self.syslets.get("version")) |versionStr| {
                defer self.free(versionStr);
                return try std.fmt.parseInt(u64, versionStr, 0) catch Error.InvalidVersion;
            } else {
                return null;
            }
        } else {
            return null;
        }
    }

    pub fn vault(self: *Self, name: []const u8) !?Vault {
        const idStr = try self.vaultNames.get(name);
        if (idStr) |idStrNonNull| {
            return Vault.init(self, idStrNonNull, try std.fmt.allocPrint(self.alloc, "vault_{s}", .{idStr}) catch |e| @errSetCast(Allocator.Error, e));
        } else {
            return null;
        }
    }

    pub fn vaultOrNew(self: *Self, name: []const u8) !Vault {
        if (try self.vault(name)) |vaultObject| {
            return vaultObject;
        } else {
            const newId = self.kssidGen.generate();
            const newIdStr = try std.fmt.allocPrint(self.alloc, "{}", .{newId}) catch |e| @errSetCast(Allocator.Error, e);
            const newTableName = try std.fmt.allocPrint(self.alloc, "vault_{s}", .{newIdStr}) catch |e| @errSetCast(Allocator.Error, e);
            var newVault = Vault.init(self, newIdStr, newTableName);
            try newVault.ensure();
            try newVault.setupEmpty(name);
            return newVault;
        }
    }

    fn setVault(self: *Self, name: []const u8, idStr: ?[]const u8) !void {
        try self.vaultNames.set(name, idStr);
    }

    pub fn device(self: *Self, idStr: []const u8) !?Device {
        const idStrCopy = self.alloc.dupe(idStr);
        errdefer self.alloc.free(idStrCopy);
        const tableName = try std.fmt.allocPrint(self.alloc, "device_{s}", .{idStr}) catch |e| @errSetCast(Allocator.Error, e);
        errdefer self.alloc.free(tableName);
        var dev = Device.init(self, idStrCopy, tableName);
        if (try dev.exists()) {
            return dev;
        } else {
            self.alloc.free(idStrCopy);
            self.alloc.free(tableName);
            return null;
        }
    }

    pub fn deviceByInt(self: *Self, id: u64) !?Device {
        const idStr = try std.fmt.allocPrint(self.alloc, "{}", .{id}) catch |e| @errSetCast(Allocator.Error, e);
        defer self.free(idStr);
        return try self.device(id);
    }

    fn allDeviceTableNames(self: *Self) ![]const []const u8 {
        const query = "SELECT name FROM sqlite_master WHERE name LIKE \"device!_%\" ESCAPE '!'";
        var s = try self.db.prepare(query);
        defer s.deinit();
        return try s.all([]const u8, self.alloc, .{}, .{});
    }

    pub fn allDeviceIds(self: *Self) ![]u64 {
        const tableNames = try self.allDeviceTableNames();
        defer {
            for (tableNames) |name| self.free(name);
            self.free(tableNames);
        }
        var resultList = ArrayList(u64).init(self.alloc);
        errdefer resultList.deinit();
        for (tableNames) |name| {
            const idStr = name[7..name.len];
            const id = try std.fmt.parseInt(u64, idStr, 0);
            try resultList.append(id);
        }
        return resultList.toOwnedSlice();
    }

    /// Caller owns `name`.
    pub fn createDevice(self: *Self, name: []const u8) !Device {
        const idStr = try std.fmt.allocPrint(
            self.alloc,
            "{}",
            .{self.kssidGen.generate()},
        ) catch |e| @errSetCast(Allocator.Error, e);
        errdefer self.alloc.free(idStr);
        const tableName = try std.fmt.allocPrint(
            self.alloc,
            "device_{s}",
            .{idStr},
        ) catch |e| @errSetCast(Allocator.Error, e);
        errdefer self.alloc.free(tableName);
        var dev = Device.init(self, idStr, tableName);
        try dev.ensure();
        try dev.setupEmpty(name);
        return dev;
    }
};

test "Profile can initialise database layout automatically" {
    const _t = std.testing;
    var db = try createMemoryDatabase();
    defer db.deinit();
    var p = Profile.init(&db, _t.allocator);
    defer p.deinit();
    try p.ensure();
}

test "Profile can setup empty database" {
    const _t = std.testing;
    var db = try createMemoryDatabase();
    defer db.deinit();
    var p = Profile.init(&db, _t.allocator);
    defer p.deinit();
    try p.ensure();
    try p.setupEmpty("The_Courier", "newvegas");
    const name = try p.get(Keys.username);
    defer p.free(name.?);
    try _t.expectEqualStrings("The_Courier", name.?);
    const host = try p.get(Keys.host);
    defer p.free(host.?);
    try _t.expectEqualStrings("newvegas", host.?);
}

pub const Vault = struct {
    profile: *Profile,
    idStr: []const u8,
    lets: SqliteKV,
    tableName: []const u8,

    const Self = @This();

    /// Initialise structure.
    /// Callee owns `idStr` and `tableName`, they should be allocated by `profile`'s allocator.
    fn init(profile: *Profile, idStr: []const u8, tableName: []const u8) Self {
        return Self{
            .profile = profile,
            .idStr = idStr,
            .tableName = tableName,
            .lets = SqliteKV.init(profile.db, tableName, profile.alloc),
        };
    }

    pub fn deinit(self: *Self) void {
        self.free(self.idStr);
        self.free(self.tableName);
    }

    pub fn free(self: *Self, val: anytype) void {
        return self.profile.free(val);
    }

    pub fn exists(self: *Self) !bool {
        return try self.lets.exists();
    }

    pub fn ensure(self: *Self) !void {
        try self.lets.ensure();
        if (try self.lets.get("id")) |id| {
            defer self.free(id);
            if (!std.mem.eql(u8, id, self.idStr)) {
                return error.InvalidDatabase;
            }
        } else {
            try self.lets.set("id", self.idStr);
        }
    }

    pub fn setupEmpty(self: *Self, name: []const u8) !void {
        try self.setName(name);
    }

    pub fn getName(self: *Self) !?[]const u8 {
        return try self.lets.get("name");
    }

    pub fn setName(self: *Self, name: []const u8) !void {
        const possibleOldName = try self.lets.get("name");
        defer if (possibleOldName) |val| self.lets.free(val);
        try self.lets.set("name", name);
        try self.profile.setVault(name, self.idStr);
        if (possibleOldName) |oldName| {
            try self.profile.setVault(oldName, null);
        }
    }

    pub fn getId(self: *Self) !?[]const u8 {
        return try self.profile.alloc.dupe(u8, self.idStr);
    }

    pub fn getIdInt(self: *Self) u64 {
        return std.fmt.parseInt(u64, self.idStr, 0) catch unreachable;
    }
};

test "Profile can create new vault" {
    const _t = std.testing;
    var db = try createMemoryDatabase();
    defer db.deinit();
    var person = Profile.init(&db, _t.allocator);
    defer person.deinit();
    try person.ensure();
    try person.setupEmpty("username", "example.org");
    var vault = try person.vaultOrNew("test_vault");
    defer vault.deinit();
    var vaultAgain = try person.vault("test_vault");
    defer if (vaultAgain) |*v| v.deinit();
    try _t.expect(vaultAgain != null);
}

test "Profile.setName will set old name to null" {
    const _t = std.testing;
    var db = try createMemoryDatabase();
    defer db.deinit();
    var person = Profile.init(&db, _t.allocator);
    defer person.deinit();
    try person.ensure();
    try person.setupEmpty("username", "example.org");
    var vault = try person.vaultOrNew("test_vault");
    defer vault.deinit();
    try vault.setName("another_test_vault");
    var noVault = try person.vault("test_vault");
    defer if (noVault) |*v| v.deinit();
    try _t.expect(noVault == null);
    var vaultAgain = try person.vault("another_test_vault");
    defer if (vaultAgain) |*v| v.deinit();
    try _t.expect(vaultAgain != null);
    try _t.expectEqual(vault.getIdInt(), vaultAgain.?.getIdInt());
    const newName = try vault.getName();
    defer if (newName) |n| vault.free(n);
    try _t.expectEqualStrings("another_test_vault", newName.?);
}

pub const Device = struct {
    profile: *Profile,
    idStr: []const u8,
    lets: SqliteKV,
    tableName: []const u8,

    const Self = @This();

    /// Initialise structure.
    /// Callee owns `idStr` and `tableName`, they should be allocated by `profile`'s allocator.
    fn init(profile: *Profile, idStr: []const u8, tableName: []const u8) Self {
        return Self{
            .profile = profile,
            .idStr = idStr,
            .tableName = tableName,
            .lets = SqliteKV.init(profile.db, tableName, profile.alloc),
        };
    }

    pub fn deinit(self: *Self) void {
        self.free(self.idStr);
        self.free(self.tableName);
    }

    pub fn free(self: *Self, val: anytype) void {
        return self.profile.free(val);
    }

    pub fn exists(self: *Self) !bool {
        return try self.lets.exists();
    }

    pub fn ensure(self: *Self) !void {
        try self.lets.ensure();
        if (try self.lets.get("id")) |id| {
            defer self.free(id);
            if (!std.mem.eql(u8, id, self.idStr)) {
                return error.InvalidDatabase;
            }
        } else {
            try self.lets.set("id", self.idStr);
        }
    }

    pub fn setupEmpty(self: *Self, name: []const u8) !void {
        try self.setName(name);
    }

    pub fn getName(self: *Self) !?[]const u8 {
        return try self.lets.get("name");
    }

    pub fn setName(self: *Self, name: []const u8) !void {
        try self.lets.set("name", name);
    }

    pub fn getId(self: *Self) !?[]const u8 {
        return try self.profile.alloc.dupe(u8, self.idStr);
    }

    pub fn getIdInt(self: *Self) u64 {
        return std.fmt.parseInt(u64, self.idStr, 0) catch unreachable;
    }
};

test "Profile can create new device" {
    const _t = std.testing;
    var db = try createMemoryDatabase();
    defer db.deinit();
    var person = Profile.init(&db, _t.allocator);
    defer person.deinit();
    try person.ensure();
    try person.setupEmpty("username", "example.org");
    var dev = try person.createDevice("test_dev0");
    defer dev.deinit();
    try dev.ensure();
}

test "Profile can get all device ids" {
    const _t = std.testing;
    var db = try createMemoryDatabase();
    defer db.deinit();
    var person = Profile.init(&db, _t.allocator);
    defer person.deinit();
    try person.ensure();
    try person.setupEmpty("username", "example.org");
    var dev0 = try person.createDevice("dev0");
    defer dev0.deinit();
    try dev0.ensure();
    var dev1 = try person.createDevice("dev1");
    defer dev1.deinit();
    try dev1.ensure();
    const dev0Id = dev0.getIdInt();
    const dev1Id = dev1.getIdInt();
    const allIds = try person.allDeviceIds();
    defer person.free(allIds);
    var isIdExists = [_]bool {false, false};
    for (allIds) |id| {
        if (id == dev0Id) {
            isIdExists[0] = true;
        } else if (id == dev1Id) {
            isIdExists[1] = true;
        }
    }
    for (isIdExists) |b| {
        try _t.expect(b);
    }
}
