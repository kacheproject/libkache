const std = @import("std");
const Allocator = std.mem.Allocator;

pub fn equal(s1: []const u8, s2: []const u8) bool {
    if (s1.len == s2.len){
        for (s1) |c, i| {
            if (c != s2[i]) return false;
        }
        return true;
    } else {
        return false;
    }
}

test "equal" {
    const expectEqual = std.testing.expectEqual;
    try expectEqual(equal("Titanfall", "Crysis"), false);
    try expectEqual(equal("Tankman", "Tankman"), true);
}

pub fn concat2(s1: []const u8, s2: []const u8, alloc: *Allocator) Allocator.Error![]u8 {
    return std.fmt.allocPrint(alloc, "{s}{s}", .{s1, s2}) catch |e| return @errSetCast(Allocator.Error, e);
}

test "concat2" {
    const expectEqualStrings = std.testing.expectEqualStrings;
    const expect = std.testing.expect;
    var s = try concat2("Tiananmen Square ", "in 04 06 1989", std.testing.allocator);
    defer std.testing.allocator.free(s);
    try expectEqualStrings(s, "Tiananmen Square in 04 06 1989");
    try expect(s.ptr != "Tiananmen Square in 04 06 1989");
}
