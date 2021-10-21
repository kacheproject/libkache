//! Portable Numbers

const std = @import("std");
const builtin = @import("builtin");

pub fn getIntByteSlice(comptime T: type, n: *T) []u8 {
    return @ptrCast([*]u8, n)[0..@sizeOf(T)];
}

fn zigZagEncode(comptime T: type, n: T) T {
    if (n >= 0) {
        var k1: T = undefined;
        @shlWithOverflow(T, n, 1, &k1);
        return k1;
    } else {
        var k1: T = undefined;
        @shlWithOverflow(T, -n-1, 1, &k1);
        return k1 | 1;
    }
}

fn reserveInt(comptime T: type, n: T) T {
    if (@typeInfo(T).Int.signedness == .signed) @compileError("expect unsigned integer");
    var arr = std.PackedIntArray(T, 1).initAllTo(n).sliceCast(u8);
    var buf = std.PackedIntArray(T, 1).initAllTo(n).sliceCast(u8);
    for (buf.bytes) |*c, i| {
        c.* = arr.bytes[arr.len()-i-1];
    }
    return buf.sliceCast(T).get(0);
}

pub fn fromPortableInt(comptime T: type, n: T) T {
    return switch (builtin.cpu.arch.endian()) {
        .Big => n,
        .Little => reserveInt(T, n),
    };
}

pub fn toPortableInt(comptime T: type, n: T) T {
    return fromPortableInt(T, n);
}

test "PortableInt" {
    const _t = std.testing;
    {
        var number = @as(u8, 127);
        var n = fromPortableInt(u8, number);
        var n0 = toPortableInt(u8, n);
        try _t.expectEqual(number, n0);
    }
}
