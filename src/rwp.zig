//! Rope Wire Protocol Library.
//! This library is intented to use with ZeroMQ as wire protocol.
//! Because I(Rubicon) do not want to reimplement whole ZMTP 3 in zig to use ZeroMQ with sam3.
//! It's a small protocol inspired by ZMTP and (the old kacheproject/rfc1) RWTP (Rope Wire Transfer Protocol) to transfer data on I2P.
//! That's the reason this protocol drop all encryption compared to old rfc1 RWTP, I2P already have E2E encryption.
//! Do not use this cleartext protocol in any case may expose to the public internet.
//! It's recommended to use this protocol with virtual streams or replicatable datagram becasue of the lack of heartbeats.
//! See kacheproject/rfc1 for protocol details. (Note: It just supports a subset of the features in ZMTP 3!)
const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;

const FLAG_CMD = @as(u8, 1) << 6;
const FLAG_MORE = @as(u8, 1) << 7;
const FLAG_LONG = @as(u8, 1) << 5;

const Command = enum(u8) {
    AskOpt = 1,
    SetOpt = 2,
    Subscribe = 3,
    Unsubscribe = 4,
};


const Opt = enum(u8) {
    Version = 1,
    SocketType = 2,
    RoutingId = 3,
};


fn toPortableInt(comptime T: type, val: T) T {
    return switch (builtin.cpu.arch.endian()) {
        .Big => val,
        .Little => @bitReverse(T, val),
    };
}

fn fromPortableInt(comptime T: type, val: T) T {
    return toPortableInt(T, val);
}

// Tests for portable int should be run in different architectures.
test "portable int: signed" {
    const _t = std.testing;
    {
        var i = @as(i8, 123);
        var iPortable = toPortableInt(i8, i);
        var iOriginal = fromPortableInt(i8, iPortable);
        try _t.expectEqual(i, iOriginal);
    }
    {
        var n = @as(i8, -123);
        var nPortable = toPortableInt(i8, n);
        var nOriginal = fromPortableInt(i8, nPortable);
        try _t.expectEqual(n, nOriginal);
    }
}

test "portable int: unsigned" {
    const _t = std.testing;
    {
        var i = @as(u8, 134);
        var iPortable = toPortableInt(u8, i);
        var iOriginal = fromPortableInt(u8, iPortable);
        try _t.expectEqual(i, iOriginal);
    }
}

fn intAsByteSlice(comptime T: type, val: *const T) []const u8 {
    return @ptrCast([*]const u8, val)[0..@sizeOf(T)];
}

fn byteSliceToInt(comptime T: type, slice: []const u8) T {
    std.debug.assert((slice.len * 8) == @typeInfo(T).Int.bits);
    return @ptrCast(*const T, slice.ptr).*;
}

test "intAsByteSlice and byteSliceToInt" {
    const _t = std.testing;
    var i = @as(i8, -127);
    var slice = intAsByteSlice(i8, &i);
    var iOriginal = byteSliceToInt(i8, slice);
    try _t.expectEqual(i, iOriginal);
}

const Header = struct {
    cmd: bool = false,
    more: bool = false,
    long: bool = true,

    const Self = @This();

    pub fn build(self: *const Self) u8 {
        var iflags = @as(u8, 0);

        if (self.cmd) {
            iflags |= FLAG_CMD;
        }

        if (self.more) {
            iflags |= FLAG_MORE;
        }

        if (self.long) {
            iflags |= FLAG_LONG;
        }

        return iflags;
    }

    pub fn parse(iflags: u8) Self {
        const i = iflags;
        return Self{
            .cmd = (i & FLAG_CMD) > 0,
            .more = (i & FLAG_MORE) > 0,
            .long = (i & FLAG_LONG) > 0,
        };
    }

    pub fn getSize(self: *const Self) u64 {
        return 1;
    }
};

pub const FrameEncoder = struct {
    nextByte: u64,
    totalBytes: u64,
    frame: *const Frame,

    const Self = @This();

    pub const WriteBufError = error{
        InsufficientSize,
    };

    fn init(frame: *const Frame) Self {
        return Self{
            .frame = frame,
            .totalBytes = frame.getSize(),
            .nextByte = 0,
        };
    }

    pub fn next(self: *Self) ?u8 {
        const val = self.current();
        self.nextByte += 1;
        return val;
    }

    fn getSizeByte64(self: *Self, i: u8) u8 {
        return std.PackedIntArray(u64, 1).initAllTo(self.frame.data.len).sliceCast(u8).get(i);
    }

    /// Return current byte.
    /// Note that the bytes return in native endiness.
    /// You should send data in network order to decode by FrameDecoder, see `currentIndexNE`.
    pub fn current(self: *Self) ?u8 {
        if (!self.frame.header.long) {
            return switch (self.nextByte) {
                0 => self.frame.header.build(),
                1 => @intCast(u8, self.frame.data.len),
                else => |i| if (i < self.totalBytes) self.frame.data[i - 2] else null,
            };
        } else {
            return switch (self.nextByte) {
                0 => self.frame.header.build(),
                1, 2, 3, 4, 5, 6, 7, 8 => |i| self.getSizeByte64(@intCast(u8, i - 1)),
                else => |i| if (i < self.totalBytes) self.frame.data[i - 9] else null,
            };
        }
    }

    /// Return index in native byte order.
    pub fn currentIndex(self: *Self) usize {
        if (self.nextByte == 0) {
            unreachable;
        }
        return self.nextByte - 1;
    }

    /// Return correct memory index in network byte order (big-endiness).
    pub fn currentIndexNE(self: *Self) usize {
        return switch (builtin.cpu.arch.endian()) {
            .Big => self.currentIndex(),
            .Little => self.totalBytes - self.currentIndex() - 1,
        };
    }

    pub fn writeToBuf(self: *Self, buf: []u8) ![]u8 {
        if (buf.len < self.totalBytes) {
            return WriteBufError.InsufficientSize;
        }
        while (self.next()) |c| {
            buf[self.currentIndexNE()] = c;
        }
        return buf[0..self.totalBytes];
    }

    pub fn writeToBufAlloc(self: *Self, alloc: *Allocator) Allocator.Error![]const u8 {
        var buf = try alloc.alloc(u8, self.totalBytes);
        return self.writeToBuf(buf) catch unreachable;
    }
};

pub const FrameDecoder = struct {
    nextByte: u64,
    frame: *Frame,
    size: u64,

    const Error = error{
        Corrupted,
    };

    const Self = @This();

    fn init(frame: *Frame) Self {
        return Self{
            .nextByte = 0,
            .frame = frame,
            .size = 0,
        };
    }

    fn resevseDataOrderInplace(buf: []u8) void {
        var divN = buf.len / 2;
        var right = buf[0..divN];
        var left = buf[divN..buf.len];
        for (right) |c, rightIndex| {
            const leftIndex = left.len - rightIndex - 1;
            right[rightIndex] = left[leftIndex];
            left[leftIndex] = c;
        }
    }

    test "resevseDataOrderInplace" {
        const _t = std.testing;
        var data = [_]u8{ 1, 2, 3, 4, 5 };
        resevseDataOrderInplace(&data);
        try _t.expectEqualSlices(u8, &.{ 5, 4, 3, 2, 1 }, &data);
    }

    fn enforceNetworkByteOrderInplace(buf: []u8) void {
        switch (builtin.cpu.arch.endian()) {
            .Big => {},
            .Little => resevseDataOrderInplace(buf),
        }
    }

    /// Feed decoder with `c` and return true until frame prefix is end.
    /// Please ensure the order of the bytes being feed is in native endianess.
    ///
    /// ````zig
    /// var decoder = frame.getDecoder();
    /// for (stringNeededToDecode) |c| {
    ///     if(!decoder.feed(c)) break;
    /// }
    /// var nextFramePos = try decoder.setBuffer(stringNeededToDecode);
    /// ````
    pub fn feed(self: *Self, c: u8) bool {
        switch (self.nextByte) {
            0 => {
                self.frame.header = Header.parse(c);
            },
            else => {
                if (!self.frame.header.long) {
                    switch (self.nextByte) {
                        1 => {
                            self.size = c;
                        },
                        else => {
                            return false;
                        },
                    }
                } else {
                    switch (self.nextByte) {
                        1, 2, 3, 4, 5, 6, 7, 8 => |i| {
                            var sizeSlice = std.PackedIntArray(u64, 1).initAllTo(self.size).sliceCast(u8);
                            sizeSlice.set(i - 1, c);
                            const sizePortable = sizeSlice.sliceCast(u64).get(0);
                            self.size = sizePortable;
                        },
                        else => {
                            return false;
                        },
                    }
                }
            },
        }
        self.nextByte += 1;
        return true;
    }

    fn checkDecoding(self: *Self) Error!void {
        if (self.nextByte < 2) {
            return Error.Corrupted;
        } else if (self.frame.header.long and self.nextByte < 9){
            return Error.Corrupted;
        }
    }

    /// Set the buffer of the frame and return the next frame position.
    /// This function will try to ensure decoding is complete without error.
    /// This function is designed to use with `feed`.
    pub fn setBuffer(self: *Self, buf: []u8) Error!u64 {
        try self.checkDecoding();
        if (buf.len < (self.frame.getPrefixSize()+self.size)){
            return Error.Corrupted;
        }
        self.frame.data = buf[self.frame.getPrefixSize()..self.frame.getPrefixSize()+self.size];
        return self.frame.getSize();
    }

    /// Reserve byte order in-place if it isn't in network order, decode frame and return the possible next frame position.
    pub fn decode(self: *Self, buf: []u8) Error!u64 {
        enforceNetworkByteOrderInplace(buf);
        for (buf) |c| {
            if (!self.feed(c)) break;
        }
        return try self.setBuffer(buf);
    }
};

pub const Frame = struct {
    header: Header,
    data: []const u8,

    const Self = @This();

    pub fn init(header: Header, data: []const u8) Self {
        var newHeader = header;
        if (data.len > std.math.maxInt(u8)) {
            newHeader.long = true;
        } else {
            newHeader.long = false;
        }
        return Self{
            .header = newHeader,
            .data = data,
        };
    }

    pub fn initEmpty() Self {
        return Self{
            .header = std.mem.zeroes(Header),
            .data = undefined,
        };
    }

    fn getSizeFieldSize(self: *const Self) u64 {
        return if (self.header.long) 8 else 1;
    }

    fn getPrefixSize(self: *const Self) u64 {
        return self.header.getSize() + self.getSizeFieldSize();
    }

    pub fn getSize(self: *const Self) u64 {
        return self.getPrefixSize() + self.data.len;
    }

    pub fn getEncoder(self: *const Self) FrameEncoder {
        return FrameEncoder.init(self);
    }

    pub fn getDecoder(self: *Self) FrameDecoder {
        return FrameDecoder.init(self);
    }
};

test "FrameDecoder and FrameEncoder" {
    const _t = std.testing;
    {
        const DATA = "Hello RWP"; // length is 9
        const frame0 = Frame.init(.{}, DATA);
        var buf = [_]u8{0} ** 256;
        var encoder = frame0.getEncoder();
        var wireData = try encoder.writeToBuf(&buf); // length is 1 + 1 + 9 = 11
        var frame1 = Frame.initEmpty();
        var decoder = frame1.getDecoder();
        const fNextPos = try decoder.decode(wireData);
        try _t.expectEqual(@as(u64, wireData.len), fNextPos);
        try _t.expectEqualStrings(DATA, frame1.data);
    }
    {
        const DATA = "1" ** (std.math.maxInt(u8) + 1);
        const frame0 = Frame.init(.{}, DATA);
        var buf = [_]u8{0} ** 512;
        var encoder = frame0.getEncoder();
        var wireData = try encoder.writeToBuf(&buf);
        var frame1 = Frame.initEmpty();
        var decoder = frame1.getDecoder();
        const fNextPos = try decoder.decode(wireData);
        try _t.expectEqual(@as(u64, wireData.len), fNextPos);
        try _t.expectEqualStrings(DATA, frame1.data);
    }
    {
        const DATA = "1" ** (std.math.maxInt(u8) + 1);
        const frame0 = Frame.init(.{}, DATA);
        var buf = [_]u8{0} ** 512;
        var encoder = frame0.getEncoder();
        var wireData = try encoder.writeToBuf(&buf);
        var frame1 = Frame.initEmpty();
        var decoder = frame1.getDecoder();
        for (wireData) |_, i| {
            if (!decoder.feed(wireData[wireData.len-i-1])){
                break;
            }
        }
        FrameDecoder.enforceNetworkByteOrderInplace(wireData);
        const fNextPos = try decoder.setBuffer(wireData);
        try _t.expectEqual(@as(u64, wireData.len), fNextPos);
        try _t.expectEqualStrings(DATA, frame1.data);
    }
}
