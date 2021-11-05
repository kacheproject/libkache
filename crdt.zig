const std = @import("std");
const HashMap = std.AutoArrayHashMap;
const Allocator = std.mem.Allocator;
const kssid = @import("./kssid.zig");

pub const VecClock = struct {
    vec: HashMap(u64, u64),
    myid: u64,

    const Self = @This();

    pub fn init(myid: u64, initialClk: u64, alloc: *Allocator) Allocator.Error!Self {
        var result = Self {
            .vec = HashMap(u64, u64).init(alloc),
            .myid = myid,
        };
        try result.vec.put(myid, initialClk);
        return result;
    }

    pub fn deinit(self: *Self) void {
        self.vec.deinit();
    }

    pub fn canBeUpdated(self: *Self, k: u64, clk: u64) bool {
        if (self.vec.get(k)) |val| {
            return clk >= val;
        } else {
            return true;
        }
    }

    pub fn update(self: *Self, k: u64, clk: u64) Allocator.Error!bool {
        if (self.vec.contains(k)) {
            var oldClk = self.vec.get(k);
            if (clk > oldClk.?) {
                try self.vec.put(k, clk);
                return true;
            } else {
                return false;
            }
        } else {
            try self.vec.put(k, clk);
            return true;
        }
    }

    pub fn myClk(self: *Self) u64 {
        return self.myClkPtr().*;
    }

    pub fn myClkPtr(self: *Self) *u64 {
        if (self.vec.getPtr(self.myid)) |clk| {
            return clk;
        } else {
            unreachable;
        }
    }

    pub fn increment(self: *Self, offest: u64) u64 {
        var oldVal = self.myClk();
        var val = oldVal + offest;
        self.myClkPtr().* = val;
        return val;
    }
};
