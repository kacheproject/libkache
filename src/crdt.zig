const std = @import("std");
const HashMap = std.HashMap;
const Allocator = std.mem.Allocator;
const kssid = @import("./kssid.zig");

const VecClock = struct {
    vec: HashMap(u64, u64, std.hash_map.AutoContext(u64), 0.9),
    myid: u64,

    const Self = @This();

    pub fn init(myid: u64, initialClk: u64, alloc: *Allocator) Allocator.Error!Self {
        var result = Self {
            .vec = HashMap(u64, u64, std.hash_map.AutoContext(u64), 0.8).init(alloc),
            .myid = myid,
        };
        try result.vec.put(myid, initialClk);
        return result;
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
                try self.vec.put(clk);
                return true;
            } else {
                return false;
            }
        } else {
            try self.vec.put(clk);
            return true;
        }
    }

    pub fn myClk(self: *Self) u64 {
        if (self.vec.get(self.myid)) |myclk| {
            return myclk;
        } else {
            return 0;
        }
    }

    pub fn increment(self: *Self, offest: u64) void {
        var oldVal = self.vec.get(self.myid).?;
        var val = oldVal + offest;
        self.vec.put(val) catch unreachable; // the key-value pair have been exists
        return val;
    }
};
