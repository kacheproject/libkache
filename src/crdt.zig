const std = @import("std");
const HashMap = std.HashMap;
const Allocator = std.mem.Allocator;
const kssid = @import("./kssid.zig");

const VecClock = struct {
    vec: HashMap(u64, u64, std.hash_map.AutoContext(u64), 0.9),
    myid: u64,

    const Self = @This();

    pub fn init(myid: u64, alloc: *Allocator) Allocator.Error!Self {
        return Self {
            .vec = HashMap(u64, u64, std.hash_map.AutoContext(u64), 0.8).init(alloc),
            .myid = myid,
        };
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

    pub fn increment(self: *Self, offest: u64) Allocator.Error!void {
        var oldVal = self.vec.get(self.myid);
        var val = if (oldVal) |old| old + offest else offest;
        try self.vec.put(val);
    }

    pub fn send(self: *Self, alloc: *Allocator) Allocator.Error![]u8 {
        var len = self.vec.count();
        var buf = try alloc.alloc(u64, len*2);
        var currslot = 0;
        for (self.vec.keyIterator()) |k| {
            var val = self.vec.get(k).?;
            buf[currslot] = k;
            buf[currslot+1] = val;
            currslot += 2;
        }
        return buf;
    }

    pub fn recv(self: *Self, buf: []u8) bool {
        for (buf) |val, i| {
            if (i % 2 == 1) {
                var k = buf[i-1];
                if (!self.canBeUpdated(k, val)) {
                    return false;
                }
            }
        }

        for (buf) |val, i| {
            if (i % 2 == 1) {
                var k = buf[i-1];
                self.update(k, val);
            }
        }
        return true;
    }
};
