//! KSSID (Kache Simple & Short IDentity)
//! This library contains a tool to generate a 8 bytes id, which naturally shortable across seconds.
//! Such short id should only be used to identify Peers or such long-term use, which transfered on network frequently.
//! Use UUIDv4/KSUID when used in collision matters.
//!
//! Format (64 bits in total)
//! | unix epoch - 14e8 (32 bits) | random data (32 bits) |
const std = @import("std");

const time = std.time;

const EPOCH_START = @as(i64, 14e8);

fn generateKSSID(rng: *std.rand.Random) u64 {
    var buf: u64 = 0;
    var currentTime = time.timestamp();
    if (currentTime < EPOCH_START) {
        unreachable;
    }
    var idTime = @bitCast(u64, currentTime - EPOCH_START); // (Rubicon: ) we have checked that the currentTime >= EPOCH_START
    idTime = idTime << 32;
    buf += idTime;
    var n = rng.int(u32);
    buf += n;
    return buf;
}

pub const Generator = struct {
    rng: std.rand.Random,

    const Self = @This();
    
    pub fn init() Self {
        return Self {
            .rng = std.crypto.random.*,
        };
    }

    pub fn generate(self: *Self) u64 {
        return generateKSSID(&self.rng);
    }
};

test "Generator.generate() can generate different number in each call" {
    const expect = std.testing.expect;

    var gen = Generator.init();
    const n0 = gen.generate();
    const n1 = gen.generate();
    try expect(n0 != n1);
}

test "Generator.generate() can generate naturally shortable id across seconds" {
    const idNumber = 3;
    const expect = std.testing.expect;

    var buf0 = [_]u64{0} ** idNumber;

    var gen = Generator.init();
    for (buf0) |*n| {
        time.sleep(time.ns_per_s);
        n.* = gen.generate();
    }

    try expect(std.sort.isSorted(u64, buf0[0..idNumber], {}, comptime std.sort.asc(u64)));
}
