//! A custom WireGuard implementation working with Rope Protocol.
//! It does not works with IP, so could not be work with normal wireguard implementations.
const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const Allocator = mem.Allocator;
const crypto = @import("crypto.zig");
const print = std.debug.print;

fn assert(ok: bool) void {
    if (builtin.mode == .Debug) {
        if (!ok) unreachable;
    }
}

const c = @cImport({
    @cInclude("sodium.h");
});

const nativeEndianess = builtin.cpu.arch.endian();

const RP = struct {
    // RP (16 bytes) = ver(u8) target_id(u64) target_port(u16) src_id(u64) src_port(u16) flags(u8) length(u16)
    const HEADER_SIZE: usize = 16;

    const VERISON: u8 = 0x1;

    const Header = struct { // Always use big-endiness
        ver: u8 = VERISON,
        targetId: u64,
        targetPort: u16,
        srcId: u64,
        srcPort: u64,
        flags: u8,
        length: u16,
    };
};

pub const TAI64N = struct {
    secPart: u64,
    nanoPart: u32,

    fn init(nanoTimestamp: i128) TAI64N {
        const original = std.math.absCast(nanoTimestamp);
        const secPart = @intCast(u64, @divTrunc(original, std.time.ns_per_s));
        const nanoPart = @intCast(u32, original - (@intCast(u128, secPart) * std.time.ns_per_s));
        return TAI64N{
            .secPart = secPart,
            .nanoPart = nanoPart,
        };
    }

    fn now() TAI64N {
        return TAI64N.init(std.time.nanoTimestamp());
    }

    fn cast(timestamp: [12]u8) TAI64N {
        var secPart = std.PackedIntSliceEndian(u8, .Big).init(timestamp[0..8], 8).sliceCastEndian(u64, nativeEndianess).get(0);
        var nanoPart = std.PackedIntSliceEndian(u8, .Big).init(timestamp[8..12], 4).sliceCastEndian(u32, nativeEndianess).get(1);
        return TAI64N{
            .secPart = secPart,
            .nanoPart = nanoPart,
        };
    }

    fn data(self: TAI64N) [12]u8 {
        var buf: [12]u8 = undefined;
        mem.writeInt(u64, buf[0..8], self.secPart, .Big);
        mem.writeInt(u32, buf[8..12], self.nanoPart, .Big);
        return buf;
    }
};

const utils = struct {
    const CONSTRUCTION = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
    const IDENTIFIER = "WireGuard v1 zx2c4 Jason@zx2c4.com";
    const LABEL_MAC1 = "mac1----";
    const LABEL_COOKIE = "cookie--";
    const CONSTRUCTION_HASH = hashCon: {
        @setEvalBranchQuota(9999);
        var buf: [32]u8 = undefined;
        break :hashCon hash(&buf, CONSTRUCTION);
    };
    const CONSTRUCTION_HASH_AND_IDENTIFIER_THEN_HASH = hashConAndId: {
        @setEvalBranchQuota(9999);
        var buf: [32]u8 = undefined;
        var concated: [32 + IDENTIFIER.len]u8 = undefined;
        mem.copy(u8, concated[0..32], CONSTRUCTION_HASH);
        mem.copy(u8, concated[32 .. 32 + IDENTIFIER.len], IDENTIFIER);
        break :hashConAndId hash(&buf, &concated);
    };
    var random = std.crypto.random.*;

    fn initialHash(staticKey: *PublicKey) [32]u8 {
        var buf: [32]u8 = undefined;
        var concated: [64]u8 = undefined;
        mem.copy(u8, concated[0..32], CONSTRUCTION_HASH_AND_IDENTIFIER_THEN_HASH);
        mem.copy(u8, concated[32..64], staticKey);
        _ = hash(&buf, &concated);
        return buf;
    }

    fn dh(privateKey: *const PrivateKey, publicKey: *const PublicKey) [32]u8 {
        return std.crypto.dh.X25519.scalarmult(privateKey.*, publicKey.*) catch unreachable;
    }

    const Keypair = struct {
        private: PrivateKey,
        public: PublicKey,
    };

    fn dhGen() Keypair {
        var kp = std.crypto.dh.X25519.KeyPair.create(null) catch unreachable;
        return .{ .private = kp.secret_key, .public = kp.public_key };
    }

    fn hash(buf: *[32]u8, input: []const u8) *[32]u8 {
        std.crypto.hash.blake2.Blake2s256.hash(input, buf, .{});
        return buf[0..32];
    }

    fn hashParts(buf: *[32]u8, input: anytype) *[32]u8 {
        var object = std.crypto.hash.blake2.Blake2s256.init(.{});
        inline for (comptime std.meta.fieldNames(@TypeOf(input))) |name| {
            const field = @field(input, name);
            object.update(field);
        }
        object.final(buf);
        return buf;
    }

    fn mac(buf: *[16]u8, key: []const u8, input: []const u8) *[16]u8 {
        std.crypto.hash.blake2.Blake2s128.hash(input, buf, .{ .key = key });
        return buf;
    }

    fn hmac(buf: *[32]u8, key: []const u8, input: []const u8) *[32]u8 {
        const Hmac = std.crypto.auth.hmac.Hmac;
        Hmac(std.crypto.hash.blake2.Blake2s256).create(buf, input, key);
        return buf;
    }

    fn hmacParts(buf: *[32]u8, key: []const u8, input: anytype) *[32]u8 {
        const Hmac = std.crypto.auth.hmac.Hmac;
        var object = Hmac(std.crypto.hash.blake2.Blake2s256).init(key);
        inline for (comptime std.meta.fieldNames(@TypeOf(input))) |name| {
            const field = @field(input, name);
            object.update(field);
        }
        object.final(buf);
        return buf;
    }

    fn timestamp(nanosec: ?i128) [12]u8 {
        const ts: TAI64N = if (nanosec) |nsec| TAI64N.init(nsec) else TAI64N.now();
        return ts.data();
    }

    // the counter will be converted to little-endiness
    fn aead(buf: []u8, key: []const u8, counter: u64, plain: []const u8, auth: ?[]const u8) ![]const u8 {
        var nonce = mem.zeroes([8]u8);
        {
            mem.writeInt(u64, &nonce, counter, .Little);
        }
        return try crypto.aead.encrypt(.Chacha20Poly1305, .{
            .secret = buf,
            .clear = plain,
            .addtional = auth,
            .nonce = &nonce,
            .key = key,
        });
    }

    fn deaead(buf: []u8, key: []const u8, counter: u64, secret: []const u8, auth: ?[]const u8) ![]const u8 {
        var nonce = mem.zeroes([8]u8);
        {
            mem.writeInt(u64, &nonce, counter, .Little);
        }
        return try crypto.aead.decrypt(.Chacha20Poly1305, .{
            .secret = secret,
            .clear = buf,
            .addtional = auth,
            .nonce = &nonce,
            .key = key,
        });
    }
};

pub const PublicKey = [32]u8;

pub const PrivateKey = [32]u8;

fn fillFromStruct(value: anytype, buf: []u8) []const u8 {
    var ptr = @as(usize, 0);
    inline for (comptime std.meta.fields(@TypeOf(value))) |field| {
        const F = field.field_type;
        const fSize = @sizeOf(F);
        var fPtr = @ptrCast(*F, buf[ptr .. ptr + fSize].ptr);
        fPtr.* = @field(value, field.name);
        ptr += fSize;
    }
    return buf[0..ptr];
}

test "fillFromStruct can fill buffer from structure in order" {
    const TempStructure = struct {
        a: [8]u8,
        b: [3]u8,
    };
    var obj = TempStructure{
        .a = .{ 0, 1, 2, 3, 4, 5, 6, 7 },
        .b = .{ 0, 1, 2 },
    };
    var buf: [11]u8 = undefined;
    var sli = fillFromStruct(obj, &buf);
    try std.testing.expectEqualSlices(u8, &.{ 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2 }, sli);
}

fn readToStruct(comptime T: type, buf: []const u8) T {
    var o = mem.zeroes(T);
    var ptr = @as(usize, 0);
    inline for (comptime std.meta.fields(T)) |field| {
        const F = field.field_type;
        const fSize = @sizeOf(F);
        var fPtr = @ptrCast(*const F, buf[ptr .. ptr + fSize].ptr);
        @field(o, field.name) = fPtr.*;
        ptr += fSize;
    }
    return o;
}

fn fillSize(comptime T: type) usize {
    var ptr = @as(usize, 0);
    inline for (comptime std.meta.fields(T)) |field| {
        const F = field.field_type;
        const fSize = @sizeOf(F);
        ptr += fSize;
    }
    return ptr;
}

test "readToStruct can read buffer to structure in order" {
    const TempStructure = struct {
        a: [8]u8,
        b: [3]u8,
    };
    var buf: [11]u8 = .{ 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2 };
    var sli = readToStruct(TempStructure, &buf);
    try std.testing.expectEqualSlices(u8, &.{ 0, 1, 2, 3, 4, 5, 6, 7 }, &sli.a);
    try std.testing.expectEqualSlices(u8, &.{ 0, 1, 2 }, &sli.b);
}

// Rubicon: Why I don't use packed struct here? I'd like to if I could, but zig compiler is lack of fixing bugs.
// I don't want to criticise these good guys who contributed to such open source project,
// but they are always making breaking changes while leaving critical bugs in packed struct for months.
// I do know people love working on new things, as I do. But leave critical bugs, which break key functions, for six months?
// See: https://github.com/ziglang/zig/issues?q=is%3Aissue+is%3Aopen+packed+struct+label%3Abug+sort%3Acreated-asc
// See: the long comment inside `Peer.handshakeInit`.
pub const HandshakeInitialisation = struct {
    msgType: u8,
    reserved: [3]u8 = .{ 0, 0, 0 },
    senderIndex: u32,
    unencryptedEphemeral: [32]u8,
    encryptedStatic: [32 + 16]u8,
    encryptedTimestamp: [12 + 16]u8,
    mac1: [16]u8,
    mac2: [16]u8,

    const Self = @This();

    pub fn fill(self: Self, buf: []u8) []const u8 {
        return fillFromStruct(self, buf);
    }

    pub fn read(buf: []u8) Self {
        return readToStruct(Self, buf);
    }

    pub fn bufferSize() usize {
        return fillSize(Self);
    }
};

pub const HandshakeResponse = struct {
    msgType: u8,
    reserved: [3]u8 = .{ 0, 0, 0 },
    senderIndex: u32,
    receiverIndex: u32,
    unencryptedEphemeral: [32]u8,
    encryptedNothing: [0 + 16]u8,
    mac1: [16]u8,
    mac2: [16]u8,

    const Self = @This();

    pub fn fill(self: Self, buf: []u8) []const u8 {
        return fillFromStruct(self, buf);
    }

    pub fn read(buf: []u8) Self {
        return readToStruct(Self, buf);
    }

    pub fn bufferSize() usize {
        return fillSize(Self);
    }
};

const Timer = struct {
    lastTimeRun: i64 = 0,
    step: i64,

    const Self = @This();

    fn init(initialTime: i64, step: i64) Self {
        return Self {
            .lastTimeRun = initialTime,
            .step = step,
        };
    }

    fn update(self: *Self, current: i64) bool {
        if ((self.lastTimeRun + self.step) < current) {
            self.lastTimeRun += self.step;
            return true;
        } else {
            return false;
        }
    }

    fn reset(self: *Self, current: i64) void {
        self.lastTimeRun = current;
    }
};

pub const Peer = struct {
    publicKey: PublicKey,
    identity: u64,
    endpoint: ?std.net.Address,
    configEndpoint: ?std.net.Address,
    lastReceivedTime: i64, // Updated by interface
    lastSentTime: i64, // Updated by interface
    senderId: u32,
    handshake: HandshakeState,
    rekeyAttemptTimer: Timer = undefined, // Used by interface

    const Self = @This();

    pub fn init(publicKey: PublicKey, identity: u64, senderId: u32) Self {
        return Self{
            .publicKey = publicKey,
            .identity = identity,
            .lastReceivedTime = 0,
            .lastSentTime = 0,
            .senderId = senderId,
            .handshake = undefined,
            .endpoint = null,
            .configEndpoint = null,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.endpoint) |endpoint| {
            endpoint.deinit();
        }
    }

    pub const Cookie = struct {
        taste: [16]u8,
        receivedTime: u64,
    };

    pub const HandshakeState = union(enum) {
        No: void,
        Shaking: ShakingState,
        Shaked: ShakedState,
    };

    pub const ShakingState = struct {
        hash: [32]u8,
        chainingKey: [32]u8,
        ephemeralKeypair: utils.Keypair,
        cookie: ?Cookie,
        receiverId: u32,
        stateStartedTime: i64 = 0, // Set by interface
        isInitiator: bool = false,
    };

    pub const ShakedState = struct {
        sendingKey: [32]u8,
        receivingKey: [32]u8,
        sendingKeyCounter: u64,
        receivingKeyCounter: u64,
        receiverId: u32,
        stateStartedTime: i64 = 0, // Set by interface
        isInitiator: bool = false,
    };

    pub fn resetHandshake(self: *Self) *ShakingState {
        self.handshake = HandshakeState{ .Shaking = .{
            .hash = [_]u8{0} ** 32,
            .chainingKey = [_]u8{0} ** 32,
            .ephemeralKeypair = utils.dhGen(),
            .cookie = null,
            .receiverId = 0,
        } };
        self.senderId = utils.random.intRangeAtMost(u32, 1, std.math.maxInt(u32));
        return &self.handshake.Shaking;
    }

    pub const HandshakeInitOptions = struct {
        initiatorPriKey: *const PrivateKey,
        initiatorPubKey: *const PublicKey,
    };

    pub const HANDSHAKE_INIT_MSG_SIZE = 148;
    pub const HANDSHAKE_RESPONSE_MSG_SIZE = 92;

    pub fn handshakeInit(self: *Self, options: HandshakeInitOptions) HandshakeInitialisation {
        var buf: HandshakeInitialisation = undefined;
        var state = self.resetHandshake();
        state.isInitiator = true;
        var hash: *[32]u8 = &state.hash;
        var cK: *[32]u8 = &state.chainingKey;
        mem.copy(u8, cK, utils.CONSTRUCTION_HASH);
        hash = utils.hashParts(hash, .{ utils.CONSTRUCTION_HASH_AND_IDENTIFIER_THEN_HASH, &self.publicKey });
        buf.msgType = 0x1;
        buf.senderIndex = mem.nativeToLittle(u32, self.senderId);
        {
            // Bug: directly use '&'' for pointer of buf.unencryptedEphemeral cause compiler crash:
            // * thread #1, name = 'zig', stop reason = signal SIGSEGV: invalid address (fault address: 0x0)
            //   * frame #0: 0x0000000007462904 zig`llvm::PointerType::get(llvm::Type*, unsigned int) + 20
            //     frame #1: 0x000000000342a35c zig`llvm::GetElementPtrInst::getGEPReturnType(llvm::Type*, llvm::Value*, llvm::ArrayRef<llvm::Value*>) + 76
            //     frame #2: 0x0000000003440dae zig`llvm::IRBuilderBase::CreateInBoundsGEP(llvm::Type*, llvm::Value*, llvm::ArrayRef<llvm::Value*>, llvm::Twine const&) + 270
            //     frame #3: 0x00000000073819ec zig`LLVMBuildInBoundsGEP + 76
            //     frame #4: 0x00000000032d5502 zig`ir_render(CodeGen*, ZigFn*) + 1618
            //     frame #5: 0x00000000032cab8b zig`do_code_gen(CodeGen*) + 2171
            //     frame #6: 0x00000000032c7eae zig`codegen_build_object(CodeGen*) + 3310
            //     frame #7: 0x00000000032bff28 zig`zig_stage1_build_object + 2392
            //     frame #8: 0x0000000002f96213 zig`Compilation.processOneJob + 78307
            //     frame #9: 0x0000000002f7907c zig`Compilation.update + 4268
            //     frame #10: 0x0000000002f39aaf zig`main.updateModule + 31
            //     frame #11: 0x0000000002f0f185 zig`main.buildOutputType + 78757
            //     frame #12: 0x0000000002ef0df4 zig`main + 2212
            //     frame #13: 0x000000000762fd3a zig`libc_start_main_stage2 + 41
            //     frame #14: 0x0000000002eef5b6 zig`_start + 22
            mem.copy(u8, &buf.unencryptedEphemeral, &state.ephemeralKeypair.public);
            // Rubicon: I fix it. It's a bug in packed struct if it have array.
            // Don't delete my comment, leave it for history unless this piece of code should be deleted. And, yes, I am ANGRY (See the comment above `HandshakeInitialisation`).
            // I'd like to see how long it takes before they fix this bug. (I saw one issue from six months ago in 2 Dec. 2021)
            // @memcpy(&buf.unencryptedEphemeral, &state.ephemeralKeypair.public, 32);
        }
        hash = utils.hashParts(hash, .{ hash, &buf.unencryptedEphemeral });
        cK = utils.hmac(cK, cK, &buf.unencryptedEphemeral);
        cK = utils.hmac(cK, cK, &.{0x1});
        var temp: [32]u8 = undefined;
        var key: [32]u8 = undefined;
        _ = utils.hmac(&temp, cK, &utils.dh(&state.ephemeralKeypair.private, &self.publicKey));
        cK = utils.hmac(cK, &temp, &.{0x1});
        _ = utils.hmacParts(&key, &temp, .{ cK, &.{0x2} });
        _ = utils.aead(&buf.encryptedStatic, &key, 0, options.initiatorPubKey, hash) catch unreachable;
        hash = utils.hashParts(hash, .{ hash, &buf.encryptedStatic });
        _ = utils.hmac(&temp, cK, &utils.dh(options.initiatorPriKey, &self.publicKey));
        cK = utils.hmac(cK, &temp, &.{0x1});
        _ = utils.hmacParts(&key, &temp, .{ cK, &.{0x2} });
        var timestamp = utils.timestamp(null);
        _ = utils.aead(&buf.encryptedTimestamp, &key, 0, &timestamp, hash) catch unreachable;
        hash = utils.hashParts(hash, .{ hash, &buf.encryptedTimestamp });
        // Update mac1 and mac2
        _ = utils.hashParts(&temp, .{ utils.LABEL_MAC1, &self.publicKey });
        _ = utils.mac(@ptrCast(*[16]u8, &buf.mac1), &temp, @ptrCast([*]u8, &buf)[0 .. @sizeOf(HandshakeInitialisation) - 32]);
        if (state.cookie) |*cookie| {
            if ((cookie.receivedTime + 120) > std.time.timestamp()) {
                _ = utils.mac(@ptrCast(*[16]u8, &buf.mac2), &cookie.taste, @ptrCast([*]u8, &buf)[0 .. @sizeOf(HandshakeInitialisation) - 16]);
            } else {
                std.crypto.utils.secureZero(u8, &buf.mac2);
            }
        }
        return buf;
    }

    pub const HandshakeRespondOptions = struct {
        responderPubKey: *const PublicKey,
        responderPriKey: *const PrivateKey,
    };

    pub fn handshakeRespond(self: *Self, initialMsg: *const HandshakeInitialisation, options: HandshakeRespondOptions) !HandshakeResponse {
        var buf: HandshakeResponse = undefined;
        // assert(initialMsg.msgType == 0x1);
        var state = self.resetHandshake();
        var hash = &state.hash;
        var cK = &state.chainingKey;
        // Sync states with initiator
        mem.copy(u8, cK, utils.CONSTRUCTION_HASH);
        hash = utils.hashParts(hash, .{ utils.CONSTRUCTION_HASH_AND_IDENTIFIER_THEN_HASH, options.responderPubKey });
        hash = utils.hashParts(hash, .{ hash, &initialMsg.unencryptedEphemeral });
        cK = utils.hmac(cK, cK, &initialMsg.unencryptedEphemeral);
        cK = utils.hmac(cK, cK, &.{0x1});
        var temp: [32]u8 = undefined;
        var key: [32]u8 = undefined;
        _ = utils.hmac(&temp, cK, &utils.dh(options.responderPriKey, &initialMsg.unencryptedEphemeral));
        cK = utils.hmac(cK, &temp, &.{0x1});
        _ = utils.hmacParts(&key, &temp, .{ cK, &.{0x2} });
        var decryptedStatic: [32]u8 = undefined;
        _ = try utils.deaead(&decryptedStatic, &key, 0, &initialMsg.encryptedStatic, hash);
        if (!mem.eql(u8, &decryptedStatic, &self.publicKey)) {
            return error.BadKey; // TODO: Use specific error set
        }
        hash = utils.hashParts(hash, .{ hash, &initialMsg.encryptedStatic });
        _ = utils.hmac(&temp, cK, &utils.dh(options.responderPriKey, &decryptedStatic));
        cK = utils.hmac(cK, &temp, &.{0x1});
        _ = utils.hmacParts(&key, &temp, .{ cK, &.{0x2} });
        var decryptedTimestamp: [12]u8 = undefined;
        _ = try utils.deaead(&decryptedTimestamp, &key, 0, &initialMsg.encryptedTimestamp, hash);
        hash = utils.hashParts(hash, .{ hash, &initialMsg.encryptedTimestamp });
        state.receiverId = mem.littleToNative(u32, initialMsg.senderIndex); // TODO: remove this swap for performance
        // Fill response
        buf.msgType = 0x2;
        buf.senderIndex = mem.nativeToLittle(u32, self.senderId);
        buf.receiverIndex = mem.nativeToLittle(u32, state.receiverId);
        mem.copy(u8, &buf.unencryptedEphemeral, &state.ephemeralKeypair.public);
        hash = utils.hashParts(hash, .{ hash, &buf.unencryptedEphemeral });
        cK = utils.hmac(cK, cK, &buf.unencryptedEphemeral);
        cK = utils.hmac(cK, cK, &.{0x1});
        cK = utils.hmac(cK, cK, &utils.dh(&state.ephemeralKeypair.private, &initialMsg.unencryptedEphemeral));
        cK = utils.hmac(cK, cK, &.{0x1});
        cK = utils.hmac(cK, cK, &utils.dh(&state.ephemeralKeypair.private, &self.publicKey));
        cK = utils.hmac(cK, cK, &.{0x1});
        const presharedKey = mem.zeroes([32]u8); // We don't use pre-shared key now.
        _ = utils.hmac(&temp, cK, &presharedKey);
        cK = utils.hmac(cK, &temp, &.{0x1});
        var temp2: [32]u8 = undefined;
        _ = utils.hmacParts(&key, &temp, .{ &temp2, &.{0x3} });
        hash = utils.hashParts(hash, .{ hash, &temp2 });
        _ = try utils.aead(&buf.encryptedNothing, &key, 0, &.{}, hash);
        hash = utils.hashParts(hash, .{ hash, &buf.encryptedNothing });
        // Update mac1 and mac2
        _ = utils.hashParts(&temp, .{ utils.LABEL_MAC1, &self.publicKey });
        _ = utils.mac(@ptrCast(*[16]u8, &buf.mac1), &temp, @ptrCast([*]u8, &buf)[0 .. @sizeOf(HandshakeResponse) - 32]);
        if (state.cookie) |*cookie| {
            if ((cookie.receivedTime + 120) > std.time.timestamp()) {
                _ = utils.mac(@ptrCast(*[16]u8, &buf.mac2), &cookie.taste, @ptrCast([*]u8, &buf)[0 .. @sizeOf(HandshakeInitialisation) - 16]);
            } else {
                std.crypto.utils.secureZero(u8, &buf.mac2);
            }
        }
        // Update state to Shaked
        var shakedState = ShakedState{
            .sendingKey = undefined,
            .receivingKey = undefined,
            .sendingKeyCounter = 0,
            .receivingKeyCounter = 0,
            .receiverId = initialMsg.senderIndex,
            .isInitiator = state.isInitiator,
        };
        _ = utils.hmac(&temp, cK, &.{});
        _ = utils.hmac(&temp2, &temp, &.{0x1});
        var temp3: [32]u8 = undefined;
        _ = utils.hmacParts(&temp3, &temp, .{ &temp2, &.{0x2} });
        mem.copy(u8, &shakedState.sendingKey, &temp2);
        mem.copy(u8, &shakedState.receivingKey, &temp3);
        self.handshake = HandshakeState{ .Shaked = shakedState };
        return buf;
    }

    pub fn receiveHandshakeResponse(self: *Self, msg: *HandshakeResponse, options: HandshakeInitOptions) !void {
        var state = self.handshake.Shaking;
        var cK: *[32]u8 = &state.chainingKey;
        var hash: *[32]u8 = &state.hash;
        state.receiverId = mem.littleToNative(u32, msg.senderIndex);
        hash = utils.hashParts(hash, .{ hash, &msg.unencryptedEphemeral });
        cK = utils.hmac(cK, cK, &msg.unencryptedEphemeral);
        cK = utils.hmac(cK, cK, &.{0x1});
        cK = utils.hmac(cK, cK, &utils.dh(&state.ephemeralKeypair.private, &msg.unencryptedEphemeral));
        cK = utils.hmac(cK, cK, &.{0x1});
        cK = utils.hmac(cK, cK, &utils.dh(options.initiatorPriKey, &msg.unencryptedEphemeral));
        cK = utils.hmac(cK, cK, &.{0x1});
        const presharedKey = mem.zeroes([32]u8); // We don't use pre-shared key now.
        var temp: [32]u8 = undefined;
        _ = utils.hmac(&temp, cK, &presharedKey);
        cK = utils.hmac(cK, &temp, &.{0x1});
        var temp2: [32]u8 = undefined;
        var key: [32]u8 = undefined;
        _ = utils.hmacParts(&key, &temp, .{ &temp2, &.{0x3} });
        hash = utils.hashParts(hash, .{ hash, &temp2 });
        var nothingBuf: [1]u8 = undefined;
        _ = try utils.deaead(&nothingBuf, &key, 0, &msg.encryptedNothing, hash);
        hash = utils.hashParts(hash, .{ hash, &msg.encryptedNothing });
        // Update state to Shaked
        var shakedState = ShakedState{
            .sendingKey = undefined,
            .receivingKey = undefined,
            .sendingKeyCounter = 0,
            .receivingKeyCounter = 0,
            .receiverId = msg.senderIndex,
            .isInitiator = state.isInitiator,
        };
        _ = utils.hmac(&temp, cK, &.{});
        _ = utils.hmac(&temp2, &temp, &.{0x1});
        var temp3: [32]u8 = undefined;
        _ = utils.hmacParts(&temp3, &temp, .{ &temp2, &.{0x2} });
        mem.copy(u8, &shakedState.sendingKey, &temp3);
        mem.copy(u8, &shakedState.receivingKey, &temp2);
        self.handshake = HandshakeState{ .Shaked = shakedState };
    }

    /// Make a data packet. `data` should padded to ensure the length is multiple of 16 bytes.
    /// The length of buffer should be at least data's length + 32.
    /// You must ensure the `buf` has more 32 bytes to data, or undefined behaivour might be triggered.
    pub fn sendRaw(self: *Self, buf: []u8, data: []const u8) []const u8 {
        assert(data.len % 16 == 0);
        var header: [16]u8 = undefined;
        header[0] = 0x3;
        mem.set(u8, header[1..4], 0);
        mem.writeInt(u32, header[4..8], self.handshake.Shaked.receiverId, .Little);
        self.handshake.Shaked.sendingKeyCounter += 1;
        const counter = self.handshake.Shaked.sendingKeyCounter;
        mem.writeInt(u64, header[8..16], counter, .Little);
        _ = utils.aead(buf[16 .. data.len + 32], &self.handshake.Shaked.sendingKey, counter, data, null) catch unreachable;
        mem.copy(u8, buf[0..16], &header);
        return buf[0 .. data.len + 32];
    }

    pub const ReceiveError = error{
        BadReceiver,
        BadCounter,
        Crypto,
    };

    pub fn receiveRaw(self: *Self, buf: []u8, packet: []const u8) ReceiveError![]const u8 {
        assert(packet.len % 16 == 0);
        assert(packet[0] == 0x3);
        var receiverId = mem.readInt(u32, packet[4..8], .Little);
        if (receiverId != self.senderId) {
            return ReceiveError.BadReceiver;
        }
        var state = &self.handshake.Shaked;
        const counter = state.receivingKeyCounter;
        const remoteCounter = mem.readInt(u64, packet[8..16], .Little);
        if (remoteCounter > counter) {
            state.receivingKeyCounter = remoteCounter;
        } else if ((std.math.absInt(@intCast(i64, remoteCounter) - @intCast(i64, counter)) catch unreachable) > 2000) {
            return ReceiveError.BadCounter;
        }
        _ = try utils.deaead(buf[0 .. packet.len - 32], &self.handshake.Shaked.receivingKey, remoteCounter, packet[16..packet.len], null) catch ReceiveError.Crypto;
        return buf[0 .. packet.len - 32];
    }
};

test "Peer can correctly handshake" {
    const t = std.testing;
    const kssid = @import("kssid.zig");
    var idgen = kssid.Generator.init();
    var aliceKeyP = try std.crypto.dh.X25519.KeyPair.create(null);
    var bobKeyP = try std.crypto.dh.X25519.KeyPair.create(null);
    var alice = Peer.init(aliceKeyP.public_key, idgen.generate(), 1);
    var bob = Peer.init(bobKeyP.public_key, idgen.generate(), 2);
    var handshakeInit: HandshakeInitialisation = alice.handshakeInit(.{
        .initiatorPubKey = &bobKeyP.public_key,
        .initiatorPriKey = &bobKeyP.secret_key,
    });
    var handshakeResponse = try bob.handshakeRespond(&handshakeInit, .{
        .responderPriKey = &aliceKeyP.secret_key,
        .responderPubKey = &aliceKeyP.public_key,
    });
    try alice.receiveHandshakeResponse(&handshakeResponse, .{
        .initiatorPubKey = &bobKeyP.public_key,
        .initiatorPriKey = &bobKeyP.secret_key,
    });

    const DATA = "Hello World, man";
    var buf: [DATA.len + 32]u8 = undefined;
    _ = alice.sendRaw(&buf, DATA);
    var received = try bob.receiveRaw(&buf, &buf);
    try t.expectEqualStrings(DATA, received);
}

const udp = @import("udp.zig");

/// The WireGuard Interface. It is not thread-safe.
/// It's recommended to use interface with sperarated thread.
///     var wg: Interface = Interface.init(&pub, &pri, std.net.Address.resolveIp("0.0.0.0", 57127), &allocator);
///     try wg.socket.spawnThread();
pub const Interface = struct {
    privateKey: PrivateKey,
    publicKey: PublicKey,
    peers: std.ArrayList(*Peer),
    alloc: *Allocator,
    socket: *udp.Socket,
    eventQ: std.PriorityQueue(EventSchedule),
    currentTime: i64 = 0, // ms
    rekeyTimeout: i64 = 15 * std.time.ms_per_s, // ms
    rand: std.rand.Random,
    listenAddress: std.net.Address,
    keepaliveTimeout: i64 = 5 * std.time.ms_per_s, // ms
    rejectAfterTime: i64 = 180 * std.time.ms_per_s,
    rekeyAfterMessages: u64 = std.math.maxInt(u64) / 2,
    rekeyAfterTime: i64 = 120 * std.time.ms_per_s,
    rekeyAttemptTime: i64 = 60 * std.time.ms_per_s,

    const Self = @This();

    const SendEvent = struct {
        peer: *Peer,
        buf: []u8,
        data: []const u8,
        alloc: ?*Allocator,
    };

    const InitHandshakeEvent = struct {
        peer: *Peer,
        endpoint: std.net.Address,
    };

    const Event = union(enum) {
        Send: SendEvent,
        InitHandshake: InitHandshakeEvent,
    };

    const EventSchedule = struct {
        event: Event,
        expectedTime: u64,
        retried: u8 = 0,

        pub fn compare(self: *Self, other: *Self) std.math.Order {
            return std.math.order(self.expectedTime, other.expectedTime);
        }

        pub fn comparePriority(self: *Self, other: *Self) std.math.Order {
            return compare(self, other).invert();
        }
    };

    /// Maintain states for interface.
    /// You should call this function repeatly to maintain interface infomation.
    pub fn doRoutine(self: *Self) !void {
        self.currentTime = std.time.milliTimestamp();
        for (self.peers.items) |peer| {
            if (peer.handshake == .Shaked) {
                var state = &peer.handshake.Shaked;
                if (self.currentTime > (state.stateStartedTime + (self.rejectAfterTime * 3))) {
                    peer.handshake = .No;
                }
            } else if (peer.handshake == .Shaking) {
                if (self.currentTime > (peer.handshake.Shaking.stateStartedTime + (self.rejectAfterTime * 3))) {
                    peer.handshake = .No;
                }
            }

            if (peer.rekeyAttemptTimer.update(self.currentTime)) {
                var inList = std.ArrayList(u64).init(self.alloc);
                defer inList.deinit();
                for (self.eventQ.items) |sch, i| {
                    if (sch.event == .Send and sch.event.Send.peer == peer) {
                        try inList.append(i);
                    }
                }
                for (inList.items) |index, i| {
                    _ = self.eventQ.removeIndex(index-i);
                }
                self.tryHandshake(peer);
            }
        }

        self.handleEvent();
    }

    /// Run `doRoutine` then run `socket.enter`.
    pub fn enter(self: *Self, timeout: i32) !void {
        try self.doRoutine();
        self.enter(timeout);
    }

    pub fn addPeer(self: *Self, peer: *Peer) Allocator.Error!void {
        peer.rekeyAttemptTimer = Timer.init(self.currentTime, self.rekeyAttemptTime);
        try self.peers.append(peer);
    }

    /// the queue is not thread-safe.
    fn hasHandshakeInQueueFor(self: *Self, peer: *Peer) bool {
        for (self.eventQ.items) |sched| {
            if (sched.event == .InitHandshake and sched.evnet.InitHandshake.peer == peer) {
                return true;
            }
        }
        return false;
    }

    fn tryHandshake(self: *Self, peer: *Peer) Allocator.Error!void {
        if (!self.hasHandshakeInQueueFor(peer)) {
            if (peer.endpoint) |endpoint| {
                try self.scheduleHandshake(peer, endpoint);
            } else if (peer.configEndpoint) |configEndpoint| {
                try self.scheduleHandshake(peer, configEndpoint);
            }
        }
    }

    fn handleEvent(self: *Self) void {
        while (self.eventQ.peek()) |schedule| {
            if (self.currentTime > schedule.expectedTime) {
                _ = self.eventQ.remove();
                defer self.alloc.destroy(schedule);
                switch (schedule.event) {
                    .Send => |*ev| {
                        ev.peer.rekeyAttemptTimer.reset(self.currentTime);
                        self.sendDataPacket(ev) catch |e| {
                            switch (e) {
                                InternalSendError.PeerNotReady => {
                                    if (schedule.retried <= 10) {
                                        schedule.retried += 1;
                                        schedule.expectedTime = self.currentTime + self.getJitter();
                                        self.tryHandshake() catch {};
                                        var copy = self.alloc.dupe(@TypeOf(schedule), schedule) catch return;
                                        self.eventQ.add(copy) catch {
                                            self.alloc.destroy(copy);
                                        };
                                        return;
                                    }
                                },
                            }
                            return;
                        };
                        if (ev.peer.handshake == .Shaked) {
                            var state = &ev.peer.handshake.Shaked;
                            if (state.sendingKeyCounter > self.rekeyAfterMessages) {
                                self.tryHandshake(ev.peer) catch {};
                            } else if (state.isInitiator and self.currentTime > (state.stateStartedTime + self.rekeyAfterTime)) {
                                self.tryHandshake(ev.peer) catch {};
                            }
                        }
                    },
                    .InitHandshake => |ev| {
                        self.doHandshakeInit(ev.peer, ev.endpoint) catch {
                            if (schedule.retried <= 10) {
                                schedule.retried += 1;
                            } else {
                                return;
                            }
                            schedule.expectedTime = self.currentTime + self.rekeyTimeout + self.getJitter();
                            var copy = self.alloc.dupe(@TypeOf(schedule), schedule) catch return;
                            self.evnetQ.add(copy) catch {
                                self.alloc.destroy(copy);
                            };
                            return;
                        };
                    },
                }
            }
        }
    }

    pub fn init(publicKey: PublicKey, privateKey: PrivateKey, listenAddr: std.net.Address, alloc: *Allocator) !Self {
        var socket = try alloc.create(udp.Socket);
        errdefer alloc.destroy(socket);
        socket.* = try udp.Socket.open(alloc);
        try socket.bind(listenAddr);
        var self = Self{
            .privateKey = privateKey,
            .publicKey = publicKey,
            .peers = std.ArrayList(Peer).init(alloc),
            .alloc = alloc,
            .socket = null,
            .eventQ = std.PriorityQueue(*EventSchedule).init(alloc, EventSchedule.comparePriority),
            .rand = std.crypto.random.*,
            .listenAddress = listenAddr,
        };
        return self;
    }

    fn getJitter(self: *Self) i64 {
        return self.rand.intRangeAtMost(i64, 0, 333);
    }

    pub fn deinit(self: *Self) void {
        self.socket.deinit(); // Socket.deinit will shutdown the thread if it has one
        while (self.eventQ.removeOrNull()) |evs| {
            self.alloc.destroy(evs);
        }
        self.eventQ.deinit();
        self.alloc.destroy(self.socket);
        for (self.peers.items) |p| {
            self.alloc.destroy(p);
        }
        self.peers.deinit();
    }

    /// Exact remote static public key from initial handshake message. Copied from Peer.handshakeRespond.
    /// The static public key can be used to find related Peer.
    fn getDecryptedStaticFromInitialHandshake(self: *const Self, initialMsg: *const HandshakeInitialisation) PublicKey {
        var hashBuf = mem.zeroes([32]u8);
        var cKBuf = mem.zeroes([32]u8);
        var hash = hashBuf;
        var cK = cKBuf;
        // Sync states with initiator
        mem.copy(u8, cK, utils.CONSTRUCTION_HASH);
        hash = utils.hashParts(hash, .{ utils.CONSTRUCTION_HASH_AND_IDENTIFIER_THEN_HASH, &self.publicKey });
        hash = utils.hashParts(hash, .{ hash, &initialMsg.unencryptedEphemeral });
        cK = utils.hmac(cK, cK, &initialMsg.unencryptedEphemeral);
        cK = utils.hmac(cK, cK, &.{0x1});
        var temp: [32]u8 = undefined;
        var key: [32]u8 = undefined;
        _ = utils.hmac(&temp, cK, &utils.dh(&self.privateKey, &initialMsg.unencryptedEphemeral));
        cK = utils.hmac(cK, &temp, &.{0x1});
        _ = utils.hmacParts(&key, &temp, .{ cK, &.{0x2} });
        var decryptedStatic: [32]u8 = undefined;
        _ = try utils.deaead(&decryptedStatic, &key, 0, &initialMsg.encryptedStatic, hash);
        hash = utils.hashParts(hash, .{ hash, &initialMsg.encryptedStatic });
        _ = utils.hmac(&temp, cK, &utils.dh(&self.privateKey, &decryptedStatic));
        cK = utils.hmac(cK, &temp, &.{0x1});
        _ = utils.hmacParts(&key, &temp, .{ cK, &.{0x2} });
        var decryptedTimestamp: [12]u8 = undefined;
        _ = try utils.deaead(&decryptedTimestamp, &key, 0, &initialMsg.encryptedTimestamp, hash);
        hash = utils.hashParts(hash, .{ hash, &initialMsg.encryptedTimestamp });
        return decryptedStatic;
    }

    pub fn getPeerByPublicKey(self: *Self, static: *const PublicKey) ?*Peer {
        for (self.peers.items) |peer| {
            if (mem.eql(u8, &peer.publicKey, static)) {
                return peer;
            }
        }
        return null;
    }

    pub fn getPeerById(self: *Self, id: u64) ?*Peer {
        for (self.peers.items) |peer| {
            if (peer.id == id) {
                return peer;
            }
        }
        return null;
    }

    pub fn getPeerByReceiverId(self: *Self, receiverId: u32) ?*Peer {
        for (self.peers.items) |peer| {
            if (peer.senderId == receiverId) {
                return peer;
            }
        }
        return null;
    }

    pub fn getReceiverIdFromDataMessages(buf: []const u8) u32 {
        return std.PackedIntSliceEndian(u8, .Little).init(buf[2..6], 4).sliceCastEndian(u32, nativeEndianess).get(0);
    }

    pub const ReadDetails = union(enum) {
        Ignored: void,
        Handshake: void,
        Data: struct {
            data: []const u8,
            srcAddress: std.net.Address,
            peer: *Peer,
        },
    };

    pub const ReadError = error{
        BadPacket,
        UnknownPeer,
    } || Allocator.Error;

    /// Read message from `buf` and handle this message.
    fn readBuf(self: *Self, buf: []u8, srcAddress: std.net.Address) ReadError!ReadDetails {
        switch (buf[0]) {
            0x1 => {
                if (buf.len < HandshakeInitialisation.bufferSize()) {
                    return ReadError.BadPacket;
                }
                const msg = HandshakeInitialisation.read(buf);
                const remoteStaticPubKey = self.getDecryptedStaticFromInitialHandshake(&msg);
                if (self.getPeerByPublicKey(&remoteStaticPubKey)) |peer| {
                    peer.lastReceivedTime = self.currentTime;
                    const response = peer.handshakeRespond(&msg, .{
                        .responderPriKey = &self.privateKey,
                        .responderPubKey = &self.publicKey,
                    }) catch return ReadError.BadPacket;
                    peer.handshake.Shaked.stateStartedTime = self.currentTime;
                    var sendBuf = self.alloc.alloc(u8, HandshakeResponse.bufferSize()) catch return ReadError.OutOfMemory;
                    errdefer self.alloc.free(sendBuf);
                    response.fill(sendBuf);
                    try self.socket.send(srcAddress, sendBuf, self.alloc);
                    peer.lastSentTime = self.currentTime;
                    peer.endpoint = srcAddress;
                    return ReadDetails.Handshake;
                } else return ReadError.UnknownPeer;
            },
            0x2 => {
                if (buf.len >= HandshakeResponse.bufferSize()) {
                    const msg = HandshakeResponse.read(buf);
                    if (self.getPeerByReceiverId(mem.littleToNative(u32, msg.receiverId))) |peer| {
                        peer.lastReceivedTime = self.currentTime;
                        peer.receiveHandshakeResponse(&msg, .{
                            .initiatorPriKey = &self.privateKey,
                            .initiatorPubKey = &self.publicKey,
                        }) catch return ReadError.BadPacket; // TODO: handle error
                        peer.handshake.Shaked.stateStartedTime = self.currentTime;
                        peer.endpoint = srcAddress;
                    } else return ReadError.UnknownPeer;
                } else return ReadError.BadPacket;
                return ReadDetails.Handshake;
            },
            0x3 => {
                if (buf.len >= 16) {
                    const receiverId = getReceiverIdFromDataMessages(buf);
                    if (self.getPeerByReceiverId(receiverId)) |peer| {
                        var data = peer.receiveRaw(buf, buf) catch ReadError.BadPacket;
                        peer.lastReceivedTime = self.currentTime;
                        if (self.currentTime > (peer.lastSentTime + self.keepaliveTimeout)) {
                            self.sendEmptyPacket(peer) catch {};
                        }
                        if (peer.handshake == .Shaked) {
                            var state = &peer.handshake.Shaked;
                            var newHandshakeIn = self.rekeyAfterTime - self.keepaliveTimeout - self.rekeyTimeout;
                            if (state.isInitiator and (self.currentTime > (state.stateStartedTime + newHandshakeIn))) {
                                self.tryHandshake(peer);
                            }
                        }
                        return ReadDetails{ .Data = .{
                            .data = data,
                            .srcAddress = srcAddress,
                            .peer = peer,
                        } };
                    } else return ReadError.UnknownPeer;
                }
            },
            0x4 => {
                return ReadDetails.Ignored;
            },
            else => {
                return ReadError.BadPacket;
            }, // ignore bad messages
        }
    }

    pub fn scheduleHandshake(self: *Self, peer: *Peer, endpoint: std.net.Address) Allocator.Error!void {
        var evsched = try self.alloc.create(EventSchedule);
        errdefer self.alloc.destroy(evsched);
        var ev = &evsched.event;
        ev.InitHandshake = InitHandshakeEvent{
            .peer = peer,
            .endpoint = endpoint,
        };
        evsched.expectedTime = self.currentTime + self.getJitter();
        evsched.retried = 0;
        try self.eventQ.add(evsched);
    }

    pub fn doHandshakeInit(self: *Self, peer: *Peer, endpoint: std.net.Address) Allocator.Error!void {
        var buf = try self.alloc.alloc(u8, HandshakeInitialisation.bufferSize());
        errdefer self.alloc.free(buf);
        const msg = try peer.handshakeInit(.{
            .initiatorPriKey = &self.privateKey,
            .initiatorPubKey = &self.publicKey,
        });
        peer.handshake.Shaking.stateStartedTime = self.currentTime;
        try self.socket.send(endpoint, msg.fill(buf), self.alloc);
    }

    const InternalSendError = error{
        PeerNotReady,
    } || Allocator.Error;

    /// Actually send the data packet.
    fn sendDataPacket(self: *Self, event: *SendEvent) InternalSendError!void {
        if (event.peer.handshake == .Shaked) {
            if (self.endpoint) |endpoint| {
                var eData = event.peer.sendRaw(event.buf, event.data);
                try self.socket.send(endpoint, eData, event.alloc);
                event.peer.lastSentTime = self.currentTime;
                return;
            }
        }
        return InternalSendError.PeerNotReady;
    }

    /// Send an empty packet. Used to keep alive.
    fn sendEmptyPacket(self: *Self, peer: *Peer) InternalSendError!void {
        if (peer.handshake == .Shaked) {
            if (self.endpoint) |endpoint| {
                var buf = try self.alloc.alloc(u8, 32);
                var eData = peer.sendRaw(buf, &.{});
                try self.socket.send(endpoint, eData, self.alloc);
                peer.lastSentTime = self.currentTime;
                return;
            }
        }
        return InternalSendError.PeerNotReady;
    }

    pub fn send() void {
        // TODO: send
    }

    pub fn recv() void {
        // TODO: recv
    }
};
