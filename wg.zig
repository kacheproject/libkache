//! A custom WireGuard implementation working with Rope Protocol.
//! It does not works with IP, so could not be work with normal wireguard implementations.
const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const Allocator = mem.Allocator;
const crypto = @import("crypto.zig");

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

    const Header = packed struct { // Always use big-endiness
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
        return TAI64N {
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
        return TAI64N {
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
        var concated: [32+IDENTIFIER.len]u8 = undefined;
        mem.copy(u8, concated[0..32], CONSTRUCTION_HASH);
        mem.copy(u8, concated[32..32+IDENTIFIER.len], IDENTIFIER);
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
        return .{.private=kp.secret_key, .public=kp.public_key};
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
        std.crypto.hash.blake2.Blake2s128.hash(input, buf, .{.key = key});
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
    fn aead(buf: []u8, key: []const u8, counter: u64, plain: []const u8, auth: []const u8) ![]const u8 {
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

    fn deaead(buf: []u8, key: []const u8, counter: u64, secret: []const u8, auth: []const u8) ![]const u8 {
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

// Rubicon: Why I don't use packed struct here? I'd like to if I could, but zig compiler is lack of fixing bugs.
// I don't want to criticise these good guys who contributed to such open source project,
// but they are always making breaking changes while leaving critical bugs in packed struct for months.
// I do know people love working on new things, as I do. But leave critical bugs, which break key functions, for six months?
// See: https://github.com/ziglang/zig/issues?q=is%3Aissue+is%3Aopen+packed+struct+label%3Abug+sort%3Acreated-asc
// See: the long comment inside `Peer.handshakeInit`.
pub const HandshakeInitialisation = extern struct {
    msgType: u8,
    reserved: [3]u8 = .{0, 0, 0},
    senderIndex: u32,
    unencryptedEphemeral: [32]u8,
    encryptedStatic: [32+16]u8,
    encryptedTimestamp: [12+16]u8,
    mac1: [16]u8,
    mac2: [16]u8,
};

pub const HandshakeResponse = extern struct {
    msgType: u8,
    reserved: [3]u8 = .{0, 0, 0},
    senderIndex: u32,
    receiverIndex: u32,
    unencryptedEphemeral: [32]u8,
    encryptedNothing: [0+16]u8,
    mac1: [16]u8,
    mac2: [16]u8,
};

pub const Peer = struct {
    publicKey: PublicKey,
    identity: u64,
    endpoint: ?Endpoint,
    lastDataTransmittedTime: u64,
    senderId: u32,
    handshake: HandshakeState,

    const Self = @This();
    
    pub const Endpoint = struct {
        address: []const u8,
        alloc: ?*Allocator,

        pub fn deinit(self: *Endpoint) void {
            if (self.alloc) |alloc| {
                alloc.free(self.address);
            }
        }
    };

    pub fn init(publicKey: PublicKey, identity: u64, senderId: u32, endpoint: ?Endpoint) Self {
        return Self {
            .publicKey = publicKey,
            .identity = identity,
            .endpoint = endpoint,
            .lastDataTransmittedTime = 0,
            .senderId = senderId,
            .handshake = undefined,
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

    pub const HandshakeState = union(enum){
        Shaking: ShakingState,
        Shaked: ShakedState,
    };

    pub const ShakingState = struct {
        hash: [32]u8,
        chainingKey: [32]u8,
        ephemeralKeypair: utils.Keypair,
        cookie: ?Cookie,
        receiverId: u32,
    };

    pub const ShakedState = struct {
        sendingKey: [32]u8,
        receivingKey: [32]u8,
        sendingKeyCounter: u64,
        receivingKeyCounter: u64,
        receiverId: u32,
    };

    pub fn resetHandshake(self: *Self) *ShakingState {
        self.handshake = HandshakeState {
            .Shaking = .{
                .hash = [_]u8{0} ** 32,
                .chainingKey = [_]u8{0} ** 32,
                .ephemeralKeypair = utils.dhGen(),
                .cookie = null,
                .receiverId = 0,
            }
        };
        self.senderId = utils.random.intRangeAtMost(u32, 1, std.math.maxInt(u32));
        return &self.handshake.Shaking;
    }

    pub fn repleaceEndpoint(self: *Self, endpoint: ?Endpoint) void {
        var oldEndpoint = self.endpoint;
        self.endpoint = endpoint;
        if (oldEndpoint) |oldEnd| {
            oldEnd.deinit();
        }
    }

    pub const HandshakeInitOptions = struct {
        initiatorPriKey: *const PrivateKey,
        initiatorPubKey: *const PublicKey,
    };

    pub const HANDSHAKE_INIT_MSG_SIZE = 148;
    pub const HANDSHAKE_RESPONSE_MSG_SIZE = 92;


    pub fn handshakeInit(self: *Self, options: HandshakeInitOptions) !HandshakeInitialisation {
        var buf: HandshakeInitialisation = undefined;
        var state = self.resetHandshake();
        var hash: *[32]u8 = &state.hash;
        var cK: *[32]u8 = &state.chainingKey;
        _ = state; _ = cK; _ = hash; _ = options;
        mem.copy(u8, cK, utils.CONSTRUCTION_HASH);
        hash = utils.hashParts(hash, .{utils.CONSTRUCTION_HASH_AND_IDENTIFIER_THEN_HASH, &self.publicKey});
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
            // Rubicon: I fix it though using 'extern struct' with C ABI. It's a bug in packed struct if it have array.
            // Don't delete my comment, leave it for history unless this piece of code should be deleted. And, yes, I am ANGRY (See the comment above `HandshakeInitialisation`).
            // I'd like to see how long it takes before they fix this bug. (I saw one issue from six months ago in 2 Dec. 2021)
            // @memcpy(&buf.unencryptedEphemeral, &state.ephemeralKeypair.public, 32);
        }
        hash = utils.hashParts(hash, .{hash, &buf.unencryptedEphemeral});
        cK = utils.hmac(cK, cK, &buf.unencryptedEphemeral);
        cK = utils.hmac(cK, cK, &.{0x1});
        var temp: [32]u8 = undefined;
        var key: [32]u8 = undefined;
        _ = utils.hmac(&temp, cK, &utils.dh(&state.ephemeralKeypair.private, &self.publicKey));
        cK = utils.hmac(cK, &temp, &.{0x1});
        _ = utils.hmacParts(&key, &temp, .{cK, &.{0x2}});
        _ = try utils.aead(&buf.encryptedStatic, &key, 0, options.initiatorPubKey, hash);
        _ = utils.hmac(&temp, cK, &utils.dh(options.initiatorPriKey, &self.publicKey));
        cK = utils.hmac(cK, &temp, &.{0x1});
        _ = utils.hmacParts(&key, &temp, .{cK, &.{0x2}});
        var timestamp = utils.timestamp(null);
        _ = try utils.aead(&buf.encryptedTimestamp, &key, 0, &timestamp, &state.hash);
        hash = utils.hashParts(hash, .{hash, &buf.encryptedTimestamp});
        // Update mac1 and mac2
        _ = utils.hashParts(&temp, .{utils.LABEL_MAC1, &self.publicKey});
        _ = utils.mac(@ptrCast(*[16]u8, &buf.mac1), &temp, @ptrCast([*]u8, &buf)[0..@sizeOf(HandshakeInitialisation)-32]);
        if (state.cookie) |*cookie| {
            if ((cookie.receivedTime + 120) > std.time.timestamp()) {
                _ = utils.mac(@ptrCast(*[16]u8, &buf.mac2), &cookie.taste, @ptrCast([*]u8, &buf)[0..@sizeOf(HandshakeInitialisation)-16]);
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

    pub fn handshakeRespond(self: *Self, initialMsg: *HandshakeInitialisation, options: HandshakeRespondOptions) !HandshakeResponse {
        var buf: HandshakeResponse = undefined;
        // assert(initialMsg.msgType == 0x1);
        var state = self.resetHandshake();
        var hash = &state.hash;
        var cK = &state.chainingKey;
        _ = state; _= hash; _ = cK; _ = options; _ = initialMsg;
        // Sync states with initiator
        mem.copy(u8, cK, utils.CONSTRUCTION_HASH);
        hash = utils.hashParts(hash, .{utils.CONSTRUCTION_HASH_AND_IDENTIFIER_THEN_HASH, options.responderPubKey});
        hash = utils.hashParts(hash, .{hash, &initialMsg.unencryptedEphemeral});
        cK = utils.hmac(cK, cK, &initialMsg.unencryptedEphemeral);
        cK = utils.hmac(cK, cK, &.{0x1});
        var temp: [32]u8 = undefined;
        var key: [32]u8 = undefined;
        _ = utils.hmac(&temp, cK, &utils.dh(options.responderPriKey, @ptrCast(*[32]u8, &initialMsg.unencryptedEphemeral)));
        cK = utils.hmac(cK, &temp, &.{0x1});
        _ = utils.hashParts(&key, .{cK, &.{0x2}});
        var decryptedStatic: [32]u8 = undefined;
        _ = try utils.deaead(&decryptedStatic, &key, 0, &initialMsg.encryptedStatic, hash);
        if (mem.eql(u8, &decryptedStatic, options.responderPubKey)) {
            return error.BadKey; // TODO: Use specific error set
        }
        hash = utils.hashParts(hash, .{hash, &initialMsg.encryptedStatic});
        _ = utils.hmac(&temp, cK, &utils.dh(options.responderPriKey, &decryptedStatic));
        cK = utils.hmac(cK, &temp, &.{0x1});
        _ = utils.hashParts(&key, .{cK, &.{0x2}});
        var decryptedTimestamp: [12]u8 = undefined;
        _ = try utils.deaead(&decryptedTimestamp, &key, 0, &initialMsg.encryptedTimestamp, hash);
        state.receiverId = mem.littleToNative(u32, initialMsg.senderIndex); // TODO: remove this swap for performance
        // Fill response
        buf.msgType = 0x2;
        buf.senderIndex = mem.nativeToLittle(u32, self.senderId);
        buf.receiverIndex = mem.nativeToLittle(u32, state.receiverId);
        mem.copy(u8, &buf.unencryptedEphemeral, &state.ephemeralKeypair.public);
        hash = utils.hashParts(hash, .{hash, &buf.unencryptedEphemeral});
        cK = utils.hmac(cK, cK, &buf.unencryptedEphemeral);
        cK = utils.hmac(cK, cK, &.{0x1});
        cK = utils.hmac(cK, cK, &utils.dh(&state.ephemeralKeypair.private, @ptrCast(*[32]u8, &initialMsg.unencryptedEphemeral)));
        cK = utils.hmac(cK, cK, &.{0x1});
        cK = utils.hmac(cK, cK, &utils.dh(&state.ephemeralKeypair.private, &self.publicKey));
        cK = utils.hmac(cK, cK, &.{0x1});
        const presharedKey = mem.zeroes([32]u8); // We don't use pre-shared key now.
        _ = utils.hmac(&temp, cK, &presharedKey);
        cK = utils.hmac(cK, &temp, &.{0x1});
        var temp2: [32]u8 = undefined;
        _ = utils.hmacParts(&key, &temp, .{&temp2, &.{0x3}});
        hash = utils.hashParts(hash, .{hash, &temp2});
        _ = try utils.aead(&buf.encryptedNothing, &key, 0, &.{}, hash);
        hash = utils.hashParts(hash, .{hash, &buf.encryptedNothing});
        // Update mac1 and mac2
         _ = utils.hashParts(&temp, .{utils.LABEL_MAC1, &self.publicKey});
        _ = utils.mac(@ptrCast(*[16]u8, &buf.mac1), &temp, @ptrCast([*]u8, &buf)[0..@sizeOf(HandshakeResponse)-32]);
        if (state.cookie) |*cookie| {
            if ((cookie.receivedTime + 120) > std.time.timestamp()) {
                _ = utils.mac(@ptrCast(*[16]u8, &buf.mac2), &cookie.taste, @ptrCast([*]u8, &buf)[0..@sizeOf(HandshakeInitialisation)-16]);
            } else {
                std.crypto.utils.secureZero(u8, &buf.mac2);
            }
        }
        // Update state to Shaked
        var shakedState = ShakedState {
            .sendingKey = undefined,
            .receivingKey = undefined,
            .sendingKeyCounter = 0,
            .receivingKeyCounter = 0,
            .receiverId = initialMsg.senderIndex,
        };
        _ = utils.hmac(&temp, cK, &.{});
        _ = utils.hmac(&temp2, &temp, &.{0x1});
        var temp3: [32]u8 = undefined;
        _ = utils.hmacParts(&temp3, &temp, .{&temp2, &.{0x2}});
        mem.copy(u8, &shakedState.sendingKey, &temp2);
        mem.copy(u8, &shakedState.receivingKey, &temp3);
        self.handshake = HandshakeState {.Shaked = shakedState};
        return buf;
    }

    pub fn receiveHandshakeResponse(self: *Self, msg: *HandshakeResponse) !void {
        var state = self.handshake.Shaking;
        var cK: *[32]u8 = &state.chainingKey;
        var hash: *[32]u8 = &state.hash;
        _ = state; _ = cK; _ = hash; _ = msg;
        state.receiverId = mem.littleToNative(u32, msg.senderIndex);
        hash = utils.hashParts(hash, .{hash, &msg.unencryptedEphemeral});
        cK = utils.hmac(cK, cK, &msg.unencryptedEphemeral);
        cK = utils.hmac(cK, cK, &.{0x1});
        cK = utils.hmac(cK, cK, &utils.dh(&state.ephemeralKeypair.private, @ptrCast(*[32]u8, &msg.unencryptedEphemeral)));
        cK = utils.hmac(cK, cK, &.{0x1});
        cK = utils.hmac(cK, cK, &utils.dh(&state.ephemeralKeypair.private, &self.publicKey));
        cK = utils.hmac(cK, cK, &.{0x1});
        const presharedKey = mem.zeroes([32]u8); // We don't use pre-shared key now.
        var temp: [32]u8 = undefined;
        _ = utils.hmac(&temp, cK, &presharedKey);
        cK = utils.hmac(cK, &temp, &.{0x1});
        var temp2: [32]u8 = undefined;
        hash = utils.hashParts(hash, .{hash, &temp2});
        hash = utils.hashParts(hash, .{hash, &msg.encryptedNothing});
        // Update state to Shaked
        var shakedState = ShakedState {
            .sendingKey = undefined,
            .receivingKey = undefined,
            .sendingKeyCounter = 0,
            .receivingKeyCounter = 0,
            .receiverId = msg.senderIndex,
        };
        _ = utils.hmac(&temp, cK, &.{});
        _ = utils.hmac(&temp2, &temp, &.{0x1});
        var temp3: [32]u8 = undefined;
        _ = utils.hmacParts(&temp3, &temp, .{&temp2, &.{0x2}});
        mem.copy(u8, &shakedState.sendingKey, &temp2);
        mem.copy(u8, &shakedState.receivingKey, &temp3);
        self.handshake = HandshakeState {.Shaked = shakedState};
    }

    pub fn send(self: *Self) []const u8 {
        _ = self;
    }

    pub fn receive(self: *Self) ![]const u8 {
        _ = self;
    }
};

test "Peer can correctly handshake" {
    const t = std.testing;
    const kssid = @import("kssid.zig");
    var idgen = kssid.Generator.init();
    var aliceKeyP = try std.crypto.dh.X25519.KeyPair.create(null);
    var bobKeyP = try std.crypto.dh.X25519.KeyPair.create(null);
    var alice = Peer.init(aliceKeyP.public_key, idgen.generate(), 1, null);
    var bob = Peer.init(bobKeyP.public_key, idgen.generate(), 2, null);
    var handshakeInit: HandshakeInitialisation = try alice.handshakeInit(.{
        .initiatorPubKey = &bobKeyP.public_key,
        .initiatorPriKey = &bobKeyP.secret_key,
    });
    var handshakeResponse = try bob.handshakeRespond(&handshakeInit, .{
        .responderPriKey = &aliceKeyP.secret_key,
        .responderPubKey = &aliceKeyP.public_key,
    });
    try alice.receiveHandshakeResponse(&handshakeResponse);
    try t.expectEqualStrings(&alice.handshake.Shaked.sendingKey, &bob.handshake.Shaked.sendingKey);
    try t.expectEqualStrings(&alice.handshake.Shaked.receivingKey, &bob.handshake.Shaked.receivingKey);
}

pub const Interface = struct {
    privateKey: PrivateKey,
    publicKey: PublicKey,
    peers: std.ArrayList(Peer),

    const Self = @This();

    pub fn init(publicKey: PublicKey, privateKey: PrivateKey, alloc: *Allocator) Self {
        var self = Self {
            .privateKey = privateKey,
            .publicKey = publicKey,
            .peers = std.ArrayList(Peer).init(alloc),
        };
        return self;
    }

    pub fn deinit(self: *Self) void {
        self.peers.deinit();
    }

    pub fn readPacket(self: *Self) void {
        _ = self;
    }
};
