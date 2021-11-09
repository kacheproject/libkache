const std = @import("std");
const Allocator = std.mem.Allocator;

const zmq = @import("pkgs/zmq/zmq.zig");
const VecClock = @import("crdt.zig").VecClock;
const pn = @import("pn.zig");

const _l = std.log.scoped(.Rope);

const URI_MAX_LENGTH = 2048;
const DEFAULT_LEASE_TIME = 10; // seconds

fn getLeaseRenewTime(leaseTime: u64) u64 {
    return @floatToInt(u64, @intToFloat(f64, leaseTime) * 0.7);
}

pub const EventPub = struct {
    zRou: zmq.Socket,
    peers: std.ArrayList(*Peer),
    router: *Router,
    bindingEndpoints: std.ArrayList([]const u8),
    zRouMonitor: zmq.Socket,

    const Self = @This();
    const log = std.log.scoped(.RopeEventPub);

    pub const MSGFLAG_FORWARDED = @as(u8, 1) << 7;

    pub const MessageType = enum(u8) {
        Heartbeat = 0,
        Broadcast = 1,

        const MIN = 0;
        const MAX = 1;
    };

    pub const MessageError = error {
        BadMessage,
    };

    pub const Message = union(MessageType) {
        Heartbeat: HeartbeatMessage,
        Broadcast: BroadcastMessage,

        fn makeFirstFrame(alloc: *Allocator, typ_: MessageType) Allocator.Error!*zmq.Msg {
            var frame = try zmq.Frame.initValue(u8, @enumToInt(MessageType), alloc);
            var msg = try zmq.Msg.initPtr(frame, alloc);
            return msg;
        }

        fn readCommonFields(ptr: anytype, msg: *zmq.Msg) MessageError!void {
            const T = @TypeOf(ptr);
            const tInfo = @typeInfo(T);
            if (tInfo != .Pointer) @compileError("only accept pointers");

            if (@hasField(T, "flags")) {
                if (msg.getNext(1)) |f| {
                    if (f.frame.size() > 0) {
                        @field(ptr, "flags") = f.frame.data()[0];
                    } else return MessageError.BadMessage;
                } else return MessageError.BadMessage;
            } else @compileError("expect field 'flags' in structure");

            if (@hasField(T, "routerId") and @hasField(T, "routerClk")) {
                var clkf = head.getNext(2) orelse return MessageError.BadMessage;
                var clkUpdate = if (clkf.frame.size() == 128/8) fetch_clkup: {
                    break :fetch_clkup ClkUpdate.parse(flagsf.frame.readValue(u128));
                } else return MessageError.BadMessage;
                @field(ptr, "routerId") = clkUpdate[0];
                @field(ptr, "routerClk") = clkUpdate[1];
            } else @compileError("expect fields 'routerId' or 'routerClk' in structure");
        }
    };

    pub const ClkUpdate = struct {
        // clkupdate = router_id router_clk
        pub fn build(routerId: u64, clk: u64) u128 {
            return pn.toPortableInt(u128, std.PackedIntArray(u64, 2).init(.{routerId, clk}).sliceCast(u128).get(0));
        }

        pub fn parse(update: u128) [2]u64 {
            var orignalPack = pn.fromPortableInt(u128, update);
            var pack = std.PackedIntArray(u128, 1).initAllTo(orignalPack).sliceCast(u64);
            return .{pack.get(0), pack.get(1)};
        }
    };

    pub const Flags = struct {
        pub fn isForwarded(flags: u8) bool {
            return flags & MSGFLAG_FORWARDED > 0;
        }

        pub fn setForwarded(flags: u8, forwarded: bool) u8 {
            return if (forwarded) flags | MSGFLAG_FORWARDED else unreachable; // TODO: can unset forwarded
        }
    };

    pub const HeartbeatMessage = struct {
        // heartbeat = %x0 flags clkupdate version physicaltime
        // version = 1OTECT
        // flags = 1OTECT
        // physicaltime = 8OTECT
        // 1 + 1 + 1 + 16 + 8 = 27 bytes
        version: u8,
        flags: u8,
        physicalTime: u64,
        routerId: u64,
        routerClk: u64,


        pub fn build(self: *HeartbeatMessage, router: *Router) !*zmq.Msg {
            var head = try Message.makeFirstFrame(router.alloc, .Heartbeat);
            errdefer head.deinitAll();
            _ = try head.appendValue(u8, self.flags, router.alloc);
            _ = try head.appendValue(u128, ClkUpdate.build(self.routerId, self.routerClk), router.alloc);
            _ = try head.appendValue(u8, 2, router.alloc);
            _ = try head.appendValue(u64, pn.toPortableInt(u64, self.physicalTime), router.alloc);
            return head;
        }

        pub fn parse(head: *zmq.Msg) MessageError!HeartbeatMessage {
            var versionf = head.getNext(3) orelse return MessageError.BadMessage;
            var physicalTimef = head.getNext(4) orelse return MessageError.BadMessage;
            var ver = if (versionf.frame.size() > 0) fetch_ver: {
                break :fetch_ver flagsf.frame.data()[0];
            } else return MessageError.BadMessage;
            var pTime = if (physicalTimef.frame.size() == 64/8)
                physicalTimef.frame.readValue(u64)
                else return MessageError.BadMessage;
            var result = HeartbeatMessage {
                .version = ver,
                .flags = undefined,
                .physicalTime = pTime,
                .routerId = undefined,
                .routerClk = undefined,
            };
            try Message.readCommonFields(&result, head);
            return result;
        } 
    };

    pub const BroadcastMessage = struct {
        // broadcast = %x1 flags clkupdate event_name argument
        flags: u8,
        routerId: u64,
        routerClk: u64,
        eventName: []const u8,
        argument: []const u8,
        alloc: ?*Allocator = null,

        pub fn build(self: *BroadcastMessage, router: *Router, dataAlloc: *Allocator) !*zmq.Msg {
            var head = try Message.makeFirstFrame(router.alloc, .Broadcast);
            errdefer head.deinitAll();
            _ = try head.appendValue(u8, self.flags, router.alloc);
            _ = try head.appendValue(u128, ClkUpdate.build(self.routerId, self.routerClk), router.alloc);
            _ = try head.appendData(self.eventName, dataAlloc);
            _ = try head.appendData(self.argument, dataAlloc);
            return head;
        }

        pub fn parse(msg: *zmq.Msg, alloc: *Allocator) (MessageError||Allocator.Error)!BroadcastMessage {
            var result = BroadcastMessage {
                .flags = undefined,
                .routerId = undefined,
                .eventName = undefined,
                .argument = undefined,
                .routerClk = undefined,
            };
            try Message.readCommonFields(&result, msg);
            result.eventName = if (msg.getNext(3)) |f| fetchEventName: {
                break :fetchEventName try alloc.dupe(f.frame.data());
            } else return MessageError.BadMessage;
            errdefer alloc.free(result.eventName);
            result.argument = if (msg.getNext(4)) |f| fetchArg: {
                break :fetchArg try alloc.dupe(f.frame.data());
            } else return MessageError.BadMessage;
            errdefer alloc.free(result.argument);
            result.alloc = alloc;
            return result;
        }

        pub fn deinit(self: *BroadcastMessage) void {
            if (self.alloc) |alloc| {
                alloc.free(self.eventName);
                alloc.free(self.argument);
            }
        }
    };

    pub fn handleMessage(self: *Self, msg: Message, idMsg: *zmq.Msg) !void {
        switch (msg) {
            .Heartbeat => {},
            .Broadcast => {},
        }
    }

    fn receiveMessage(self: *Self, socket: *zmq.Socket) !?Message {
        var rawMsg = try zmq.Msg.recvFrom(socket, .{}, self.router.alloc);
        defer rawMsg.deinitAll();
        var typeInt = rawMsg.frame.data()[0];
        if (typeInt <= MessageType.MAX) {
            return switch(@intToEnum(MessageType, typeInt)) {
                .Heartbeat => Message {.Heartbeat = try HeartbeatMessage.parse(rawMsg)},
                .Broadcast => Message {.Broadcast = try BroadcastMessage.parse(rawMsg)},
            };
        } else {
            log.warn("unregonised type code: {}", .{typeInt});
            return null;
        }
    }

    fn receiveIdMessage(self: *Self, socket: *zmq.Socket) !*zmq.Msg {
        var idf = zmq.Frame.init();
        errdefer idf.deinit();
        _ = try socket.recvFrame(&idf, .{});
        if (socket.getRcvMore()) {
            var msg = try zmq.Msg.initPtr(idf, self.router.alloc);
            errdefer msg.deinitAll();
            try socket.recvIgnore(.{});
            try msg.appendEmpty(self.router.alloc);
            if (socket.getRcvMore()) {
                return msg;
            } else {
                return MessageError.BadMessage;
            }
        } else return MessageError.BadMessage;
    }

    pub fn init(router: *Router) Self {}

    pub fn socketHandler(self: *Self, socket: *zmq.Socket, time: u64) !void {
        if (socket == &self.zRou) {
            // TODO
        } else if (socket == &self.zRouMonitor) {
            // TODO
        }
    }

    pub fn dailyRoutine(self: *Self, time: u64) !void {
        // TODO
    }
};

/// Infomation about a physical address.
///
/// This structure use lease-style to measure the reachablity from local of a physical address.
/// lastReachable: when this physical address is reachable recently.
/// lastFound: when this physical address is found recently. See `WireFoundEvent`.
/// A _reachable_ physical address means this address could be reachable and used to transfer data.
/// A _found_ physical address means this address is found in network.
/// The two dimensions are decoupled. An address could be reachable and found, unreachable and found, unreachable and not found, even reachable but not found. 
/// 
/// To understand "reachable but not found", image such case:
/// Peer A just connect peer B and A send B a _ticktok event. Now B knows this address is reachable, but it does not be found in network.
/// Next step B broadcast _wire.found event. Now other peers C, D, E knowns the peer A with the address. As the view of any of C, D, E,
/// this address is found. Don't forget we use flooding to ensure messages reach every corner of the network.
/// C, D, or E's will forward finally the _wire.found message to B. Now B also found this peer in network and set correct lastFound.
pub const PhysicalAddress = struct {
    peerId: ?u64 = null,
    entryId: ?u64 = null,
    address: [:0]const u8,
    alloc: ?*Allocator,
    lastReachable: u64 = 0,
    lastFound: u64 = 0,
    lastDismiss: u64 = 0,
    promiseReachable: u64 = 0,

    const Self = @This();

    pub fn init(address: [:0]const u8, alloc: ?*Allocator) Self {
        return Self{
            .address = address,
            .alloc = alloc,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.alloc) |alloc| {
            alloc.free(self.address);
        }
    }

    pub fn maybeReachable(self: *Self, time: u64) bool {
        return (time < self.promiseReachable) and ((std.math.max(self.lastReachable, time) - std.math.min(self.lastReachable, time)) > 0);
    }

    pub fn isFound(self: *Self) bool {
        return self.lastDismiss < self.lastFound;
    }
};

pub const Peer = struct {
    id: u64,
    aliveUntil: u64 = 0,
    aliveOffest: u64 = 0,
    lastTickTock: u64 = 0,
    physicalTimeOffest: i8 = 0, // Offest could not > 30s

    const Self = @This();

    pub fn getRemoteTime(self: *Self, localTime: u64) u64 {
        return localTime + self.physicalTimeOffest;
    }

    pub fn setTimeOffest(self: *Self, remoteTime: u64, localTime: u64) void {
        self.physicalTimeOffest = remoteTime - localTime;
    }
};

pub const Entry = struct {
    address: u128,

    const Self = @This();

    pub fn init(address: u128) Self {
        return Self{ .address = address };
    }

    pub fn build(peerId: u64, entryId: u64) Self {
        const addr = std.PackedIntArray(u64, 2).init(.{ peerId, entryId }).sliceCast(u128).get(0);
        return Self.init(addr);
    }

    pub fn getPeerId(self: *Self) u64 {
        return std.PackedIntArray(u128, 1).initAllTo(self.address).sliceCast(u64).get(0);
    }

    pub fn getEntryId(self: *Self) u64 {
        return std.PackedIntArray(u128, 1).initAllTo(self.address).sliceCast(u64).get(1);
    }
};

pub const NetDb = struct {
    allAddresses: std.ArrayList(*PhysicalAddress),
    peers: std.AutoArrayHashMap(u64, Peer),
    services: std.StringArrayHashMap(Entry),
    alloc: *Allocator,

    const Self = @This();

    pub fn init(alloc: *Allocator) Self {
        return Self{
            .allAddresses = std.ArrayList(*PhysicalAddress).init(alloc),
            .peers = std.AutoArrayHashMap(u64, Peer).init(alloc),
            .services = std.StringArrayHashMap(Entry).init(alloc),
            .alloc = alloc,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.services.keys()) |key| {
            self.alloc.free(key);
        }
        for (self.allAddresses.items) |addr| {
            self.alloc.destroy(addr);
        }
        self.allAddresses.deinit();
        self.peers.deinit();
        self.services.deinit();
    }

    pub fn getPeer(self: *Self, id: u64) Allocator.Error!*Peer {
        if (self.peers.getPtr(id)) |target| {
            return target;
        } else {
            try self.peers.put(id, Peer{ .id = id });
            return self.peers.getPtr(id).?;
        }
    }

    pub fn hasPeer(self: *Self, id: u64) bool {
        return self.peers.contains(id);
    }

    pub fn getWireForPeer(self: *Self, id: u64, addr: []const u8) ?*PhysicalAddress {
        if (self.hasPeer(id)) {
            // for (self.allAddresses.items) |item| {
            //     if (id == item.peerId and std.mem.eql(u8, addr, item.address)) {
            //         return item;
            //     }
            // }
            // Rubicon: above have bug in zig 0.9.0+dev.1561
            // broken LLVM module found: PHI node entries do not match predecessors!
            //   %35 = phi i1 [ %27, %ForBody ], [ %34, %BoolAndTrue ], !dbg !36653
            // label %ForBody
            // label %CmpOptionalNonOptionalEnd
            // Instruction does not dominate all uses!
            // %27 = phi i1 [ false, %CmpOptionalNonOptionalOptionalNull ], [ %26, %CmpOptionalNonOptionalOptionalNotNull ], !dbg !36652
            // %35 = phi i1 [ %27, %ForBody ], [ %34, %BoolAndTrue ], !dbg !36653
            // looks related issue: https://github.com/ziglang/zig/issues/6059
            // compare optional value to non-optional value cause broken generated code
            for (self.allAddresses.items) |item| {
                if (item.peerId != null and id == item.peerId.? and std.mem.eql(u8, addr, item.address)) {
                    return item;
                }
            }
        }
        return null;
    }

    pub fn hasWireForPeer(self: *Self, id: u64, addr: []const u8) bool {
        return self.getWireForPeer(id, addr) != null;
    }

    /// Lookup physical address by address string.
    pub fn lookupByAddress(self: *Self, addr: []const u8, alloc: *Allocator) Allocator.Error![]*PhysicalAddress {
        var list = std.ArrayList(*PhysicalAddress).init(alloc);
        for (self.allAddresses.items) |paddr| {
            if (std.mem.eql(u8, paddr.address, addr)) {
                try list.append(paddr);
            }
        }
        return list.toOwnedSlice();
    }

    /// Lookup physical addresses by router id.
    /// If `noEntry` is `true`, only return the addresses which not linked to an entry.
    pub fn lookupById(self: *Self, routerId: u64, noEntry: bool, alloc: *Allocator) Allocator.Error![]*PhysicalAddress {
        var list = std.ArrayList(*PhysicalAddress).init(alloc);
        for (self.allAddresses.items) |paddr| {
            if (paddr.peerId == routerId and (noEntry and paddr.entryId == null)) {
                try list.append(paddr);
            }
        }
        return list.toOwnedSlice();
    }

    /// Lookup physical addresses by entry.
    pub fn lookupByEntry(self: *Self, entry: Entry, alloc: *Allocator) Allocator.Error![]*PhysicalAddress {
        var list = std.ArrayList(*PhysicalAddress).init(alloc);
        for (self.allAddresses.items) |paddr| {
            if (paddr.peerId == entry.device() and paddr.entryId == entry.entry()) {
                try list.append(paddr);
            }
        }
        return list.toOwnedSlice();
    }

    pub fn isPeerAlive(self: *Self, id: u64, currentTime: u64) bool {
        if (self.peers.getPtr(id)) |peer| {
            const peerPromise = peer.aliveUntil > currentTime;
            return peerPromise;
        } else {
            return false;
        }
    }

    pub fn isPeerReachable(self: *Self, id: u64, currentTime: u64) bool {
        var physicsPromise = false;
        for (self.allAddresses.items) |addr| {
            if (addr.routerId == id) {
                physicsPromise = physicsPromise or addr.maybeReachable(currentTime);
            }
        }
        return physicsPromise;
    }
};

fn posixTimestamp() u64 {
    return @intCast(u64, @divTrunc(std.time.milliTimestamp(), std.time.ms_per_s));
}

pub const Router = struct {
    zctx: zmq.Context,
    eventPub: EventPub,
    poller: zmq.Poller,
    clk: VecClock,
    alloc: *Allocator,
    myid: u64,
    zEvSideListen: zmq.Socket, // be used to update clock
    netdb: NetDb,

    const Self = @This();

    const Error = error{} || zmq.Error;

    const IOError = error{} || zmq.IOError;

    pub fn init(id: u64, alloc: *Allocator) (zmq.FileError || Error || Allocator.Error)!*Self {
        var result = try alloc.create(Self);
        var ctx = try zmq.Context.init();
        ctx.setOpt(.Blocky, bool, false);
        result.* = Self {
            .zctx = ctx,
            .eventPub = undefined,
            .poller = zmq.Poller.init(alloc),
            .clk = try VecClock.init(id, 0, alloc),
            .alloc = alloc,
            .myid = id,
            .zEvSideListen = try ctx.socket(.Sub),
            .netdb = NetDb.init(alloc), // TODO errderfer sockets
        };
        var me = try result.netdb.getPeer(id); // ensure me peer exists
        me.aliveUntil = std.math.maxInt(u64);
        me.aliveOffest = DEFAULT_LEASE_TIME;
        result.eventPub = try EventPub.init(&result.zctx, result);
        try result.zEvSideListen.subscribe("");
        try result.addEventPubSocketPolls();
        return result;
    }

    fn addEventPubSocketPolls(self: *Self) !void {
        try self.poller.add(&self.eventPub.zRou, .{"in"});
        try self.poller.add(&self.eventPub.zRouMonitor, .{"in"});
    }

    pub fn deinit(self: *Self) void {
        // Deinitialise sockets
        self.eventPub.deinit();
        self.zEvSideListen.deinit();
        // Other resources
        self.netdb.deinit();
        self.clk.deinit();
        self.poller.deinit();
        self.zctx.deinit();
        self.alloc.destroy(self);
    }

    pub fn getMePeer(self: *Self) *Peer {
        return self.netdb.getPeer(self.myid) catch unreachable;
    }

    fn handleSideListen(self: *Self, currentTime: u64) (zmq.IOError || Allocator.Error)!void {
        _ = currentTime; _ = self;
        // TODO: remove side listen
    }

    fn _poll(self: *Self, timeout: c_int) !?zmq.PollEvent { // TODO: fill the error set
        var currentTime = posixTimestamp();
        var me = self.getMePeer();
        // Do daily routine
        try self.eventPub.dailyRoutine(currentTime);
        if (try self.poller.wait(timeout)) |pollev| {
            var sock = pollev.socket;
            if (sock == &self.eventPub.zRou or sock == &self.eventPub.zRouMonitor) {
                try self.eventPub.socketHandler(sock, currentTime);
            } else if (sock == &self.zEvSideListen) {
                try self.handleSideListen(currentTime);
            }
            return pollev;
        }
        return null;
    }

    pub fn poll(self: *Self, timeout: c_int) !void {
        _ = try self.poll(timeout);
    }

    pub fn start(self: *Self) (zmq.FileError || Allocator.Error)!void {
        try self.eventPub.outBind("tcp://*:*"); // TODO: use secure tunnel
        _l.notice("({}) router started", .{self.myid});
    }
};

pub const RouterCtl = struct {
    cmd: Command,
    address: ?[:0]const u8 = undefined,
    result: ?Result = null,

    const Self = @This();

    pub const Result = union (enum) {
        Ok: void,
        Err: anyerror,
    };

    pub const Command = enum {
        EventPubConnect,
        Stop,
    };
};

pub const RouterThread = struct {
    router: *Router,
    thread: std.Thread,
    ctlServer: zmq.Socket,
    ctlClient: zmq.Socket,

    const Self = @This();

    const _lt = std.log.scoped(.RopeRouterThread);

    const RouterThreadTool = struct {
        router: *Router,
        ctlServer: *zmq.Socket,
    };

    fn threadBody(ctx: *Self) void {
        _lt.debug("thread is starting...", .{});
        var router = ctx.router;
        var ctlServer = &ctx.ctlServer;
        router.poller.add(ctlServer, .{"in"}) catch unreachable;
        defer router.poller.rm(ctlServer);
        router.start() catch unreachable;
        _ = ctlServer.sendEmpty(.{}) catch unreachable;
        _lt.debug("thread started", .{});
        while(true) {
            if (router._poll(5) catch |e| blk: {
                _lt.err("poll error: {}", .{e});
                if (e == error.OutOfMemory) {
                    break;
                }
                break :blk null;
            }) |pollev| { // TODO: logging
                if (pollev.socket == ctlServer) {
                    var ctl = ctlServer.recvValue(*RouterCtl, .{}) catch |e| {
                        _lt.err("receive ctl message error: {}", .{e});
                        continue;
                    };
                    switch (ctl.cmd) {
                        .Stop => {
                            ctl.result = RouterCtl.Result.Ok;
                            _ = ctlServer.sendConstValue(*RouterCtl, &ctl, .{}) catch |e| _lt.err("reply error: {}", .{e});
                            break;
                        },
                        .EventPubConnect => {
                            var addr = ctl.address.?;
                            ctl.result = RouterCtl.Result.Ok;
                            _lt.info("notify event pub to connect {s}", .{ctl.address.?});
                            router.eventPub.outConnect(addr) catch |e| {ctl.result = RouterCtl.Result {.Err = e};}; // TODO: use secure tunnel
                            _ = ctlServer.sendConstValue(*RouterCtl, &ctl, .{}) catch |e| _lt.err("reply error: {}", .{e});
                        },
                    }
                }
            }
        }
        _lt.debug("thread is ended", .{});
    }


    pub fn spawn(router: *Router) !*Self {
        var result = try router.alloc.create(Self);
        errdefer router.alloc.destroy(result);
        result.* = Self {
            .router = router,
            .thread = undefined,
            .ctlServer = undefined,
            .ctlClient = undefined,
        };
        result.ctlServer = try router.zctx.socket(.Pair);
        errdefer result.ctlServer.deinit();
        try result.ctlServer.bind("inproc://rope.routerctl");
        result.ctlClient = try router.zctx.socket(.Pair);
        errdefer result.ctlClient.deinit();
        try result.ctlClient.connect("inproc://rope.routerctl");
        result.thread = try std.Thread.spawn(.{}, threadBody, .{result});
        _l.debug("waiting for thread...", .{});
        try result.ctlClient.recvIgnore(.{});
        _l.debug("thread have started", .{});
        if (@hasDecl(std.Thread, "detach")) {
            result.thread.detach();
        }
        return result;
    }

    fn stop(self: *Self) void {
        var ctl = RouterCtl {
            .cmd = .Stop,
        };
        var ctlPtr = &ctl;
        _ = self.ctlClient.sendConstValue(*RouterCtl, &ctlPtr, .{}) catch unreachable;
        _ = self.ctlClient.recvIgnore(.{}) catch unreachable;
    }

    /// Deinitilise thread.
    /// Warning: the router have been started after the thread spawned. It should not be started again.
    pub fn deinit(self: *Self) void {
        self.stop();
        if (!@hasDecl(std.Thread, "detach")) {
            self.thread.join();
        }
        self.ctlClient.deinit();
        self.ctlServer.deinit();
        self.router.alloc.destroy(self);
    }

    /// Deinitilise thread and router.
    pub fn deinitAll(self: *Self) void {
        var router = self.router;
        self.deinit();
        router.deinit();
    }

    pub fn connect(self: *Self, addr: [:0]const u8) !void {
        var ctl = RouterCtl {
            .cmd = .EventPubConnect,
            .address = addr,
        };
        var ctlPtr = &ctl;
        _ = self.ctlClient.sendConstValue(*RouterCtl, &ctlPtr, .{}) catch unreachable;
        if (self.ctlClient.recvValue(*RouterCtl, .{}) catch null) |rctl| {
            const result = rctl.result.?;
            if (result == .Err) {
                return result.Err;
            }
        } else unreachable;
    }
};

test "Router initialise, start and deinitialise" {
    const _t = std.testing;
    const kssid = @import("kssid.zig");
    var gen = kssid.Generator.init();
    var router = try Router.init(gen.generate(), _t.allocator);
    try router.start();
    defer router.deinit();
}

test "RouterThread spawn and stop" {
    const _t = std.testing;
    const kssid = @import("kssid.zig");
    var gen = kssid.Generator.init();
    var router = try Router.init(gen.generate(), _t.allocator);
    defer router.deinit();
    var rThread = try RouterThread.spawn(router);
    defer rThread.deinit();
}

test "Router can know each other" {
    const _t = std.testing;
    const kssid = @import("kssid.zig");
    var gen = kssid.Generator.init();
    const r0Id = gen.generate();
    var r0 = try Router.init(r0Id, _t.allocator);
    defer r0.deinit();
    const r1Id = gen.generate();
    var r1 = try Router.init(r1Id, _t.allocator);
    defer r1.deinit();
    var rT0 = try RouterThread.spawn(r0);
    defer rT0.deinit();
    var rT1 = try RouterThread.spawn(r1);
    defer rT1.deinit();
    const uri = @import("pkgs/uri/uri.zig");
    var r0EndpointUri = try uri.parse(r0.eventPub.bindingEndpoints.items[0]);
    var r0EndpointUriStr = try std.fmt.allocPrintZ(_t.allocator, "tcp://127.0.0.1:{}", .{r0EndpointUri.port.?});
    defer _t.allocator.free(r0EndpointUriStr);
    try rT1.connect(r0EndpointUriStr);
    const t1 = posixTimestamp();
    while (true) {
        const t2 = posixTimestamp();
        if (t2 - t1 > 20) {
            return error.TestTimeout;
        }
        if(r0.netdb.hasPeer(r1Id)) {
            std.log.notice("discover cost {}s", .{t2-t1});
            break;
        }
        std.time.sleep(std.time.ns_per_ms);
    }
}

export fn rope_router_new(id: u64) ?*Router {
    var router = Router.init(id, std.heap.c_allocator) catch return null;
    return router;
}

export fn rope_router_destroy(ptr: *Router) void {
    ptr.deinit();
}
