const std = @import("std");
const Allocator = std.mem.Allocator;

const zmq = @import("pkgs/zmq/zmq.zig");
const VecClock = @import("crdt.zig").VecClock;
const pn = @import("pn.zig");

const _l = std.log.scoped(.Rope);

// event = event_name flags(u8) router_id clock user_message
const EventPub = struct {
    zPubOut: zmq.Socket,
    zXSub: zmq.Socket,
    zXPub: zmq.Socket,
    zPubOutMonitor: zmq.Socket,

    const Self = @This();

    fn init(zctx: *zmq.Context, router: *Router) (zmq.FileError || zmq.Error)!Self {
        var result = Self{
            .zPubOut = try zctx.socket(.Pub),
            .zXSub = try zctx.socket(.XSub),
            .zXPub = try zctx.socket(.XPub),
            .zPubOutMonitor = try zctx.socket(.Pair), // TODO: errdefer close sockets
        };
        const monitorAddr = zmq.genRandomInprocAddress("rope.monitor.", 63);
        try result.zPubOut.startMonitor(&monitorAddr, .{
            zmq.SocketEvent.Connected,
            zmq.SocketEvent.Disconnected,
            zmq.SocketEvent.Closed,
            zmq.SocketEvent.Accepted,
            zmq.SocketEvent.AcceptFailed,
        });
        errdefer result.zPubOut.stopMonitor() catch {};
        try result.zXPub.bind("inproc://rope.eventpub");
        return result;
    }

    fn deinit(self: *Self) void {
        self.zPubOut.deinit();
        self.zXSub.deinit();
        self.zXPub.deinit();
        self.zPubOutMonitor.deinit();
    }

    fn outBind(self: *Self, addr: [:0]const u8) zmq.FileError!void {
        try self.zPubOut.bind(addr);
    }

    fn outConnect(self: *Self, addr: [:0]const u8) zmq.FileError!void {
        try self.zPubOut.connect(addr);
    }

    // TODO: outCurveBind & outCurveConnect

    fn proxyMessage(dst: *Socket, src: *Socket, comptime maxsize: c_int) zmq.IOError!void {
        var buf: [maxsize]u8 = undefined;
        var fstPart = try src.recv(buf, .{});
        _ = try dst.send(fstPart, if (src.getRcvMore()) zmq.MORE else 0);
        while (src.getRcvMore()) {
            var part = try src.recv(buf, .{});
            _ = try dst.send(part, if (src.getRcvMore()) zmq.MORE else 0);
        }
    }

    fn inHandle(self: *Self, socket: *Socket, router: *Router, currentTime: u64) (zmq.IOError || Allocator.Error)!void {
        if (socket == &self.zXSub) {
            var msg = try EventMessage.recv(&self.zXSub, alloc) catch |e| switch (e) {
                error.BadMessage => {
                    _l.warn("eventpub receive bad message", .{});
                    return;
                },
                else => return e,
            };
            defer msg.deinit();
            try self.handleIncomeMessage(&msg, router, currentTime);
            if (router.clk.canBeUpdated(msg.routerId, msg.clock)) {
                _ = try msg.send(&self.zXPub);
                msg.setForwarded();
                _ = try msg.send(&self.zPubOut); // forward message
            } else {
                _l.debug("eventpub drop message {}/{}", .{ msg.routerId, msg.clock });
            }
        } else if (socket == &self.zPubOutMonitor) {
            var msg = try zmq.SocketEventMessage.recv(&self.zPubOutMonitor, router.alloc);
            defer msg.deinit();
            _l.info("socket: {} {} endpoint={s}", .{msg.event, msg.value, msg.endpoint.?});
        } else {
            try proxyMessage(&self.zXPub, &self.zXSub, EventMessage.USERMSG_MAXSIZE);
            // TODO: optz this case, XPub only send subscribes message out
        }
    }

    fn handleIncomeMessage(self: *Self, msg: *EventMessage, r: *Router, currentTime: u64) (zmq.IOError || Allocator.Error)!void {
        var clkUpdated = false;
        if (r.clk.canBeUpdated(msg.routerId, msg.clock)) {
            const oldClk = r.clk.vec.get(msg.routerId);
            _ = try r.clk.update(msg.routerId, msg.clock);
            _l.debug("clock updated for {}: {} -> {}", .{ msg.routerId, oldClk, msg.clock });
            clkUpdated = true;
        }
        // rope_events = ticktok | wire_found | wire_down | entry_up | entry_down
        // ticktok = "_ticktok" router_id router_clk ticktok_msg
        // ticktok_msg = alive_until_offest(u64) physical_time(u64)
        // wire_found = "_wire.found" router_id router_clk wire_info
        // wire_info = peer_router_id(u64) ADDRESS(string)
        // wire_down = "_wire.down" router_id router_clk wire_info
        // entry_up = "_entry.up" router_id router_clk entry_addr
        // entry_down = "_entry.down" router_id router_clk entry_addr
        if (std.mem.eql(u8, msg.eventName, "_ticktok")) {
            // ticktok events tell other routers that this router is still alive.
            var view = TickTokEvent.init(msg);
            if (!view.isValid()) return;
            const aliveUntilOffest = view.aliveUntilOffest();
            const physicalTime = view.physicalTime();
            if (std.math.approxEqRel(u64, physicalTime, currentTime, 30)) {
                var peer = r.netdb.getPeer(msg.routerId);
                const routerAlivePromiseTime = std.math.min(physicalTime, currentTime) + aliveUntilOffest;
                peer.aliveUntil = routerAlivePromiseTime;
                peer.lastTickTok = currentTime;
                peer.aliveOffest = aliveUntilOffest;
                if (msg.peerAddress) |peerAddr| {
                    if (!(msg.isForwarded() or r.netdb.hasWireForPeer(msg.routerId, peerAddr))) {
                        var addr = try r.alloc.create(PhysicalAddress);
                        addr.* = PhysicalAddress {
                            .peerId = msg.routerId,
                            .address = try r.alloc.dupeZ(u8, peerAddr),
                        };
                        r.netdb.allAddresses.append(addr);
                        var usrMsg = try r.alloc.alloc(u8, WireFoundEvent.userMessageSize(msg.routerId, peerAddr));
                        WireFoundEvent.buildUserMessage(usrMsg, msg.routerId, peerAddr);
                        try r.publish(WireFoundEvent.NAME, usrMsg, r.alloc);
                    }
                }
                if (msg.peerAddress) |peerAddress| {
                    var paddrs = try r.netdb.lookupByAddress(peerAddress, self.alloc);
                    defer r.alloc.free(paddrs);
                    for (paddrs) |paddr| {
                        if (paddr.peerId != msg.routerId) {
                            paddr.lastReachable = std.math.max(paddr.lastReachable, currentTime);
                            // If the message is being forwarded, at least we know the forwarder is alive at the moment.
                        } else {
                            paddr.lastReachable = routerAlivePromiseTime;
                            // If the message is directly sent by the peer, set the last reachable time to promised time
                        }
                    }
                }
                var routerAddrs = try r.netdb.lookupById(msg.routerId, false, r.alloc);
                defer self.alloc.free(routerAddrs);
                for (routerAddrs) |paddr| {
                    paddr.lastReachable = routerAlivePromiseTime;
                }
            } else {
                _l.warn("peer {}, the difference of physical time is larger than 30s from local time. (local: {})", .{ msg.routerId, physicalTime, currentTime });
            }
        } else if (std.mem.eql(u8, msg.eventName, "_wire.found")) {
            var view = WireFoundEvent.init(msg);
            if (view.isValid()) {
                // update wire infomation
                if (r.netdb.getWireForPeer(view.peerRouterId(), view.address())) |wireAddrO| {
                    wireAddrO.lastFound = currentTime;
                } else {
                    var list = try r.netdb.lookupByAddress(view.address(), r.alloc);
                    for (list) |paddr| {
                        if (paddr.peerId == null) {
                            paddr.peerId = view.peerRouterId();
                            paddr.lastFound = currentTime;
                            break;
                        }
                    }
                }
            }
        } else if (std.mem.eql(u8, msg.eventName, "_wire.down")) {
            // TODO: handle wire down
        } else if (std.mem.eql(u8, msg.eventName, "_entry.up")) {
            // TODO: handle entry up
        } else if (std.mem.eql(u8, msg.eventName, "_entry.down")) {
            // TODO: handle entry down
        } else if (msg.eventName.len > 0 and msg.eventName[0] == '_') {
            _l.warn("got an unknown rope/kache event: {}", .{msg.eventName});
        }
    }
};

pub const EventMessage = struct {
    // event = event_name flags router_id clock user_message
    eventName: []const u8,
    flags: u8,
    routerId: u64,
    clock: u64,
    userMessage: []const u8,
    alloc: ?*Allocator,
    // fields below are not from message
    peerAddress: ?[:0]const u8 = null,

    const Self = @This();

    const FLAG_FORWARDED = @as(u8, 1) << 7;

    const EVENTNAME_MAXSIZE = 255;
    const USERMSG_MAXSIZE = 4096;

    const Error = error{
        BadMessage,
    };

    pub fn init(eventName: []const u8, flags: u8, routerId: u64, clock: u64, userMessage: []const u8, alloc: ?*Allocator) Self {
        return Self{
            .eventName = eventName,
            .flags = flags,
            .routerId = routerId,
            .clock = clock,
            .userMessage = userMessage,
            .alloc = alloc,
        };
    }

    pub fn setForwarded(self: *Self) void {
        self.flags |= FLAG_FORWARDED;
    }

    pub fn isForwarded(self: *Self) bool {
        return self.flags & FLAG_FORWARDED > 0;
    }

    pub fn deinit(self: *Self) void {
        if (self.alloc) |alloc| {
            alloc.free(self.eventName);
            alloc.free(self.userMessage);
            if (self.peerAddress) |addr| {
                alloc.free(addr);
            }
        }
    }

    pub fn send(self: *Self, socket: *zmq.Socket) (zmq.IOError || Allocator.Error)!void {
        _ = try socket.sendCopy(self.eventName, .{"more"});
        _ = try socket.sendValue(u8, &self.flags, .{"more"});
        const routerIdP = pn.toPortableInt(u64, self.routerId);
        _ = try socket.sendValue(u64, routerIdP, .{"more"});
        const clkP = pn.toPortableInt(u64, self.clock);
        _ = try socket.sendValue(clkP, .{"more"});
        _ = try socket.sendCopy(self.userMessage, .{});
    }

    // TODO: zero-copy function to send message

    pub fn recv(socket: *zmq.Socket, alloc: *Allocator) (Allocator.Error || zmq.IOError || Error)!Self {
        var frame = zmq.Frame.init();
        defer frame.deinit();
        _ = try socket.recvFrame(&frame, .{});
        var peerAddress = frame.getPeerAddress();
        var eventName = try alloc.dupe(u8, frame.data());
        errdefer alloc.free(eventName);
        if (!socket.getRcvMore()) return Error.BadMessage;
        var flags = try socket.recvValue(u8, .{}) orelse Error.BadMessage;
        if (!socket.getRcvMore()) return Error.BadMessage;
        var routerId = pn.fromPortableInt(try socket.recvValue(u64, .{}) orelse Error.BadMessage);
        if (!socket.getRcvMore()) return Error.BadMessage;
        var clock = pn.fromPortableInt(try socket.recvValue(u64, .{}) orelse Error.BadMessage);
        if (!socket.getRcvMore()) return Error.BadMessage;
        var userMessage = try socket.recvAlloc(alloc, 2048, .{});
        errdefer alloc.free(eventName);
        if (!socket.getRcvMore()) return Error.BadMessage;
        var result = Self.init(eventName, flags, routerId, clock, userMessage, alloc);
        if (peerAddress) |pa| {
            var peerAddrCopy = try alloc.dupeZ(u8, pa);
            errdefer alloc.free(peerAddrCopy);
            result.peerAddress = peerAddrCopy;
        }
        return result;
    }
};

pub const WireFoundEvent = struct {
    msg: *EventMessage,

    const Self = @This();

    pub const NAME = "_wire.found";

    pub fn init(msg: *EventMessage) Self {
        return Self {.msg = msg};
    }

    pub fn isValid(self: *Self) bool {
        return std.mem.eql(u8, "_wire.found", self.msg.eventName) and self.msg.userMessage.len > 8;
    }

    pub fn peerRouterId(self: *Self) u64 {
        return pn.fromPortableInt(std.PackedIntSlice(u8).init(self.msg.userMessage[0..8]).sliceCast(u64).get(0));
    }

    pub fn setPeerRouterId(self: *Self, val: u64) void {
        std.PackedIntSlice(u8).init(self.msg.userMessage[0..8]).sliceCast(u64).set(0, pn.toPortableInt(val));
    }

    pub fn address(self: *Self) []const u8 {
        return self.msg.userMessage[8..self.msg.userMessage.len];
    }

    pub fn userMessageSize(peerRouterId: u64, address: []const u8) usize {
        return 8+address.len;
    }

    pub fn buildUserMessage(buf: []u8, peerRouterId: u64, address: []const u8) []const u8 {
        std.mem.copy(u8, buf[8..buf.len], address);
        std.PackedIntSlice(u8).init(buf[0..8]).sliceCast(u64).set(0, peerRouterId);
        return buf[0..8+address.len-1];
    }
};

pub const TickTokEvent = struct {
    msg: *EventMessage,

    const Self = @This();

    pub const NAME = "_ticktok";

    pub fn init(msg: *EventMessage) Self {
        return Self {.msg = msg};
    }

    pub fn isValid(self: *Self) Self {
        return std.mem.eql(u8, self.msg.eventName, NAME) and self.msg.userMessage.len == 128;
    }

    fn getSlice(self: *Self) std.PackedIntSlice(u64) {
        return std.PackedIntSlice(u128).init(msg.userMessage, 1).sliceCast(u64);
    }

    pub fn physicalTime(self: *Self) u64 {
        const slice = self.getSlice();
        return pn.fromPortableInt(slice.get(1));
    }

    pub fn aliveUntilOffest(self: *Self) u64 {
        const slice = self.getSlice();
        return pn.fromPortableInt(slice.get(0));
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
const PhysicalAddress = struct {
    peerId: ?u64 = null,
    entryId: ?u64 = null,
    address: [:0]const u8,
    alloc: ?*Allocator,
    lastReachable: u64 = 0,
    lastFound: u64 = 0,

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
        return (std.math.max(self.lastReachable, time) - std.math.min(self.lastReachable, time)) > 0;
    }
};

const Peer = struct {
    id: u64,
    aliveUntil: u64 = 0,
    aliveOffest: u64 = 0,
    lastTickTok: u64 = 0,
};

const Entry = struct {
    address: u128,

    const Self = @This();

    pub fn init(address: u128) Self {
        return Self{ .address = address };
    }

    pub fn build(devId: u64, entryId: u64) Self {
        const addr = std.PackedIntArray(u64, 2).init(.{ devId, entryId }).sliceCast(u128).get(0);
        return Self.init(addr);
    }

    pub fn device(self: *Self) u64 {
        return std.PackedIntArray(u128, 1).initAllTo(self.address).sliceCast(u64).get(0);
    }

    pub fn entry(self: *Self) u64 {
        return std.PackedIntArray(u128, 1).initAllTo(self.address).sliceCast(u64).get(1);
    }
};

const NetDb = struct {
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
            for (self.allAddresses.items) |item| {
                if (id == item.peerId and std.mem.eql(u8, addr, item.address)) {
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
    return @intCast(u64, std.time.milliTimestamp() / std.time.ms_per_s);
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
            .netdb = NetDb.init(alloc),
        };
        var me = try result.netdb.getPeer(id); // ensure me peer exists
        me.aliveUntil = std.math.maxInt(u64);
        result.eventPub = try EventPub.init(&result.zctx, result);
        try result.zEvSideListen.subscribe("");
        try result.addEventPubSocketPolls();
        return result;
    }

    fn addEventPubSocketPolls(self: *Self) !void {
        try self.poller.add(&self.eventPub.zXPub, .{"in"});
        try self.poller.add(&self.eventPub.zXSub, .{"in"});
        try self.poller.add(&self.eventPub.zPubOutMonitor, .{"in"});
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

    fn sendTickTok(self: *Self, currentTime: u64) (Allocator.Error || zmq.IOError)!void {
        const aliveOffest = @as(u64, 12);
        const args = std.PackedIntArray(u64, 2).init(.{ pn.toPortableInt(aliveOffest), pn.toPortableInt(posixTimestamp()) }).sliceCast(u8);
        var buf = try self.alloc.dupe(u8, args.bytes);
        try self.publish("_ticktok", buf, self.alloc);
        self.getMePeer().lastTickTok = currentTime;
    }

    fn handleSideListen(self: *Self, currentTime: u64) (zmq.IOError || Allocator.Error)!void {
        var msg = try EventMessage.recv(&self.zEvSideListen);
    }

    /// Publish a message though event pub.
    /// If `alloc` is not null, `eventName` and `userMessage` will be free'd after message sent.
    /// Warning: all event name prefixed with `_` are only for internal use of rope or kache.
    /// This function does zero check on names. And the `flags` will be set to zero.
    pub fn publish(self: *Self, eventName: []const u8, userMessage: []const u8, alloc: ?*Allocator) (IOError || Allocator.Error)!void {
        var clk = self.clk.increment(1);
        var msg = EventMessage.init(eventName, 0, self.myid, clk, userMessage, alloc);
        defer msg.deinit();
        try msg.send(self.eventPub.zPubOut);
    }

    pub fn poll(self: *Self, timeout: c_int) !void {
        const pclk = @intCast(u64, std.time.milliTimestamp());
        var currentTime = posixTimestamp();
        // Do daily routine
        if (currentTime - self.getMePeer().lastTickTok >= 9) {
            try self.sendTickTok(currentTime);
        }
        if (self.poller.wait(timeout)) |pollev| {
            var sock = pollev.socket;
            if (sock == &self.eventPub.zXPub or sock == &self.eventPub.zXSub or sock == &self.eventPub.zPubOutMonitor) {
                try self.eventPub.inHandle(sock, self.alloc, &self.clk);
            } else if (sock == &self.zEvSideListen) {
                try self.handleSideListen(currentTime);
            }
        }
    }

    pub fn start(self: *Self) (zmq.FileError || Allocator.Error)!void {
        try self.eventPub.outBind("tcp://*:*"); // TODO: use secure tunnel
        _l.notice("router started", .{});
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

export fn rope_router_new(id: u64) ?*Router {
    var router = Router.init(id, std.heap.c_allocator) catch return null;
    return router;
}

export fn rope_router_destroy(ptr: *Router) void {
    ptr.deinit();
}
