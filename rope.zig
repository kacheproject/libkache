const std = @import("std");
const Allocator = std.mem.Allocator;

const zmq = @import("pkgs/zmq/zmq.zig");
const VecClock = @import("crdt.zig").VecClock;
const pn = @import("pn.zig");

const _l = std.log.scoped(.Rope);

// event = event_name router_id clock user_message
const EventPub = struct {
    zPubOut: zmq.Socket,
    zXSub: zmq.Socket,
    zXPub: zmq.Socket,

    const Self = @This();

    fn init(zctx: *zmq.Context, router: *Router) (zmq.FileError || zmq.Error)!Self {
        var result = Self {
            .zPubOut = try zctx.socket(.Pub),
            .zXSub = try zctx.socket(.XSub),
            .zXPub = try zctx.socket(.XPub),
        };
        try result.zXPub.bind("inproc://rope.eventpub");
        return result;
    }

    fn deinit(self: *Self) void {
        self.zPubOut.deinit();
        self.zXSub.deinit();
        self.zXPub.deinit();
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

    fn inHandle(self: *Self, socket: *Socket, alloc: *Allocator, clk: *VecClock) (zmq.IOError || Allocator.Error)!void {
        if (socket == &self.zXSub) {
            var msg = try EventMessage.recv(&self.zXSub, alloc) catch |e| switch (e) {
                error.BadMessage => {
                    _l.warn("eventpub receive bad message", .{});
                    return;
                },
                else => return e,
            };
            defer msg.deinit();
            if (clk.canBeUpdated(msg.routerId, msg.clock)) {
                _ = try msg.send(&self.zXPub);
            } else {
                _l.debug("eventpub drop message {}/{}", .{msg.routerId, msg.clock});
            }
        } else {
            try proxyMessage(&self.zXPub, &self.zXSub, EventMessage.USERMSG_MAXSIZE);
            // TODO: optz this case, XPub only send subscribes message out
        }
    }
};

const EventMessage = struct {
    // event = event_name router_id clock user_message
    eventName: []const u8,
    routerId: u64,
    clock: u64,
    userMessage: []const u8,
    alloc: ?*Allocator,

    const Self = @This();

    const EVENTNAME_MAXSIZE = 255;
    const USERMSG_MAXSIZE = 4096;

    const Error = error {
        BadMessage,
    };

    pub fn init(eventName: []const u8, routerId: u64, clock: u64, userMessage: []const u8, alloc: ?*Allocator) Self {
        return Self {
            .eventName = eventName,
            .routerId = routerId,
            .clock = clock,
            .userMessage = userMessage,
            .alloc = alloc,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.alloc) |alloc| {
            alloc.free(self.eventName);
            alloc.free(self.userMessage);
        }
    }

    pub fn send(self: *Self, socket: *zmq.Socket) (zmq.IOError || Allocator.Error)!void {
        _ = try socket.sendCopy(self.eventName, .{"more"});
        const routerIdP = pn.toPortableInt(u64, self.routerId);
        _ = try socket.sendValue(u64, routerIdP, .{"more"});
        const clkP = pn.toPortableInt(u64, self.clock);
        _ = try socket.sendValue(clkP, .{"more"});
        _ = try socket.sendCopy(self.userMessage, .{});
    }

    // TODO: zero-copy function to send message

    pub fn recv(socket: *zmq.Socket, alloc: *Allocator) (Allocator.Error || zmq.IOError || Error)!Self {
        var eventName = try socket.recvAlloc(alloc, 255, .{});
        errdefer alloc.free(eventName);
        if (!socket.getRcvMore()) return Error.BadMessage;
        var routerId = pn.fromPortableInt(try socket.recvValue(u64, .{}));
        if (!socket.getRcvMore()) return Error.BadMessage;
        var clock = pn.fromPortableInt(try socket.recvValue(u64, .{}));
        if (!socket.getRcvMore()) return Error.BadMessage;
        var userMessage = try socket.recvAlloc(alloc, 2048, .{});
        errdefer alloc.free(eventName);
        if (!socket.getRcvMore()) return Error.BadMessage;
        return Self.init(eventName, routerId, clock, userMessage, alloc);
    }
};

const NetDb = struct {};

pub const Router = struct {
    zctx: zmq.Context,
    eventPub: EventPub,
    poller: zmq.Poller,
    clk: VecClock,
    alloc: *Allocator,
    myid: u64,
    zEvSideListen: zmq.Socket, // be used to update clock

    const Self = @This();

    const Error = error {} || zmq.Error;

    const IOError = error{} || zmq.IOError;

    pub fn init(id: u64, alloc: *Allocator) (zmq.FileError || Error || Allocator.Error)!*Self {
        var result = try alloc.create(Self);
        var ctx = try zmq.Context.init();
        result.* = Self {
            .zctx = ctx,
            .eventPub = undefined,
            .poller = zmq.Poller.init(alloc),
            .clk = try VecClock.init(id, 0, alloc),
            .alloc = alloc,
            .myid = id,
            .zEvSideListen = try ctx.socket(.Sub),
        };
        result.eventPub = try EventPub.init(&result.zctx, result);
        try result.zEvSideListen.subscribe("");
        try result.addEventPubSocketPolls();
        return result;
    }

    fn addEventPubSocketPolls(self: *Self) !void {
        try self.poller.add(&self.eventPub.zXPub, .{"in"});
        try self.poller.add(&self.eventPub.zXSub, .{"in"});
    }

    pub fn deinit(self: *Self) void {
        // Deinitialise sockets
        self.eventPub.deinit();
        self.zEvSideListen.deinit();
        // Other resources
        self.clk.deinit();
        self.poller.deinit();
        self.zctx.deinit();
        self.alloc.destroy(self);
    }

    fn handleSideListen(self: *Self) zmq.IOError!void {
        var msg = try EventMessage.recv(&self.zEvSideListen);
        if (self.clk.canBeUpdated(msg.routerId, msg.clock)) {
            const oldClk = self.clk.vec.get(msg.routerId);
            _ = try self.clk.update(msg.routerId, msg.clock);
            _l.debug("clock updated for {}: {} -> {}", .{msg.routerId, oldClk, msg.clock});
        }
    }

    /// Publish a message though event pub.
    /// If `alloc` is not null, `eventName` and `userMessage` will be free'd after message sent.
    /// Warning: all event name prefixed with `_` are only for internal use of rope or kache.
    /// This function does zero check on names.
    pub fn publish(self: *Self, eventName: []const u8, userMessage: []const u8, alloc: ?*Allocator) (IOError || Allocator.Error)!void {
        var clk = self.clk.increment(1);
        var msg = EventMessage.init(eventName, self.myid, clk, userMessage, alloc);
        defer msg.deinit();
        try msg.send(self.eventPub.zPubOut);
    }

    pub fn poll(self: *Self, timeout: c_int) !void {
        if (self.poller.wait(timeout)) |pollev| {
            var sock = pollev.socket;
            if (sock == &self.eventPub.zXPub or sock == &self.eventPub.zXSub) {
                try self.eventPub.inHandle(sock, self.alloc, &self.clk);
            } else if (sock == &self.zEvSideListen) {
                try self.handleSideListen();
            }
        }
    }

    pub fn start(self: *Self) zmq.FileError!void {
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
