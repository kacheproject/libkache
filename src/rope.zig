const std = @import("std");
const Allocator = std.mem.Allocator;

const zmq = @import("../pkgs/zmq/zmq.zig");
const VecClock = @import("crdt.zig").VecClock;
const pn = @import("pn.zig");

// event = event_name router_id clock user_message
const EventPub = struct {
    zPubOut: zmq.Socket,
    zXSub: zmq.Socket,
    zXPub: zmq.Socket,

    const Self = @This();

    fn init(zctx: zmq.Context, router: *Router) !Self {
        var result = Self {
            .zPubOut = zctx.socket(.Pub),
            .zXSub = zctx.socket(.XSub),
            .zXPub = zctx.socket(.XPub),
        };
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

    fn inHandle(self: *Self, socket: *Socket, alloc: *Allocator) zmq.IOError!void {
        if (socket == &self.zXSub) {
            try proxyMessage(&self.zXSub, &self.zXPub, EventMessage.USERMSG_MAXSIZE);
            // TODO: drop message if the clock is out of date
        } else {
            try proxyMessage(&self.zXPub, &self.zXSub, EventMessage.USERMSG_MAXSIZE);
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

    pub fn send(self: *Self, socket: *zmq.Socket) zmq.IOError!void {
        _ = try socket.send(self.eventName, .{"more"});
        const routerIdP = pn.toPortableInt(u64, self.routerId);
        const routerIdPS = pn.getIntByteSlice(u64, &routerIdP);
        _ = try socket.send(routerIdPS, .{"more"});
        const clkP = pn.toPortableInt(u64, self.clock);
        const clkPS = pn.getIntByteSlice(u64, &clkP);
        _ = try socket.send(clkPS, .{"more"});
        _ = try socket.send(self.userMessage, .{});
    }

    pub fn recv(socket: *zmq.Socket, alloc: *Allocator) (Allocator.Error || zmq.IOError || Error)!Self {
        var eventName = try socket.recvAlloc(alloc, 255, .{});
        if (!socket.getRcvMore()) return Error.BadMessage;
        var routerId = pn.fromPortableInt(try socket.recvValue(u64, .{}));
        if (!socket.getRcvMore()) return Error.BadMessage;
        var clock = pn.fromPortableInt(try socket.recvValue(u64, .{}));
        if (!socket.getRcvMore()) return Error.BadMessage;
        var userMessage = try socket.recvAlloc(alloc, 2048, .{});
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

    pub fn init(id: u64, alloc: *Allocator) (zmq.FileError || Error || Allocator.Error)!*Self {
        var result = try alloc.create(Self);
        var ctx = try Context.init();
        result.* = Self {
            .zctx = ctx,
            .eventPub = undefined,
            .poller = zmq.Poller.init(alloc),
            .clk = VecClock.init(id, alloc),
            .alloc = alloc,
            .myid = id,
            .zEvSideListen = try ctx.socket(.Sub),
        };
        result.eventPub = try EventPub.init(ctx, &router);
        try result.zEvSideListen.subscribe("");
        try result.addEventPubSocketPolls();
    }

    fn addEventPubSocketPolls(self: *Self) !void {
        try self.poller.add(&self.eventPub.zXPub, .{"in"});
        try self.poller.add(&self.eventPub.zXSub, .{"in"});
    }

    pub fn deinit(self: *Self) void {
        self.eventPub.deinit();
        self.zctx.deinit();
        self.alloc.free(self);
    }

    fn handleSideListen(self: *Self) zmq.IOError!void {
        var msg = try EventMessage.recv(&self.zEvSideListen);
        if (self.clk.canBeUpdated(msg.routerId, msg.clock)) {
            try self.clk.update(msg.routerId, msg.clock);
        }
    }

    pub fn poll(self: *Self, timeout: c_int) !void {
        if (self.poller.wait(timeout)) |pollev| {
            var sock = pollev.socket;
            if (sock == &self.eventPub.zXPub or sock == &self.eventPub.zXSub) {
                try self.eventPub.inHandle(sock);
            }
        }
    }

    pub fn start(self: *Self) zmq.FileError!void {
        try self.eventPub.outBind("tcp://*:*"); // TODO: use secure tunnel
    }
};
