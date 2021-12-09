const std = @import("std");
const Allocator = std.mem.Allocator;
const os = std.os;

const _l = std.log.scoped(.UDP);

const Packet = struct {
    data: []const u8,
    alloc: ?*Allocator,

    fn deinit(self: Packet) void {
        if (self.alloc) |alloc| {
            alloc.free(self.data);
        }
    }
};

const SendRequest = struct {
    packet: Packet,
    address: std.net.Address,

    fn deinit(self: SendRequest) void {
        self.packet.deinit();
    }
};

const Buffer = struct {
    data: []u8,
    alloc: ?*Allocator,

    fn deinit(self: Buffer) void {
        if (self.alloc) |alloc| {
            alloc.free(self.data);
        }
    }
};

const RecvResponse = struct {
    packet: Packet,
    originalBuffer: Buffer,
    srcAddress: std.net.Address,

    pub fn deinit(self: RecvResponse) void {
        self.originalBuffer.deinit();
    }
};

/// Asynchrounous socket for UDP.
/// Every socket keeps three queues: send, recv, buffer.
/// enter() will poll on events, when:
/// - Any message in send queue, send them out to specific address.
/// - Any message is incoming, receive to the first buffer from buffer queue, then enqueue to recv queue.
/// 
/// It's recommended to use I/O thread by .spawnThread(). .deinit() will call .shutdownThread() when there is a thread.
///
/// Example:
///     var socket = Socket.open(&allocator);
///     try socket.bind(try std.net.Address.resolveIp("127.0.0.1", 10189));
///     try socket.send(&HELLO, null);
///     var response = socket.recv(&buf, null);
///     defer response.deinit(); // Or memory leak
///     std.debug.print("response: {s}", .{response.packet.data});
///
/// Warning: the socket object could not be moved after the I/O thread has started. You could shutdown, move object, then restart again.
/// That's because the thread accessing object though the memory address passed to .spawnThread().
/// Consider copy the socket to heap at first if you want to avoid the overhead of restarting.
pub const Socket = struct {
    sendQueue: std.atomic.Queue(SendRequest),
    recvQueue: std.atomic.Queue(RecvResponse),
    bufferQueue: std.atomic.Queue(Buffer),
    recentError: ?anyerror,
    alloc: *Allocator,
    thread: ?std.Thread,
    _fd: os.socket_t,
    _evfd: i32,
    emufd: i32,
    recvHWM: usize, // TODO: high water mark
    sendHWM: usize,
    _toShutdownThread: bool,

    const Self = @This();

    pub fn open(alloc: *Allocator) !Self {
        var fd = try os.socket(os.AF.INET, os.SOCK.DGRAM, 0); // TODO: support IPv6
        errdefer os.closeSocket(fd);
        var evfd = try os.eventfd(0, 0); // TODO: set EFD_NONBLOCK, that's not in std.os. Though it does not cause blocking in general.
        errdefer os.close(evfd);
        var emufd = try os.eventfd(0, 0);
        errdefer os.close(emufd);
        return Self{
            .sendQueue = std.atomic.Queue(SendRequest).init(),
            .recvQueue = std.atomic.Queue(RecvResponse).init(),
            .bufferQueue = std.atomic.Queue(Buffer).init(),
            .errorQueue = std.atomic.Queue(anyerror).init(),
            .alloc = alloc,
            .thread = null,
            ._fd = fd,
            ._evfd = evfd,
            .emufd = emufd,
            .recvHWM = 0,
            .sendHWM = 0,
            ._toShutdownThread = false,
        };
    }

    pub fn bind(self: *Self, address: std.net.Address) os.BindError!void {
        try os.bind(self._fd, &address.any, address.getOsSockLen());
    }

    pub fn deinit(self: *Self) void {
        if (self.thread) |_| {
            self.shutdownThread();
        }
        inline for (.{ "sendQueue", "recvQueue", "bufferQueue", "errorQueue" }) |name| {
            var q = &@field(self, name);
            while (q.get()) |e| {
                if (@TypeOf(e.data) != anyerror and @hasDecl(@TypeOf(e.data), "deinit")) {
                    e.data.deinit();
                }
                self.alloc.destroy(e);
            }
            q.* = undefined;
        }
        os.close(self._evfd);
        os.close(self.emufd);
        os.closeSocket(self._fd);
    }

    pub fn send(self: *Self, targetAddress: std.net.Address, data: []const u8, alloc: ?*Allocator) Allocator.Error!void {
        var node = try self.alloc.create(@TypeOf(self.sendQueue).Node);
        node.data = SendRequest{
            .packet = .{
                .data = data,
                .alloc = alloc,
            },
            .address = targetAddress,
        };
        self.sendQueue.put(node);
        var buf: [8]u8 = undefined;
        std.mem.writeIntNative(u64, &buf, 1);
        _ = os.write(self._evfd, &buf) catch unreachable;
        // It will work fine if the enter() run successfully,
        // as the value of the eventfd will be reset to zero when being read. (See eventfd(2))
        // The inner counter's cap is maxInt(u64)-1, so the logic can be seem broken if the cap is reached.
    }

    pub fn recv(self: *Self, buf: []u8, alloc: ?*Allocator) Allocator.Error!RecvResponse {
        try self.setBuffer(buf, alloc);
        while (true) {
            _ = self.poll(-1);
            if (self.getResult()) |result| {
                return result;
            }
        }
    }

    /// Push a new buffer into buffer queue.
    pub fn setBuffer(self: *Self, buf: []u8, alloc: ?*Allocator) Allocator.Error!void {
        var buffer = Buffer{
            .data = buf,
            .alloc = alloc,
        };
        var node = try self.alloc.create(@TypeOf(self.bufferQueue).Node);
        node.data = buffer;
        self.bufferQueue.put(node);
    }

    pub fn getResult(self: *Self) ?RecvResponse {
        if (self.recvQueue.get()) |rnode| {
            defer self.alloc.destroy(rnode);
            var buf: [8]u8 = undefined;
            _ = os.read(self.emufd, &buf) catch {};
            return rnode.data;
        }
        return null;
    }

    pub fn poll(self: *Self, timeout: i32) bool {
        if (!self.recvQueue.isEmpty()) {
            return true;
        }
        var polls = [1]os.pollfd{.{
            .fd = self.emufd,
            .events = os.POLL.IN,
            .revents = 0,
        }};
        if ((os.poll(&polls, timeout) catch 0) > 0) {
            return true;
        } else {
            return false;
        }
    }

    pub fn enforceError(self: *const Self) anyerror!void { // TODO: limit error to a specific set
        if (self.recentError) |e| {
            return e;
        }
    }

    fn threadBody(self: *Self) void {
        while (true) {
            self.enter(-1) catch |e| {
                self.recentError = e;
            };
            if (self._toShutdownThread) {
                break;
            }
        }
        @atomicStore(bool, &self._toShutdownThread, false, .SeqCst);
    }

    /// Spawn the I/O thread for this socket.
    /// The object should not be moved after the thread started. The thread will refer the address when the thread starts.
    /// TODO: Make the moving possible.
    pub fn spawnThread(self: *Self) std.Thread.SpawnError!void {
        std.debug.assert(self.thread == null);
        while (@cmpxchgWeak(bool, &self._toShutdownThread, false, false, .SeqCst, .SeqCst)) |_| {} // ensure there is no thread is going down
        self.thread = try std.Thread.spawn(.{}, Self.threadBody, .{self});
        self.thread.?.detach();
    }

    /// Shutdown the I/O thread
    pub fn shutdownThread(self: *Self) void {
        self._toShutdownThread = true;
        // Write _evfd to notify poll() exits
        var buf: [8]u8 = undefined;
        std.mem.writeIntNative(u64, &buf, 1);
        _ = os.write(self._evfd, &buf) catch unreachable;
        while (true) {
            if (!self._toShutdownThread) {
                break;
            }
        }
        self.thread = null;
    }

    pub fn enter(self: *Self, timeout: i32) !void {
        var fds: [2]os.pollfd = .{ .{
            .fd = self._evfd,
            .events = os.POLL.IN,
            .revents = 0,
        }, .{
            .fd = self._fd,
            .events = os.POLL.IN,
            .revents = 0,
        } };
        if ((try os.poll(&fds, timeout)) > 0) {
            for (&fds) |fdevs| {
                if (fdevs.revents > 0) {
                    if (fdevs.fd == self._evfd) {
                        var buf: [8]u8 = undefined;
                        _ = try os.read(self._evfd, &buf); // consume the event
                        while (self.sendQueue.get()) |node| {
                            defer self.alloc.destroy(node);
                            var req = node.data;
                            defer req.packet.deinit();
                            _ = try os.sendto(self._fd, req.packet.data, 0, &req.address.any, req.address.getOsSockLen());
                        }
                    } else if (fdevs.fd == self._fd) {
                        if (self.bufferQueue.get()) |node| {
                            var req = node.data;
                            errdefer self.bufferQueue.put(node);
                            var newRecvNode = try self.alloc.create(@TypeOf(self.recvQueue).Node);
                            var address = std.net.Address.initIp6(
                                std.mem.zeroes([16]u8),
                                0,
                                0,
                                0,
                            );
                            var actualAddrLength = @as(u32, address.getOsSockLen());
                            const len = try os.recvfrom(self._fd, req.data, 0, &address.any, &actualAddrLength);
                            address = std.net.Address.initPosix(@alignCast(4, &address.any));
                            var receivedPacket = Packet{
                                .data = req.data[0..len],
                                .alloc = req.alloc,
                            };
                            newRecvNode.data = RecvResponse{
                                .packet = receivedPacket,
                                .originalBuffer = req,
                                .srcAddress = address,
                            };
                            self.recvQueue.put(newRecvNode);
                            defer self.alloc.destroy(node);
                            var emufdBuf: [8]u8 = undefined;
                            std.mem.writeIntNative(u64, &emufdBuf, 1);
                            _ = os.write(self.emufd, &emufdBuf) catch {};
                        }
                    }
                }
            }
        }
    }
};

test "Socket can send and receive packets" {
    const t = std.testing;
    const DATA = "City of stars, are you shining just for me?";
    var s0 = try Socket.open(t.allocator);
    defer s0.deinit();
    var s1 = try Socket.open(t.allocator);
    defer s1.deinit();
    try s0.spawnThread();
    try s1.spawnThread();
    const s0Addr = try std.net.Address.resolveIp("127.0.0.1", 57527);
    const s1Addr = try std.net.Address.resolveIp("127.0.0.1", 57528);
    try s0.bind(s0Addr);
    try s1.bind(s1Addr);
    try s0.send(s1Addr, DATA, null);
    var buf = try t.allocator.alloc(u8, DATA.len);
    var response = try s1.recv(buf, t.allocator);
    defer response.deinit();
    try t.expectEqualStrings(DATA, response.packet.data);
}
