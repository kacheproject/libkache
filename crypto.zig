const std = @import("std");
const c = @cImport({
    @cInclude("sodium.h");
});

pub fn initialise() error{BadInit}!void {
    const stat = c.sodium_init();
    if (stat < 0) {
        return error.BadInit;
    }
}

pub fn initialiseSimple() void {
    initialise() catch unreachable;
}

pub const aead = struct {
    pub const Algorithm = enum {
        Chacha20Poly1305,
        Chacha20Poly1305IETF,
    };

    pub const CHACHA20POLY1305_KEYLEN = c.crypto_aead_chacha20poly1305_KEYBYTES;
    pub const CHACHA20POLY1305_NONCELEN = c.crypto_aead_chacha20poly1305_NPUBBYTES;
    pub const CHACHA20POLY1305_ALEN = c.crypto_aead_chacha20poly1305_ABYTES;

    pub const CHACHA20POLY1305_IETF_KEYLEN = c.crypto_aead_chacha20poly1305_ietf_KEYBYTES;
    pub const CHACHA20POLY1305_IETF_NONCELEN = c.crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    pub const CHACHA20POLY1305_IETF_ALEN = c.crypto_aead_chacha20poly1305_ietf_ABYTES;

    pub const EncryptRequest = struct {
        secret: []u8,
        clear: []const u8,
        addtional: ?[]const u8,
        nonce: []const u8,
        key: []const u8
    };

    pub const Error = error {
        Unknown,
    };

    pub fn encrypt(comptime A: Algorithm, req: EncryptRequest) Error![]const u8 {
        const f = switch (A) {
            .Chacha20Poly1305 => c.crypto_aead_chacha20poly1305_encrypt,
            .Chacha20Poly1305IETF => c.crypto_aead_chacha20poly1305_ietf_encrypt,
        };
        var actualLength = req.secret.len;
        const stat = f(
            req.secret.ptr, &actualLength,
            req.clear.ptr, req.clear.len,
            if (req.addtional) |addtional| addtional.ptr else null,
            if (req.addtional) |addtional| addtional.len else 0,
            null, req.nonce.ptr, req.key.ptr
        );
        if (stat >= 0) {
            return req.secret[0..actualLength];
        } else {
            return Error.Unknown;
        }
    }

    pub fn encryptLength(comptime A: Algorithm, clearLength: usize) usize {
        _ = A;
        return clearLength + c.crypto_aead_chacha20poly1305_ABYTES;
    }

    pub const DecryptRequest = struct {
        secret: []const u8,
        clear: []u8,
        addtional: ?[]const u8,
        nonce: []const u8,
        key: []const u8
    };

    pub fn decrypt(comptime A: Algorithm, req: DecryptRequest) Error![]const u8 {
        const f = switch (A) {
            .Chacha20Poly1305 => c.crypto_aead_chacha20poly1305_decrypt,
            .Chacha20Poly1305IETF => c.crypto_aead_chacha20poly1305_ietf_decrypt,
        };
        var actualLength = req.clear.len;
        const stat = f(
            req.clear.ptr, &actualLength, null,
            req.secret.ptr, req.secret.len,
            if (req.addtional) |addtional| addtional.ptr else null,
            if (req.addtional) |addtional| addtional.len else 0,
            req.nonce.ptr, req.key.ptr
        );
        if (stat >= 0) {
            return req.secret[0..actualLength];
        } else {
            std.debug.print("error code: {}\n", .{stat});
            return Error.Unknown;
        }
    }

    pub fn decryptLength(comptime A: Algorithm, secretLength: usize) usize {
        _ = A;
        return secretLength - c.crypto_aead_chacha20poly1305_ABYTES;
    }
};

test "AEAD can encrypt and decrypt" {
    initialiseSimple();
    var random = std.crypto.random.*;
    const DATA = "Hello World!";
    var nonce: [8]u8 = undefined;
    random.bytes(&nonce);
    var key: [32]u8 = undefined;
    random.bytes(&key);
    var secretbuf: [aead.encryptLength(.Chacha20Poly1305, DATA.len)]u8 = undefined;
    _ = try aead.encrypt(.Chacha20Poly1305, .{
        .secret = &secretbuf,
        .clear = DATA,
        .addtional = DATA,
        .nonce = &nonce,
        .key = &key,
    });
    var clearbuf: [DATA.len]u8 = undefined;
    _ = try aead.decrypt(.Chacha20Poly1305, .{
        .secret = &secretbuf,
        .clear = &clearbuf,
        .addtional = DATA,
        .nonce = &nonce,
        .key = &key,
    });
    try std.testing.expectEqualStrings(DATA, &clearbuf);
}
