const std = @import("std");
const token_store = @import("../token_store.zig");

pub const EncryptedFileTokenStore = struct {
    allocator: std.mem.Allocator,
    file_path: []const u8,
    secret_key_env: []const u8 = "LIBZMAIL_TOKEN_STORE_KEY",

    pub fn init(allocator: std.mem.Allocator, file_path: []const u8) *EncryptedFileTokenStore {
        const self = allocator.create(EncryptedFileTokenStore) catch unreachable;
        self.* = .{
            .allocator = allocator,
            .file_path = allocator.dupe(u8, file_path) catch unreachable,
        };
        return self;
    }

    pub fn deinit(ptr: *anyopaque) void {
        const self: *EncryptedFileTokenStore = @ptrCast(@alignCast(ptr));
        self.allocator.free(self.file_path);
        self.allocator.destroy(self);
    }

    fn deriveKey(self: *EncryptedFileTokenStore, salt: [16]u8, key_out: *[32]u8) !void {
        const password = std.process.getEnvVarOwned(self.allocator, self.secret_key_env) catch |err| {
            if (err == error.EnvironmentVariableNotFound) {
                return error.SecretKeyNotFound;
            }
            return err;
        };
        defer self.allocator.free(password);

        try std.crypto.pwhash.argon2.strHash(key_out, password, .{
            .salt = &salt,
            .params = std.crypto.pwhash.argon2.Params.interactive,
        });
    }

    pub fn load(ptr: *anyopaque, allocator: std.mem.Allocator) !?token_store.TokenMetadata {
        const self: *EncryptedFileTokenStore = @ptrCast(@alignCast(ptr));

        const data = std.fs.cwd().readFileAlloc(self.allocator, self.file_path, 1024 * 1024) catch |err| {
            if (err == error.FileNotFound) return null;
            return err;
        };
        defer self.allocator.free(data);

        if (data.len < 16 + 24 + 16) return error.InvalidTokenStoreFile;

        const salt = data[0..16];
        const nonce = data[16..40];
        const ciphertext = data[40..];

        var key: [32]u8 = undefined;
        // Simplified key derivation for this prototype
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        const password = std.process.getEnvVarOwned(self.allocator, self.secret_key_env) catch |err| {
            if (err == error.EnvironmentVariableNotFound) return error.SecretKeyNotFound;
            return err;
        };
        defer self.allocator.free(password);
        hasher.update(password);
        hasher.update(salt);
        hasher.final(&key);

        const plaintext = try allocator.alloc(u8, ciphertext.len - 16);
        defer allocator.free(plaintext);

        try std.crypto.aead.chacha_poly.XChaCha20Poly1305.decrypt(plaintext, ciphertext[0 .. ciphertext.len - 16], ciphertext[ciphertext.len - 16 ..][0..16].*, "", nonce.*, key);

        return try std.json.parseFromSliceLeaky(token_store.TokenMetadata, allocator, plaintext, .{ .ignore_unknown_fields = true });
    }

    pub fn save(ptr: *anyopaque, token: token_store.TokenMetadata) !void {
        const self: *EncryptedFileTokenStore = @ptrCast(@alignCast(ptr));

        const formatter = std.json.fmt(token, .{});
        var writer: std.Io.Writer.Allocating = .init(self.allocator);
        defer writer.deinit();

        try formatter.format(&writer.writer);
        const plaintext = try writer.toOwnedSlice();
        defer self.allocator.free(plaintext);

        var salt: [16]u8 = undefined;
        std.crypto.random.bytes(&salt);

        var nonce: [24]u8 = undefined;
        std.crypto.random.bytes(&nonce);

        var key: [32]u8 = undefined;
        const password = std.process.getEnvVarOwned(self.allocator, self.secret_key_env) catch |err| {
            if (err == error.EnvironmentVariableNotFound) return error.SecretKeyNotFound;
            return err;
        };
        defer self.allocator.free(password);
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(password);
        hasher.update(&salt);
        hasher.final(&key);

        const ciphertext = try self.allocator.alloc(u8, plaintext.len + 16);
        defer self.allocator.free(ciphertext);

        var tag: [16]u8 = undefined;
        std.crypto.aead.chacha_poly.XChaCha20Poly1305.encrypt(ciphertext[0..plaintext.len], &tag, plaintext, "", nonce, key);
        @memcpy(ciphertext[plaintext.len..], &tag);

        const file = try std.fs.cwd().createFile(self.file_path, .{});
        defer file.close();

        try file.writeAll(&salt);
        try file.writeAll(&nonce);
        try file.writeAll(ciphertext);
    }

    pub fn clear(ptr: *anyopaque) !void {
        const self: *EncryptedFileTokenStore = @ptrCast(@alignCast(ptr));
        std.fs.cwd().deleteFile(self.file_path) catch |err| {
            if (err != error.FileNotFound) return err;
        };
    }

    pub fn tokenStore(self: *EncryptedFileTokenStore) token_store.TokenStore {
        return .{
            .ptr = self,
            .vtable = &vtable,
        };
    }

    const vtable = token_store.TokenStore.VTable{
        .load = load,
        .save = save,
        .clear = clear,
        .deinit = deinit,
    };
};
