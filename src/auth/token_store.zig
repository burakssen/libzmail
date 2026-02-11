const std = @import("std");

pub const TokenMetadata = struct {
    access_token: [:0]const u8,
    refresh_token: ?[:0]const u8 = null,
    expires_at_unix: ?i64 = null,
    username: ?[:0]const u8 = null,

    pub fn deinit(self: *TokenMetadata, allocator: std.mem.Allocator) void {
        allocator.free(self.access_token);
        if (self.refresh_token) |rt| allocator.free(rt);
        if (self.username) |u| allocator.free(u);
    }

    pub fn dupe(self: TokenMetadata, allocator: std.mem.Allocator) !TokenMetadata {
        return .{
            .access_token = try allocator.dupeZ(u8, self.access_token),
            .refresh_token = if (self.refresh_token) |rt| try allocator.dupeZ(u8, rt) else null,
            .expires_at_unix = self.expires_at_unix,
            .username = if (self.username) |u| try allocator.dupeZ(u8, u) else null,
        };
    }
};

pub const TokenStore = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        load: *const fn (ptr: *anyopaque, allocator: std.mem.Allocator) anyerror!?TokenMetadata,
        save: *const fn (ptr: *anyopaque, token: TokenMetadata) anyerror!void,
        clear: *const fn (ptr: *anyopaque) anyerror!void,
        deinit: *const fn (ptr: *anyopaque) void,
    };

    pub fn load(self: TokenStore, allocator: std.mem.Allocator) !?TokenMetadata {
        return self.vtable.load(self.ptr, allocator);
    }

    pub fn save(self: TokenStore, token: TokenMetadata) !void {
        return self.vtable.save(self.ptr, token);
    }

    pub fn clear(self: TokenStore) !void {
        return self.vtable.clear(self.ptr);
    }

    pub fn deinit(self: TokenStore) void {
        return self.vtable.deinit(self.ptr);
    }
};

test {
    _ = @import("token_store/memory.zig");
    _ = @import("token_store/encrypted_file.zig");
}
