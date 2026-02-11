const std = @import("std");
const token_store = @import("../token_store.zig");

pub const MemoryTokenStore = struct {
    allocator: std.mem.Allocator,
    token: ?token_store.TokenMetadata = null,

    pub fn init(allocator: std.mem.Allocator) *MemoryTokenStore {
        const self = allocator.create(MemoryTokenStore) catch unreachable;
        self.* = .{ .allocator = allocator };
        return self;
    }

    pub fn deinit(ptr: *anyopaque) void {
        const self: *MemoryTokenStore = @ptrCast(@alignCast(ptr));
        if (self.token) |*t| t.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    pub fn load(ptr: *anyopaque, allocator: std.mem.Allocator) !?token_store.TokenMetadata {
        const self: *MemoryTokenStore = @ptrCast(@alignCast(ptr));
        if (self.token) |t| {
            return try t.dupe(allocator);
        }
        return null;
    }

    pub fn save(ptr: *anyopaque, token: token_store.TokenMetadata) !void {
        const self: *MemoryTokenStore = @ptrCast(@alignCast(ptr));
        if (self.token) |*t| t.deinit(self.allocator);
        self.token = try token.dupe(self.allocator);
    }

    pub fn clear(ptr: *anyopaque) !void {
        const self: *MemoryTokenStore = @ptrCast(@alignCast(ptr));
        if (self.token) |*t| t.deinit(self.allocator);
        self.token = null;
    }

    pub fn tokenStore(self: *MemoryTokenStore) token_store.TokenStore {
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

test "memory token store smoke test" {
    const allocator = std.testing.allocator;
    var mem_store = MemoryTokenStore.init(allocator);
    const store = mem_store.tokenStore();
    defer store.deinit();

    const token = token_store.TokenMetadata{
        .access_token = "test_token",
    };

    try store.save(token);
    
    var loaded = (try store.load(allocator)).?;
    defer loaded.deinit(allocator);
    
    try std.testing.expectEqualStrings("test_token", loaded.access_token);
    
    try store.clear();
    try std.testing.expect((try store.load(allocator)) == null);
}
