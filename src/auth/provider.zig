const std = @import("std");
const c = @cImport(@cInclude("curl/curl.h"));

const types = @import("types.zig");
const providers = @import("providers.zig");

pub fn Provider(comptime tag: std.meta.Tag(types.PayloadType)) type {
    const Payload = std.meta.TagPayload(types.PayloadType, tag);

    const Impl = switch (tag) {
        .basic => providers.BasicProvider,
        .oauth2 => providers.OAuth2Provider,
    };

    return struct {
        pub const PayloadTag = tag;

        allocator: std.mem.Allocator,
        impl: ?Impl = null,

        pub fn init(allocator: std.mem.Allocator, payload: Payload) @This() {
            return .{
                .allocator = allocator,
                .impl = Impl.init(allocator, payload),
            };
        }

        pub fn deinit(self: *@This()) void {
            if (self.impl) |*impl| {
                impl.deinit();
            }
        }

        pub fn authenticate(self: *@This(), curl: *c.CURL) !void {
            if (self.impl) |*impl| {
                try impl.authenticate(curl);
            }
        }
    };
}
