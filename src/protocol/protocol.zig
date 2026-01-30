const std = @import("std");
const types = @import("types.zig");
const protocols = @import("protocols.zig");

pub fn Protocol(comptime tag: std.meta.Tag(types.ProtocolPayloadType), comptime ProviderType: type) type {
    const Payload = std.meta.TagPayload(types.ProtocolPayloadType, tag);
    const Impl = protocols.SmtpProtocol(ProviderType);

    return struct {
        pub const PayloadTag = tag;

        allocator: std.mem.Allocator,
        impl: ?Impl = null,

        pub fn init(allocator: std.mem.Allocator, payload: Payload, provider: ProviderType) @This() {
            return .{
                .allocator = allocator,
                .impl = Impl.init(allocator, payload, provider),
            };
        }

        pub fn deinit(self: *@This()) void {
            if (self.impl) |*impl| {
                impl.deinit();
            }
        }

        pub fn connect(self: *@This()) !void {
            if (self.impl) |*impl| {
                try impl.connect();
            }
        }

        pub fn send(self: *@This(), data: types.MailPayload) !void {
            if (self.impl) |*impl| {
                try impl.send(data);
            }
        }
    };
}
