const std = @import("std");
const c = @cImport(@cInclude("curl/curl.h"));
const utils = @import("utils");
const types = @import("types.zig");
const log = std.log.scoped(.imap);

pub fn ImapProtocol(comptime ProviderType: type) type {
    return struct {
        const Self = @This();

        curl: utils.CurlHandle,
        allocator: std.mem.Allocator,
        payload: types.ImapPayload,
        provider: ProviderType,

        pub fn init(allocator: std.mem.Allocator, payload: types.ImapPayload, provider: ProviderType) !Self {
            return .{
                .curl = try utils.CurlHandle.init(),
                .allocator = allocator,
                .payload = payload,
                .provider = provider,
            };
        }

        pub fn deinit(self: *Self) void {
            self.curl.deinit();
            self.provider.deinit();
        }

        pub fn connect(self: *Self) !void {
            try self.provider.authenticate(self.curl.handle);
        }

        pub fn listMailboxes(self: *Self) ![]const u8 {
            log.info("Listing mailboxes on {s}:{d}", .{ self.payload.hostname, self.payload.port });

            const url = try self.buildUrl();
            defer self.allocator.free(url);

            var response: std.Io.Writer.Allocating = .init(self.allocator);
            errdefer response.deinit();

            try self.configureListRequest(url, &response.writer);
            try self.curl.perform();

            log.info("Mailboxes listed successfully", .{});
            return response.toOwnedSlice();
        }

        fn buildUrl(self: Self) ![]const u8 {
            return std.fmt.allocPrint(
                self.allocator,
                "imaps://{s}:{d}/",
                .{ self.payload.hostname, self.payload.port },
            );
        }

        fn configureListRequest(self: *Self, url: []const u8, writer: *std.Io.Writer) !void {
            try self.curl.setOpt(c.CURLOPT_URL, url.ptr);
            try self.curl.setOpt(c.CURLOPT_USE_SSL, c.CURLUSESSL_ALL);
            try self.curl.setOpt(c.CURLOPT_TIMEOUT, @as(c_long, 30));
            try self.curl.setOpt(c.CURLOPT_CONNECTTIMEOUT, @as(c_long, 10));
            try self.curl.setOpt(c.CURLOPT_WRITEFUNCTION, utils.CurlHandle.writeCallback);
            try self.curl.setOpt(c.CURLOPT_WRITEDATA, writer);
            try self.curl.setOpt(c.CURLOPT_CUSTOMREQUEST, "LIST \"\" \"*\"");
        }
    };
}
