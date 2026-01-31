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

        /// List all mailboxes and return structured data
        pub fn listMailboxes(self: *Self) ![]types.Mailbox {
            log.info("Listing mailboxes on {s}:{d}", .{ self.payload.hostname, self.payload.port });

            const response = try self.listMailboxesRaw();
            defer self.allocator.free(response);

            return try self.parseMailboxList(response);
        }

        /// Get raw mailbox list response
        pub fn listMailboxesRaw(self: *Self) ![]const u8 {
            const url = try self.buildUrl();
            defer self.allocator.free(url);

            var response: std.Io.Writer.Allocating = .init(self.allocator);
            errdefer response.deinit();

            try self.configureListRequest(url, &response.writer);
            try self.curl.perform();

            log.info("Mailboxes listed successfully", .{} );
            return response.toOwnedSlice();
        }

        /// Parse the raw LIST response into structured Mailbox data
        fn parseMailboxList(self: *Self, response: []const u8) ![]types.Mailbox {
            var mailboxes: std.ArrayList(types.Mailbox) = .empty;
            errdefer {
                for (mailboxes.items) |*mb| {
                    mb.deinit(self.allocator);
                }
                mailboxes.deinit(self.allocator);
            }

            var lines = std.mem.splitScalar(u8, response, '\n');
            while (lines.next()) |line| {
                const trimmed = std.mem.trim(u8, line, " \r\n");
                if (trimmed.len == 0) continue;

                if (try types.Mailbox.parse(self.allocator, trimmed)) |mailbox| {
                    try mailboxes.append(self.allocator, mailbox);
                }
            }

            return mailboxes.toOwnedSlice(self.allocator);
        }

        /// Get mailboxes filtered by type
        pub fn getMailboxesByType(self: *Self, mailbox_type: enum {
            inbox,
            drafts,
            sent,
            trash,
            junk,
            archive,
        }) ![]types.Mailbox {
            const all_mailboxes = try self.listMailboxes();
            defer {
                for (all_mailboxes) |*mb| {
                    mb.deinit(self.allocator);
                }
                self.allocator.free(all_mailboxes);
            }

            var filtered: std.ArrayList(types.Mailbox) = .empty;
            errdefer filtered.deinit(self.allocator);

            for (all_mailboxes) |mb| {
                const matches = switch (mailbox_type) {
                    .inbox => std.mem.eql(u8, mb.name, "INBOX"),
                    .drafts => mb.flags.drafts,
                    .sent => mb.flags.sent,
                    .trash => mb.flags.trash,
                    .junk => mb.flags.junk,
                    .archive => mb.flags.archive,
                };

                if (matches) {
                    try filtered.append(self.allocator, .{
                        .name = try self.allocator.dupe(u8, mb.name),
                        .delimiter = mb.delimiter,
                        .flags = mb.flags,
                        .decoded_name = if (mb.decoded_name) |dn| try self.allocator.dupe(u8, dn) else null,
                    });
                }
            }

            return filtered.toOwnedSlice(self.allocator);
        }

        /// Find a mailbox by name (case-insensitive for INBOX)
        pub fn findMailbox(self: *Self, name: []const u8) !?types.Mailbox {
            const all_mailboxes = try self.listMailboxes();
            defer {
                for (all_mailboxes) |*mb| {
                    mb.deinit(self.allocator);
                }
                self.allocator.free(all_mailboxes);
            }

            for (all_mailboxes) |mb| {
                const matches = if (std.mem.eql(u8, mb.name, "INBOX") or std.mem.eql(u8, name, "INBOX"))
                    std.ascii.eqlIgnoreCase(mb.name, name)
                else
                    std.mem.eql(u8, mb.name, name);

                if (matches) {
                    return .{
                        .name = try self.allocator.dupe(u8, mb.name),
                        .delimiter = mb.delimiter,
                        .flags = mb.flags,
                        .decoded_name = if (mb.decoded_name) |dn| try self.allocator.dupe(u8, dn) else null,
                    };
                }
            }

            return null;
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
