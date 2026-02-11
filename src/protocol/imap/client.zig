const std = @import("std");
const c = @cImport(@cInclude("curl/curl.h"));
const utils = @import("utils");
const types = @import("types.zig");
const log = std.log.scoped(.imap);

const redundancy = @import("../redundancy.zig");

pub fn Client(comptime ProviderType: type) type {
    return struct {
        const Self = @This();

        curl: utils.CurlHandle,
        allocator: std.mem.Allocator,
        payload: types.ImapPayload,
        provider: *ProviderType,
        health_states: []redundancy.HealthState,

        pub fn init(allocator: std.mem.Allocator, payload: types.ImapPayload, provider: *ProviderType) !Self {
            const endpoint_count = 1 + payload.fallback_endpoints.len;
            const health_states = try allocator.alloc(redundancy.HealthState, endpoint_count);
            @memset(health_states, .{});

            return .{
                .curl = try utils.CurlHandle.init(),
                .allocator = allocator,
                .payload = payload,
                .provider = provider,
                .health_states = health_states,
            };
        }

        pub fn deinit(self: *Self) void {
            self.curl.deinit();
            self.allocator.free(self.health_states);
        }

        pub fn connect(self: *Self) !void {
            try self.provider.authenticate(self.curl.handle);
        }

        fn ensureAuthenticated(self: *Self) !void {
            try self.provider.authenticate(self.curl.handle);
        }

        /// List all mailboxes and return structured data
        pub fn listMailboxes(self: *Self) ![]types.Mailbox {
            const response = try self.listMailboxesRaw();
            defer self.allocator.free(response);

            return try self.parseMailboxList(response);
        }

        /// Get raw mailbox list response with redundancy support
        pub fn listMailboxesRaw(self: *Self) ![]const u8 {
            var attempt: u32 = 0;
            const policy = self.payload.redundancy_policy;

            while (attempt < policy.retry.max_attempts) : (attempt += 1) {
                if (attempt > 0) {
                    const backoff = redundancy.calculateBackoff(policy.retry, attempt);
                    log.info("Retrying in {d}ms (attempt {d}/{d})...", .{ backoff, attempt + 1, policy.retry.max_attempts });
                    std.Thread.sleep(backoff * std.time.ns_per_ms);
                }

                var endpoint_idx: usize = 0;
                while (endpoint_idx < self.health_states.len) : (endpoint_idx += 1) {
                    if (!self.health_states[endpoint_idx].isHealthy(policy.health)) continue;

                    const endpoint = if (endpoint_idx == 0)
                        redundancy.Endpoint{
                            .hostname = self.payload.hostname,
                            .port = self.payload.port,
                            .use_tls = self.payload.use_tls,
                        }
                    else
                        self.payload.fallback_endpoints[endpoint_idx - 1];

                    if (self.listMailboxesRawToEndpoint(endpoint)) |res| {
                        self.health_states[endpoint_idx].markHealthy();
                        return res;
                    } else |err| {
                        log.warn("Failed to list mailboxes from {s}:{d}: {any}", .{ endpoint.hostname, endpoint.port, err });
                        self.health_states[endpoint_idx].markUnhealthy();
                        continue;
                    }
                }
            }

            return error.AllEndpointsFailed;
        }

        fn listMailboxesRawToEndpoint(self: *Self, endpoint: redundancy.Endpoint) ![]const u8 {
            log.info("Listing mailboxes on {s}:{d}", .{ endpoint.hostname, endpoint.port });

            try self.ensureAuthenticated();

            // For IMAP: port 993 is usually implicit TLS (imaps://)
            // Port 143 is usually explicit TLS (imap:// + STARTTLS)
            const scheme = if (endpoint.use_tls and endpoint.port == 993) "imaps" else "imap";
            const url = try std.fmt.allocPrint(
                self.allocator,
                "{s}://{s}:{d}/",
                .{ scheme, endpoint.hostname, endpoint.port },
            );
            defer self.allocator.free(url);

            var response: std.Io.Writer.Allocating = .init(self.allocator);
            errdefer response.deinit();

            try self.configureListRequest(url, &response.writer, endpoint.use_tls);
            try self.curl.perform();

            log.info("Mailboxes listed successfully", .{});
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
                    errdefer {
                        for (filtered.items) |*mb| {
                            mb.deinit(self.allocator);
                        }
                        filtered.deinit(self.allocator);
                    }
        
                    for (all_mailboxes) |mb| {                const matches = switch (mailbox_type) {
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
                    var mb_copy = types.Mailbox{
                        .name = try self.allocator.dupe(u8, mb.name),
                        .delimiter = mb.delimiter,
                        .flags = mb.flags,
                        .decoded_name = null,
                    };
                    errdefer mb_copy.deinit(self.allocator);

                    if (mb.decoded_name) |dn| {
                        mb_copy.decoded_name = try self.allocator.dupe(u8, dn);
                    }
                    return mb_copy;
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

        fn configureListRequest(self: *Self, url: []const u8, writer: *std.Io.Writer, use_tls: bool) !void {
            try self.curl.setOpt(c.CURLOPT_URL, url.ptr);
            if (use_tls) {
                try self.curl.setOpt(c.CURLOPT_USE_SSL, @as(c_long, c.CURLUSESSL_ALL));
            }
            try self.curl.setOpt(c.CURLOPT_TIMEOUT, @as(c_long, 30));
            try self.curl.setOpt(c.CURLOPT_CONNECTTIMEOUT, @as(c_long, 10));
            try self.curl.setOpt(c.CURLOPT_WRITEFUNCTION, utils.CurlHandle.writeCallback);
            try self.curl.setOpt(c.CURLOPT_WRITEDATA, writer);
            try self.curl.setOpt(c.CURLOPT_CUSTOMREQUEST, "LIST \"\" \"*\"");
        }
    };
}
