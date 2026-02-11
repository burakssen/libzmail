const std = @import("std");
const c = @cImport(@cInclude("curl/curl.h"));
const utils = @import("utils");
const types = @import("types.zig");
const log = std.log.scoped(.smtp);

const redundancy = @import("../redundancy.zig");

pub fn Client(comptime ProviderType: type) type {
    return struct {
        const Self = @This();

        curl: utils.CurlHandle,
        allocator: std.mem.Allocator,
        payload: types.SmtpPayload,
        provider: *ProviderType,
        health_states: []redundancy.HealthState,

        pub fn init(allocator: std.mem.Allocator, payload: types.SmtpPayload, provider: *ProviderType) !Self {
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

        pub fn send(self: *Self, data: types.MailPayload) !void {
            var attempt: u32 = 0;
            const policy = self.payload.redundancy_policy;

            while (attempt < policy.retry.max_attempts) : (attempt += 1) {
                if (attempt > 0) {
                    const backoff = redundancy.calculateBackoff(policy.retry, attempt);
                    log.info("Retrying in {d}ms (attempt {d}/{d})...", .{ backoff, attempt + 1, policy.retry.max_attempts });
                    std.Thread.sleep(backoff * std.time.ns_per_ms);
                }

                // Try each healthy endpoint
                var endpoint_idx: usize = 0;
                while (endpoint_idx < self.health_states.len) : (endpoint_idx += 1) {
                    if (!self.health_states[endpoint_idx].isHealthy(policy.health)) continue;

                    const endpoint = if (endpoint_idx == 0)
                        redundancy.Endpoint{
                            .hostname = self.payload.hostname[0..self.payload.hostname.len:0],
                            .port = self.payload.port,
                            .use_tls = self.payload.use_tls,
                        }
                    else
                        self.payload.fallback_endpoints[endpoint_idx - 1];

                    self.sendToEndpoint(endpoint, data) catch |err| {
                        log.warn("Failed to send to {s}:{d}: {any}", .{ endpoint.hostname, endpoint.port, err });
                        
                        // We need to classify the error if possible.
                        // For now we assume network-ish errors are transient and mark unhealthy.
                        // Ideally we'd have a way to get the CURLcode here.
                        self.health_states[endpoint_idx].markUnhealthy();
                        continue;
                    };

                    // Success!
                    self.health_states[endpoint_idx].markHealthy();
                    return;
                }

                if (endpoint_idx == self.health_states.len) {
                    log.err("All endpoints exhausted or unhealthy", .{});
                }
            }

            return error.AllEndpointsFailed;
        }

        fn sendToEndpoint(self: *Self, endpoint: redundancy.Endpoint, data: types.MailPayload) !void {
            log.info("Sending email to {s} via {s}:{d}", .{ data.to, endpoint.hostname, endpoint.port });

            try self.ensureAuthenticated();

            // Build URL
            // For SMTP: port 465 is usually implicit TLS (smtps://)
            // Port 587 and 25 are usually explicit TLS (smtp:// + STARTTLS)
            const scheme = if (endpoint.use_tls and endpoint.port == 465) "smtps" else "smtp";
            const url = try std.fmt.allocPrint(
                self.allocator,
                "{s}://{s}:{d}",
                .{ scheme, endpoint.hostname, endpoint.port },
            );
            defer self.allocator.free(url);

            // Set URL
            try self.curl.setOpt(c.CURLOPT_URL, url.ptr);

            // Set FROM and TO addresses
            try self.curl.setOpt(c.CURLOPT_MAIL_FROM, data.from.ptr);

            var recipients: ?*c.struct_curl_slist = null;
            recipients = c.curl_slist_append(recipients, data.to.ptr);
            defer c.curl_slist_free_all(recipients);

            try self.curl.setOpt(c.CURLOPT_MAIL_RCPT, recipients);

            const message = try std.fmt.allocPrint(
                self.allocator,
                "From: {s}\r\n" ++
                    "To: {s}\r\n" ++
                    "Subject: {s}\r\n" ++
                    "\r\n" ++
                    "{s}\r\n",
                .{ data.from, data.to, data.subject, data.body },
            );
            defer self.allocator.free(message);

            var reader: std.Io.Reader = .fixed(message);

            try self.curl.setOpt(c.CURLOPT_READDATA, &reader);
            try self.curl.setOpt(c.CURLOPT_READFUNCTION, utils.CurlHandle.readCallback);
            try self.curl.setOpt(c.CURLOPT_UPLOAD, @as(c_long, 1));

            if (endpoint.use_tls) {
                try self.curl.setOpt(c.CURLOPT_USE_SSL, @as(c_long, c.CURLUSESSL_ALL));
            }

            try self.curl.setOpt(c.CURLOPT_TIMEOUT, @as(c_long, 30));
            try self.curl.setOpt(c.CURLOPT_CONNECTTIMEOUT, @as(c_long, 10));

            // Perform the request
            self.curl.perform() catch |err| {
                // Here we could try to classify the error if we had more info
                return err;
            };

            log.info("Email sent successfully to {s}", .{data.to});
        }
    };
}
