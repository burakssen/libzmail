const std = @import("std");
const c = @cImport(@cInclude("curl/curl.h"));
const utils = @import("utils");
const types = @import("types.zig");
const log = std.log.scoped(.smtp);

pub fn SmtpProtocol(comptime ProviderType: type) type {
    return struct {
        const Self = @This();

        curl: utils.CurlHandle,
        allocator: std.mem.Allocator,
        payload: types.SmtpPayload,
        provider: ProviderType,

        pub fn init(allocator: std.mem.Allocator, payload: types.SmtpPayload, provider: ProviderType) !Self {
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

        pub fn send(self: *Self, data: types.MailPayload) !void {
            log.info("Sending email to {s} via {s}:{d}", .{ data.to, self.payload.hostname, self.payload.port });

            // Build URL
            const url = try std.fmt.allocPrint(
                self.allocator,
                "smtp://{s}:{d}",
                .{ self.payload.hostname, self.payload.port },
            );
            defer self.allocator.free(url);

            // Set URL
            try self.curl.setOpt(c.CURLOPT_URL, url.ptr);

            // Enable verbose output for debugging (optional)
            // try self.curl.setOpt(c.CURLOPT_VERBOSE, @as(c_long, 1));

            // Set FROM and TO addresses
            try self.curl.setOpt(c.CURLOPT_MAIL_FROM, data.from.ptr);

            // Create recipient list (CURLOPT_MAIL_RCPT expects a slist)
            var recipients: ?*c.struct_curl_slist = null;
            recipients = c.curl_slist_append(recipients, data.to.ptr);
            defer c.curl_slist_free_all(recipients);

            try self.curl.setOpt(c.CURLOPT_MAIL_RCPT, recipients);

            // Create properly formatted email message with all required headers
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

            // Create a fixed buffer stream reader from the message
            var reader: std.Io.Reader = .fixed(message);

            // Use CURLOPT_READDATA with a read callback
            try self.curl.setOpt(c.CURLOPT_READDATA, &reader);
            try self.curl.setOpt(c.CURLOPT_READFUNCTION, utils.CurlHandle.readCallback);
            try self.curl.setOpt(c.CURLOPT_UPLOAD, @as(c_long, 1));

            // Configure SSL/TLS based on port
            if (self.payload.port == 465) {
                // Port 465 uses implicit SSL (SMTPS)
                try self.curl.setOpt(c.CURLOPT_USE_SSL, @as(c_long, c.CURLUSESSL_ALL));
            } else if (self.payload.port == 587) {
                // Port 587 typically uses STARTTLS
                try self.curl.setOpt(c.CURLOPT_USE_SSL, @as(c_long, c.CURLUSESSL_ALL));
            }

            // Set timeouts
            try self.curl.setOpt(c.CURLOPT_TIMEOUT, @as(c_long, 30));
            try self.curl.setOpt(c.CURLOPT_CONNECTTIMEOUT, @as(c_long, 10));

            // Perform the request
            try self.curl.perform();

            log.info("Email sent successfully to {s}", .{data.to});
        }
    };
}
