const std = @import("std");
const c = @cImport(@cInclude("curl/curl.h"));
const types = @import("../types.zig");
const log = std.log.scoped(.smtp);

const ReadState = struct {
    data: []const u8,
    offset: usize = 0,
};

pub fn SmtpProtocol(comptime ProviderType: type) type {
    return struct {
        const Self = @This();

        curl: ?*c.CURL = null,
        allocator: std.mem.Allocator,
        payload: types.SmtpPayload,
        provider: ProviderType,

        pub fn init(allocator: std.mem.Allocator, payload: types.SmtpPayload, provider: ProviderType) Self {
            return .{
                .curl = c.curl_easy_init(),
                .allocator = allocator,
                .payload = payload,
                .provider = provider,
            };
        }

        pub fn deinit(self: *Self) void {
            if (self.curl) |ch| {
                c.curl_easy_cleanup(ch);
            }
            self.curl = null;
            self.provider.deinit();
        }

        pub fn connect(self: *Self) !void {
            if (self.curl) |ch| {
                try self.provider.authenticate(ch);
            }
        }

        pub fn send(self: *Self, data: types.MailPayload) !void {
            if (self.curl) |ch| {
                // Set CURL options for sending email via SMTP
                const url_str = try std.fmt.allocPrint(self.allocator, "smtp://{s}:{d}", .{ self.payload.hostname, self.payload.port });
                defer self.allocator.free(url_str);

                var res = c.curl_easy_setopt(ch, c.CURLOPT_URL, url_str.ptr);
                if (res != c.CURLPX_OK) {
                    log.err("Failed to set URL: {s}", .{c.curl_easy_strerror(res)});
                    return error.SetOptionFailed;
                }

                // Enable verbose output for debugging (maybe with config option)
                // _ = c.curl_easy_setopt(ch, c.CURLOPT_VERBOSE, @as(c_long, 1));

                // Set FROM and TO addresses
                res = c.curl_easy_setopt(ch, c.CURLOPT_MAIL_FROM, data.from.ptr);
                if (res != c.CURLPX_OK) {
                    log.err("Failed to set MAIL FROM: {s}", .{c.curl_easy_strerror(res)});
                    return error.SetOptionFailed;
                }

                // Create recipient list (CURLOPT_MAIL_RCPT expects a slist)
                var recipients: ?*c.struct_curl_slist = null;
                recipients = c.curl_slist_append(recipients, data.to.ptr);
                defer c.curl_slist_free_all(recipients);

                res = c.curl_easy_setopt(ch, c.CURLOPT_MAIL_RCPT, recipients);
                if (res != c.CURLPX_OK) {
                    log.err("Failed to set MAIL RCPT: {s}", .{c.curl_easy_strerror(res)});
                    return error.SetOptionFailed;
                }

                // Create properly formatted email message with all required headers
                const message = try std.fmt.allocPrint(self.allocator, "From: {s}\r\n" ++
                    "To: {s}\r\n" ++
                    "Subject: {s}\r\n" ++
                    "\r\n" ++
                    "{s}\r\n", .{ data.from, data.to, data.subject, data.body });
                defer self.allocator.free(message);

                // Create read state with the message
                var read_state = ReadState{
                    .data = message,
                    .offset = 0,
                };

                // Use CURLOPT_READDATA with a read callback
                res = c.curl_easy_setopt(ch, c.CURLOPT_READDATA, &read_state);
                if (res != c.CURLPX_OK) {
                    log.err("Failed to set READDATA: {s}", .{c.curl_easy_strerror(res)});
                    return error.SetOptionFailed;
                }
                res = c.curl_easy_setopt(ch, c.CURLOPT_READFUNCTION, readCallback);
                if (res != c.CURLPX_OK) {
                    log.err("Failed to set READFUNCTION: {s}", .{c.curl_easy_strerror(res)});
                    return error.SetOptionFailed;
                }
                res = c.curl_easy_setopt(ch, c.CURLOPT_UPLOAD, @as(c_long, 1));
                if (res != c.CURLPX_OK) {
                    log.err("Failed to set UPLOAD: {s}", .{c.curl_easy_strerror(res)});
                    return error.SetOptionFailed;
                }

                // If using port 465 (SMTPS) or need TLS
                if (self.payload.port == 465) {
                    res = c.curl_easy_setopt(ch, c.CURLOPT_USE_SSL, @as(c_long, c.CURLUSESSL_ALL));
                    if (res != c.CURLPX_OK) {
                        log.err("Failed to set USE_SSL: {s}", .{c.curl_easy_strerror(res)});
                        return error.SetOptionFailed;
                    }
                } else if (self.payload.port == 587) {
                    // Port 587 typically uses STARTTLS
                    res = c.curl_easy_setopt(ch, c.CURLOPT_USE_SSL, @as(c_long, c.CURLUSESSL_ALL));
                    if (res != c.CURLPX_OK) {
                        log.err("Failed to set USE_SSL: {s}", .{c.curl_easy_strerror(res)});
                        return error.SetOptionFailed;
                    }
                }

                res = c.curl_easy_perform(ch);
                if (res != c.CURLE_OK) {
                    log.err("Failed to send email: {s}", .{c.curl_easy_strerror(res)});
                    return error.SendFailed;
                }

                log.info("Email sent successfully to {s}", .{data.to});
            }
        }

        fn readCallback(ptr: [*c]u8, size: usize, nmemb: usize, userdata: ?*anyopaque) callconv(.c) usize {
            const state: *ReadState = @ptrCast(@alignCast(userdata));
            const available = state.data.len - state.offset;
            const max_copy = size * nmemb;
            const to_copy = @min(available, max_copy);

            if (to_copy == 0) return 0;

            @memcpy(ptr[0..to_copy], state.data[state.offset..][0..to_copy]);
            state.offset += to_copy;

            return to_copy;
        }
    };
}
