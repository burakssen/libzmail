const std = @import("std");
const log = std.log.scoped(.oauth2);

const c = @cImport(@cInclude("curl/curl.h"));
const types = @import("../types.zig");

const OAuth2Provider = @This();

const response_page = @embedFile("index.html");

allocator: std.mem.Allocator,
payload: types.OAuth2Payload,
access_token: ?[]const u8 = null,
username: ?[]const u8 = null,

pub fn init(allocator: std.mem.Allocator, payload: types.OAuth2Payload) OAuth2Provider {
    return .{
        .allocator = allocator,
        .payload = payload,
    };
}

pub fn deinit(self: *OAuth2Provider) void {
    if (self.access_token) |t| self.allocator.free(t);
    if (self.username) |u| self.allocator.free(u);
}

pub fn authenticate(self: *OAuth2Provider, curl: *c.CURL) !void {
    if (self.access_token) |token| {
        return self.setAuthHeader(curl, token);
    }

    try self.performFlow(curl);

    if (self.access_token) |token| {
        try self.setAuthHeader(curl, token);
    } else {
        return error.AuthenticationFailed;
    }
}

fn performFlow(self: *OAuth2Provider, curl: *c.CURL) !void {
    // 1. Setup PKCE
    const code_verifier = try self.generateRandomString(64);
    defer self.allocator.free(code_verifier);

    const code_challenge = try self.generateCodeChallenge(code_verifier);
    defer self.allocator.free(code_challenge);

    // 2. Authorization Step
    const auth_url = try self.buildAuthorizationUrl(code_challenge);
    defer self.allocator.free(auth_url);

    log.info("Opening authorization URL: {s}", .{auth_url});
    try self.openBrowser(auth_url);

    const auth_code = try self.listenForCallback();
    defer self.allocator.free(auth_code);

    // 3. Token Exchange Step
    const tokens = try self.exchangeCodeForToken(curl, auth_code, code_verifier);
    defer {
        if (tokens.id_token) |t| self.allocator.free(t);
        self.allocator.free(tokens.access_token);
    }

    self.access_token = try self.allocator.dupe(u8, tokens.access_token);

    // 4. User Info Step
    if (tokens.id_token) |idt| {
        if (try self.extractEmailFromIdToken(idt)) |email| {
            self.username = email;
        }
    }

    if (self.username == null) {
        log.info("Fetching user info from endpoint...", .{});
        self.username = try self.fetchUserInfo(curl, self.access_token.?);
    }

    log.info("Authenticated as: {s}", .{self.username.?});
}

fn setAuthHeader(self: *OAuth2Provider, curl: *c.CURL, token: []const u8) !void {
    var res = c.curl_easy_setopt(curl, c.CURLOPT_XOAUTH2_BEARER, token.ptr);
    if (res != c.CURLE_OK) return error.CurlSetoptFailed;

    if (self.username) |u| {
        res = c.curl_easy_setopt(curl, c.CURLOPT_USERNAME, u.ptr);
        if (res != c.CURLE_OK) return error.CurlSetoptFailed;
    }

    res = c.curl_easy_setopt(curl, c.CURLOPT_LOGIN_OPTIONS, "AUTH=XOAUTH2");
    if (res != c.CURLE_OK) return error.CurlSetoptFailed;
}

// --- OAuth2 Helpers ---

fn buildAuthorizationUrl(self: *OAuth2Provider, challenge: []const u8) ![]const u8 {
    var query: std.Io.Writer.Allocating = .init(self.allocator);
    defer query.deinit();

    const writer = &query.writer;
    try writer.print("{s}?response_type=code&client_id={s}&code_challenge={s}&code_challenge_method=S256", .{
        self.payload.client_options.auth_endpoint,
        self.payload.client_id,
        challenge,
    });

    try writer.writeAll("&redirect_uri=");
    try self.percentEncodeWriter(writer, self.payload.client_options.redirect_uri);

    if (self.payload.client_options.scopes) |scopes| {
        if (scopes.len > 0) {
            try writer.writeAll("&scope=");
            for (scopes, 0..) |scope, i| {
                if (i > 0) try writer.writeAll("%20");
                try self.percentEncodeWriter(writer, scope);
            }
        }
    }

    return query.toOwnedSlice();
}

const TokenResult = struct {
    access_token: []const u8,
    id_token: ?[]const u8,
};

fn exchangeCodeForToken(self: *OAuth2Provider, curl: *c.CURL, code: []const u8, verifier: []const u8) !TokenResult {
    var form: std.Io.Writer.Allocating = .init(self.allocator);
    defer form.deinit();

    const writer = &form.writer;
    try writer.writeAll("grant_type=authorization_code&code=");
    try self.percentEncodeWriter(writer, code);
    try writer.writeAll("&redirect_uri=");
    try self.percentEncodeWriter(writer, self.payload.client_options.redirect_uri);
    try writer.writeAll("&client_id=");
    try self.percentEncodeWriter(writer, self.payload.client_id);
    try writer.print("&code_verifier={s}", .{verifier});

    const body = try self.performRequest(curl, self.payload.client_options.token_endpoint, form.written(), null);
    defer self.allocator.free(body);

    const Resp = struct {
        access_token: []const u8,
        id_token: ?[]const u8 = null,
        @"error": ?[]const u8 = null,
        error_description: ?[]const u8 = null,
    };

    const parsed = try std.json.parseFromSlice(Resp, self.allocator, body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    if (parsed.value.@"error") |err| {
        log.err("OAuth2 Error: {s} ({?s})", .{ err, parsed.value.error_description });
        return error.OAuth2Error;
    }

    return .{
        .access_token = try self.allocator.dupe(u8, parsed.value.access_token),
        .id_token = if (parsed.value.id_token) |t| try self.allocator.dupe(u8, t) else null,
    };
}

fn fetchUserInfo(self: *OAuth2Provider, curl: *c.CURL, token: []const u8) ![]const u8 {
    const auth_header = try std.fmt.allocPrint(self.allocator, "Authorization: Bearer {s}", .{token});
    defer self.allocator.free(auth_header);

    const body = try self.performRequest(curl, self.payload.client_options.userinfo_endpoint, null, auth_header);
    defer self.allocator.free(body);

    const User = struct { email: []const u8 };
    const parsed = try std.json.parseFromSlice(User, self.allocator, body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    return self.allocator.dupe(u8, parsed.value.email);
}

// --- Utils ---

fn performRequest(self: *OAuth2Provider, curl: *c.CURL, url: []const u8, post_data: ?[]const u8, header: ?[]const u8) ![]const u8 {
    _ = c.curl_easy_reset(curl);

    var res = c.curl_easy_setopt(curl, c.CURLOPT_URL, url.ptr);
    if (res != c.CURLE_OK) return error.CurlSetoptFailed;

    if (post_data) |data| {
        res = c.curl_easy_setopt(curl, c.CURLOPT_POSTFIELDS, data.ptr);
        res = c.curl_easy_setopt(curl, c.CURLOPT_POSTFIELDSIZE, @as(c_long, @intCast(data.len)));
    }

    var headers: ?*c.struct_curl_slist = null;
    defer if (headers != null) c.curl_slist_free_all(headers);

    if (header) |h| {
        headers = c.curl_slist_append(headers, h.ptr);
        res = c.curl_easy_setopt(curl, c.CURLOPT_HTTPHEADER, headers);
    }

    var resp_buf: std.Io.Writer.Allocating = .init(self.allocator);
    defer resp_buf.deinit();

    const response_writer = &resp_buf.writer;

    res = c.curl_easy_setopt(curl, c.CURLOPT_WRITEFUNCTION, writeCallback);
    res = c.curl_easy_setopt(curl, c.CURLOPT_WRITEDATA, response_writer);

    res = c.curl_easy_perform(curl);
    if (res != c.CURLE_OK) {
        log.err("Request failed: {s}", .{c.curl_easy_strerror(res)});
        return error.CurlPerformFailed;
    }

    return resp_buf.toOwnedSlice();
}

fn writeCallback(ptr: *anyopaque, size: c_uint, nmemb: c_uint, userdata: *anyopaque) callconv(.c) c_uint {
    const real_size = size * nmemb;
    const buffer: [*]const u8 = @ptrCast(ptr);
    const list: *std.Io.Writer = @ptrCast(@alignCast(userdata));
    list.writeAll(buffer[0..real_size]) catch return 0;
    return real_size;
}

fn listenForCallback(self: *OAuth2Provider) ![]const u8 {
    const uri = try std.Uri.parse(self.payload.client_options.redirect_uri);
    const port = uri.port orelse return error.MissingPortInRedirectURI;

    const addr = try std.net.Address.parseIp("127.0.0.1", port);
    var server = try addr.listen(.{ .reuse_address = true });
    defer server.deinit();

    const conn = try server.accept();
    defer conn.stream.close();

    var buf: [4096]u8 = undefined;
    const len = try conn.stream.read(&buf);
    const req = buf[0..len];

    // Simple parser for "code=..."
    // We look for "code=" followed by chars until space or &
    const marker = "code=";
    if (std.mem.indexOf(u8, req, marker)) |idx| {
        const start = idx + marker.len;
        var end = start;
        while (end < req.len) : (end += 1) {
            const char = req[end];
            if (char == ' ' or char == '&' or char == '\r' or char == '\n') break;
        }

        const raw_code = req[start..end];

        const resp = std.fmt.allocPrint(self.allocator, "HTTP/1.1 200 OK\r\n" ++
            "Content-Type: text/html; charset=utf-8\r\n" ++
            "Content-Length: {d}\r\n" ++
            "Connection: close\r\n" ++
            "\r\n" ++
            "{s}", .{ response_page.len, response_page }) catch unreachable;
        defer self.allocator.free(resp);

        _ = try conn.stream.writeAll(resp);

        return self.percentDecode(raw_code);
    }
    return error.CodeNotFound;
}

fn generateCodeChallenge(self: *OAuth2Provider, verifier: []const u8) ![]const u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(verifier, &hash, .{});

    const encoder = std.base64.url_safe_no_pad.Encoder;
    const len = encoder.calcSize(hash.len);
    const out = try self.allocator.alloc(u8, len);
    _ = encoder.encode(out, &hash);
    return out;
}

fn generateRandomString(self: *OAuth2Provider, len: usize) ![]const u8 {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    const out = try self.allocator.alloc(u8, len);

    // Use crypto secure random
    var seed: [8]u8 = undefined;
    try std.posix.getrandom(&seed);
    var prng = std.Random.DefaultPrng.init(std.mem.readInt(u64, &seed, .little));
    const random = prng.random();

    for (out) |*c_ptr| {
        c_ptr.* = chars[random.intRangeAtMost(usize, 0, chars.len - 1)];
    }
    return out;
}

fn extractEmailFromIdToken(self: *OAuth2Provider, id_token: []const u8) !?[]const u8 {
    var it = std.mem.splitScalar(u8, id_token, '.');
    _ = it.next(); // header
    const payload_b64 = it.next() orelse return null;

    // Use a decoder that ignores padding if needed
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const decoded_len = try decoder.calcSizeForSlice(payload_b64);

    const payload_json = try self.allocator.alloc(u8, decoded_len);
    defer self.allocator.free(payload_json);
    try decoder.decode(payload_json, payload_b64);

    const Payload = struct { email: ?[]const u8 = null, preferred_username: ?[]const u8 = null };
    const parsed = try std.json.parseFromSlice(Payload, self.allocator, payload_json, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();

    if (parsed.value.email) |e| return try self.allocator.dupe(u8, e);
    if (parsed.value.preferred_username) |u| return try self.allocator.dupe(u8, u);
    return null;
}

fn openBrowser(self: *OAuth2Provider, url: []const u8) !void {
    const argv: []const []const u8 = switch (@import("builtin").os.tag) {
        .macos => &.{ "open", url },
        .windows => &.{ "cmd", "/c", "start", url },
        else => &.{ "xdg-open", url },
    };

    var child = std.process.Child.init(argv, self.allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    _ = child.spawn() catch |err| {
        log.warn("Failed to open browser: {any}", .{err});
    };
}

fn percentEncodeWriter(self: *OAuth2Provider, w: anytype, input: []const u8) !void {
    _ = self;
    for (input) |byte| {
        if (std.ascii.isAlphanumeric(byte) or byte == '-' or byte == '_' or byte == '.' or byte == '~') {
            try w.writeByte(byte);
        } else {
            try w.print("%{X:0>2}", .{byte});
        }
    }
}

fn percentDecode(self: *OAuth2Provider, input: []const u8) ![]const u8 {
    var out: std.Io.Writer.Allocating = try .initCapacity(self.allocator, input.len);
    defer out.deinit();

    const writer = &out.writer;

    var i: usize = 0;
    while (i < input.len) {
        if (input[i] == '%' and i + 2 < input.len) {
            const hex = input[i + 1 .. i + 3];
            if (std.fmt.parseInt(u8, hex, 16)) |b| {
                try writer.writeByte(b);
                i += 3;
            } else |_| {
                try writer.writeByte(input[i]);
                i += 1;
            }
        } else if (input[i] == '+') {
            try writer.writeByte(' ');
            i += 1;
        } else {
            try writer.writeByte(input[i]);
            i += 1;
        }
    }
    return out.toOwnedSlice();
}
