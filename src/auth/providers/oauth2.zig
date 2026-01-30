const std = @import("std");
const c = @cImport(@cInclude("curl/curl.h"));
const log = std.log.scoped(.oauth2_provider);
const types = @import("../types.zig");

const OAuth2Provider = @This();

allocator: std.mem.Allocator,
payload: types.OAuth2Payload,
access_token: ?[]const u8 = null,
code_verifier: ?[]const u8 = null,
username: ?[]const u8 = null,

pub fn init(allocator: std.mem.Allocator, payload: types.OAuth2Payload) OAuth2Provider {
    return .{
        .allocator = allocator,
        .payload = payload,
    };
}

pub fn deinit(self: *OAuth2Provider) void {
    if (self.access_token) |token| {
        self.allocator.free(token);
    }
    if (self.code_verifier) |verifier| {
        self.allocator.free(verifier);
    }
    if (self.username) |user| {
        self.allocator.free(user);
    }
}

pub fn authenticate(self: *OAuth2Provider, curl: *c.CURL) !void {
    // If we already have a token, use it
    if (self.access_token) |token| {
        try self.setAuthHeader(curl, token);
        return;
    }

    // Otherwise, perform OAuth2 flow
    try self.performOAuth2Flow(curl);
}

fn performOAuth2Flow(self: *OAuth2Provider, curl: *c.CURL) !void {
    // Generate PKCE values
    const code_verifier = try self.generateCodeVerifier();
    errdefer self.allocator.free(code_verifier);

    const code_challenge = try self.generateCodeChallenge(code_verifier);
    defer self.allocator.free(code_challenge);

    // Build authorization URL
    const auth_url = try self.buildAuthorizationUrl(code_challenge);
    defer self.allocator.free(auth_url);

    // Prompt user to visit the URL
    log.info("Opening authorization URL in your browser...", .{});
    log.info("{s}", .{auth_url});

    // Open the URL in the default browser
    try self.openBrowser(auth_url);

    // Start local server and wait for code
    log.info("Waiting for callback on {s}...", .{self.payload.redirect_uri});
    const auth_code_owned = try self.listenForCallback();
    defer self.allocator.free(auth_code_owned);
    const auth_code = auth_code_owned;

    // Exchange authorization code for access token
    const access_token = try self.exchangeCodeForToken(curl, auth_code, code_verifier);

    // Store the verifier and token
    self.code_verifier = code_verifier;
    self.access_token = access_token;

    // Fetch user info to get the email
    const username = try self.fetchUserInfo(curl, access_token);
    self.username = username;
    log.info("Authenticated as: {s}", .{username});

    // Set the authorization header
    try self.setAuthHeader(curl, access_token);

    log.info("OAuth2 authentication configured successfully", .{});
}

fn fetchUserInfo(self: *OAuth2Provider, curl: *c.CURL, access_token: []const u8) ![]const u8 {
    const userinfo_endpoint = "https://www.googleapis.com/oauth2/v2/userinfo";

    _ = c.curl_easy_reset(curl);

    const res1 = c.curl_easy_setopt(curl, c.CURLOPT_URL, userinfo_endpoint);
    if (res1 != c.CURLE_OK) return error.CurlSetoptFailed;

    const auth_header = try std.fmt.allocPrint(self.allocator, "Authorization: Bearer {s}", .{access_token});
    defer self.allocator.free(auth_header);

    var headers: ?*c.struct_curl_slist = null;
    headers = c.curl_slist_append(headers, auth_header.ptr);
    defer c.curl_slist_free_all(headers);

    const res2 = c.curl_easy_setopt(curl, c.CURLOPT_HTTPHEADER, headers);
    if (res2 != c.CURLE_OK) return error.CurlSetoptFailed;

    var response: std.Io.Writer.Allocating = .init(self.allocator);
    errdefer response.deinit();

    const res3 = c.curl_easy_setopt(curl, c.CURLOPT_WRITEFUNCTION, writeCallback);
    if (res3 != c.CURLE_OK) return error.CurlSetoptFailed;

    const res4 = c.curl_easy_setopt(curl, c.CURLOPT_WRITEDATA, &response);
    if (res4 != c.CURLE_OK) return error.CurlSetoptFailed;

    const res5 = c.curl_easy_perform(curl);
    if (res5 != c.CURLE_OK) {
        log.err("Failed to fetch user info: {s}", .{c.curl_easy_strerror(res5)});
        return error.CurlPerformFailed;
    }

    const response_json = try response.toOwnedSlice();
    defer self.allocator.free(response_json);

    const UserInfo = struct {
        email: []const u8,
    };

    const parsed = try std.json.parseFromSlice(
        UserInfo,
        self.allocator,
        response_json,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed.deinit();

    return try self.allocator.dupe(u8, parsed.value.email);
}

fn openBrowser(self: *OAuth2Provider, url: []const u8) !void {
    const builtin = @import("builtin");

    var argv: []const []const u8 = undefined;

    switch (builtin.os.tag) {
        .macos => {
            argv = &[_][]const u8{ "open", url };
        },
        .linux => {
            argv = &[_][]const u8{ "xdg-open", url };
        },
        .windows => {
            argv = &[_][]const u8{ "cmd", "/c", "start", url };
        },
        else => {
            log.warn("Unsupported platform for automatic browser opening. Please manually visit the URL above.", .{});
            return;
        },
    }

    var child = std.process.Child.init(argv, self.allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;

    _ = child.spawn() catch |err| {
        log.warn("Failed to open browser automatically: {any}. Please manually visit the URL above.", .{err});
        return;
    };

    // We don't wait for the process to complete since browsers may detach
}

fn listenForCallback(self: *OAuth2Provider) ![]const u8 {
    const uri = try std.Uri.parse(self.payload.redirect_uri);
    const port = uri.port orelse return error.PortNotFoundInRedirectUri;

    // Listen on 127.0.0.1
    const address = try std.net.Address.parseIp("127.0.0.1", port);
    var server = try address.listen(.{
        .kernel_backlog = 1,
        .reuse_address = true,
    });
    defer server.deinit();

    // Accept one connection
    const connection = try server.accept();
    defer connection.stream.close();

    var buf: [4096]u8 = undefined;
    const len = try connection.stream.read(&buf);
    const request = buf[0..len];

    // Find "code="
    const code_marker = "code=";
    const start_idx = std.mem.indexOf(u8, request, code_marker);

    if (start_idx) |idx| {
        const code_start = idx + code_marker.len;
        var code_end = code_start;
        while (code_end < request.len) : (code_end += 1) {
            const char = request[code_end];
            if (char == '&' or char == ' ' or char == '\r' or char == '\n') break;
        }

        const code = request[code_start..code_end];

        // Respond
        const response_body =
            \\<!DOCTYPE html>
            \\<html>
            \\<body style="font-family: sans-serif; text-align: center; padding-top: 50px;">
            \\<h1>Authorization Successful</h1>
            \\<p>You can verify the authentication in your terminal and close this window.</p>
            \\<script>window.close()</script>
            \\</body>
            \\</html>
        ;

        const response_header = try std.fmt.allocPrint(self.allocator, "HTTP/1.1 200 OK\r\n" ++
            "Content-Type: text/html\r\n" ++
            "Content-Length: {d}\r\n" ++
            "Connection: close\r\n" ++
            "\r\n", .{response_body.len});
        defer self.allocator.free(response_header);

        _ = try connection.stream.writeAll(response_header);
        _ = try connection.stream.writeAll(response_body);

        return try self.allocator.dupe(u8, code);
    } else {
        return error.CodeNotFoundInRequest;
    }
}

fn generateCodeVerifier(self: *OAuth2Provider) ![]const u8 {
    // Generate 43-128 character random string (we'll use 64 characters)
    const verifier_len = 64;
    const verifier = try self.allocator.alloc(u8, verifier_len);
    errdefer self.allocator.free(verifier);

    var prng = std.Random.DefaultPrng.init(blk: {
        var seed: u64 = undefined;
        try std.posix.getrandom(std.mem.asBytes(&seed));
        break :blk seed;
    });
    const rand = prng.random();

    const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    for (verifier) |*byte| {
        byte.* = charset[rand.intRangeAtMost(usize, 0, charset.len - 1)];
    }

    return verifier;
}

fn generateCodeChallenge(self: *OAuth2Provider, verifier: []const u8) ![]const u8 {
    // SHA256 hash the verifier
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(verifier, &hash, .{});

    // Base64url encode (without padding)
    const encoder = std.base64.url_safe_no_pad.Encoder;
    const encoded_len = encoder.calcSize(hash.len);
    const challenge = try self.allocator.alloc(u8, encoded_len);
    _ = encoder.encode(challenge, &hash);

    return challenge;
}

fn urlEncode(self: *OAuth2Provider, input: []const u8) ![]const u8 {
    var result: std.Io.Writer.Allocating = .init(self.allocator);
    errdefer result.deinit();

    var writer = &result.writer;

    for (input) |byte| {
        if (std.ascii.isAlphanumeric(byte) or byte == '-' or byte == '_' or byte == '.' or byte == '~') {
            try writer.writeByte(byte);
        } else {
            try writer.print("%{X:0>2}", .{byte});
        }
    }

    return result.toOwnedSlice();
}

fn buildAuthorizationUrl(self: *OAuth2Provider, code_challenge: []const u8) ![]const u8 {
    // URL encode the redirect_uri
    const encoded_redirect = try self.urlEncode(self.payload.redirect_uri);
    defer self.allocator.free(encoded_redirect);

    var url: std.Io.Writer.Allocating = .init(self.allocator);
    errdefer url.deinit();

    const writer = &url.writer;
    try writer.print("{s}?response_type=code&client_id={s}&redirect_uri={s}&code_challenge={s}&code_challenge_method=S256", .{
        self.payload.auth_endpoint,
        self.payload.client_id,
        encoded_redirect,
        code_challenge,
    });

    // Add scope if provided
    if (self.payload.scope) |scopes| {
        if (scopes.len > 0) {
            try writer.writeAll("&scope=");
            for (scopes, 0..) |scope, i| {
                if (i > 0) try writer.writeAll("%20");
                const encoded_scope = try self.urlEncode(scope);
                defer self.allocator.free(encoded_scope);
                try writer.writeAll(encoded_scope);
            }
        }
    }

    return url.toOwnedSlice();
}

fn exchangeCodeForToken(self: *OAuth2Provider, curl: *c.CURL, auth_code: []const u8, code_verifier: []const u8) ![]const u8 {
    // Build POST data - URL encode parameters (except code_verifier which is already URL-safe)
    const encoded_code = try self.urlEncode(auth_code);
    defer self.allocator.free(encoded_code);

    const encoded_redirect = try self.urlEncode(self.payload.redirect_uri);
    defer self.allocator.free(encoded_redirect);

    const encoded_client_id = try self.urlEncode(self.payload.client_id);
    defer self.allocator.free(encoded_client_id);

    // Note: code_verifier should NOT be URL-encoded as per PKCE spec
    // It only contains URL-safe characters (A-Z, a-z, 0-9, -, ., _, ~)

    var post_data: std.Io.Writer.Allocating = .init(self.allocator);
    defer post_data.deinit();

    const writer = &post_data.writer;
    try writer.print("grant_type=authorization_code&code={s}&redirect_uri={s}&client_id={s}&code_verifier={s}", .{
        encoded_code,
        encoded_redirect,
        encoded_client_id,
        code_verifier, // Use raw code_verifier, not encoded
    });

    // Set up curl for token exchange
    const res1 = c.curl_easy_setopt(curl, c.CURLOPT_URL, self.payload.token_endpoint.ptr);
    if (res1 != c.CURLE_OK) {
        log.err("Failed to set token endpoint URL: {s}", .{c.curl_easy_strerror(res1)});
        return error.CurlSetoptFailed;
    }

    const post_data_slice = post_data.written();
    const res2 = c.curl_easy_setopt(curl, c.CURLOPT_POSTFIELDS, post_data_slice.ptr);
    if (res2 != c.CURLE_OK) {
        log.err("Failed to set POST data: {s}", .{c.curl_easy_strerror(res2)});
        return error.CurlSetoptFailed;
    }

    const res2_size = c.curl_easy_setopt(curl, c.CURLOPT_POSTFIELDSIZE, @as(c_long, @intCast(post_data_slice.len)));
    if (res2_size != c.CURLE_OK) {
        log.err("Failed to set POST data size: {s}", .{c.curl_easy_strerror(res2_size)});
        return error.CurlSetoptFailed;
    }

    // Capture response
    var response: std.Io.Writer.Allocating = .init(self.allocator);
    errdefer response.deinit();

    const res3 = c.curl_easy_setopt(curl, c.CURLOPT_WRITEFUNCTION, writeCallback);
    if (res3 != c.CURLE_OK) {
        log.err("Failed to set write callback: {s}", .{c.curl_easy_strerror(res3)});
        return error.CurlSetoptFailed;
    }

    const res4 = c.curl_easy_setopt(curl, c.CURLOPT_WRITEDATA, &response);
    if (res4 != c.CURLE_OK) {
        log.err("Failed to set write data: {s}", .{c.curl_easy_strerror(res4)});
        return error.CurlSetoptFailed;
    }

    // Perform request
    const res5 = c.curl_easy_perform(curl);
    if (res5 != c.CURLE_OK) {
        log.err("Failed to perform token exchange: {s}", .{c.curl_easy_strerror(res5)});
        return error.CurlPerformFailed;
    }

    // Parse JSON response to extract access_token
    const response_json = try response.toOwnedSlice();
    defer self.allocator.free(response_json);

    log.debug("Token response: {s}\n", .{response_json});

    const TokenResponse = struct {
        access_token: ?[]const u8 = null,
        @"error": ?[]const u8 = null,
        error_description: ?[]const u8 = null,
    };

    const parsed = try std.json.parseFromSlice(
        TokenResponse,
        self.allocator,
        response_json,
        .{
            .ignore_unknown_fields = true,
        },
    );
    defer parsed.deinit();

    if (parsed.value.access_token) |token| {
        return try self.allocator.dupe(u8, token);
    } else if (parsed.value.@"error") |err_msg| {
        log.err("OAuth2 error: {s} - {s}", .{ err_msg, parsed.value.error_description orelse "Unknown error" });
        return error.OAuth2Error;
    } else {
        return error.MissingAccessToken;
    }
}

fn setAuthHeader(self: *OAuth2Provider, curl: *c.CURL, token: []const u8) !void {
    // For both HTTP and SMTP, CURLOPT_XOAUTH2_BEARER is the correct way to pass the token
    // when using libcurl's SASL/OAuth2 support.
    var res = c.curl_easy_setopt(curl, c.CURLOPT_XOAUTH2_BEARER, token.ptr);
    if (res != c.CURLE_OK) {
        log.err("Failed to set XOAUTH2 bearer token: {s}", .{c.curl_easy_strerror(res)});
        return error.CurlSetoptFailed;
    }

    if (self.username) |username| {
        res = c.curl_easy_setopt(curl, c.CURLOPT_USERNAME, username.ptr);
        if (res != c.CURLE_OK) {
            log.err("Failed to set username: {s}", .{c.curl_easy_strerror(res)});
            return error.CurlSetoptFailed;
        }
    }

    // Force SASL XOAUTH2
    res = c.curl_easy_setopt(curl, c.CURLOPT_LOGIN_OPTIONS, "AUTH=XOAUTH2");
    if (res != c.CURLE_OK) {
        log.err("Failed to set login options: {s}", .{c.curl_easy_strerror(res)});
        return error.CurlSetoptFailed;
    }
}

fn writeCallback(ptr: *anyopaque, size: c_uint, nmemb: c_uint, userdata: *anyopaque) callconv(.c) c_uint {
    const actual_size = size * nmemb;
    const buffer: [*]const u8 = @ptrCast(ptr);
    const response: *std.Io.Writer.Allocating = @ptrCast(@alignCast(userdata));

    var response_writer = &response.writer;
    response_writer.writeAll(buffer[0..actual_size]) catch return 0;
    return actual_size;
}
