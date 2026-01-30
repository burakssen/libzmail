const std = @import("std");
const log = std.log.scoped(.basic_provider);

const c = @cImport(@cInclude("curl/curl.h"));

const types = @import("../types.zig");

const BasicProvider = @This();

payload: types.BasicPayload,

// Added allocator as argument so that it matches to other providers
pub fn init(_: std.mem.Allocator, payload: types.BasicPayload) BasicProvider {
    return .{
        .payload = payload,
    };
}
// Similarly add deinit function so that it matches to other providers
pub fn deinit(_: *BasicProvider) void {}

pub fn authenticate(self: *BasicProvider, curl: *c.CURL) !void {
    var res = c.curl_easy_setopt(curl, c.CURLOPT_USERNAME, self.payload.username.ptr);
    if (res != c.CURLPX_OK) {
        log.err("Failed to set username for basic authentication: {s}", .{c.curl_easy_strerror(res)});
    }
    res = c.curl_easy_setopt(curl, c.CURLOPT_PASSWORD, self.payload.password.ptr);
    if (res != c.CURLPX_OK) {
        log.err("Failed to set password for basic authentication: {s}", .{c.curl_easy_strerror(res)});
    }
    log.info("Basic authentication configured successfully", .{});
}
