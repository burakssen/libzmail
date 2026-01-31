const std = @import("std");
const log = std.log.scoped(.curl);
const c = @cImport(@cInclude("curl/curl.h"));

const CurlHandle = @This();

handle: *c.CURL,

pub fn init() !CurlHandle {
    return .{ .handle = c.curl_easy_init() orelse return error.CurlInitFailed };
}

pub fn deinit(self: CurlHandle) void {
    c.curl_easy_cleanup(self.handle);
}

pub fn setOpt(self: CurlHandle, opt: c.CURLoption, value: anytype) !void {
    if (c.curl_easy_setopt(self.handle, opt, value) != c.CURLE_OK) {
        return error.SetOptionFailed;
    }
}

pub fn perform(self: CurlHandle) !void {
    const res = c.curl_easy_perform(self.handle);
    if (res != c.CURLE_OK) {
        log.err("CURL request failed: {d}", .{res});
        return error.RequestFailed;
    }
}

pub fn writeCallback(ptr: [*c]u8, size: usize, nmemb: usize, userdata: *anyopaque) callconv(.c) usize {
    const writer: *std.Io.Writer = @ptrCast(@alignCast(userdata));
    const total_size = size * nmemb;
    writer.writeAll(ptr[0..total_size]) catch return 0;
    return total_size;
}

pub fn readCallback(ptr: [*c]u8, size: usize, nmemb: usize, userdata: ?*anyopaque) callconv(.c) usize {
    const reader: *std.Io.Reader = @ptrCast(@alignCast(userdata));
    const max_copy = size * nmemb;

    if (max_copy == 0) return 0;

    const bytes_read = reader.readSliceShort(ptr[0..max_copy]) catch return 0;
    return bytes_read;
}
