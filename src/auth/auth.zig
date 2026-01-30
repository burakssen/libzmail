const std = @import("std");
const c = @cImport(@cInclude("curl/curl.h"));

pub const Provider = @import("provider.zig").Provider;
pub const types = @import("types.zig");

test {
    const allocator = std.testing.allocator;
    var provider = Provider(.basic).init(allocator, .{
        .username = "burak.sen@tum.de",
        .password = "testpassword",
    });
    defer provider.deinit();

    _ = c.curl_global_init(0);
    defer _ = c.curl_global_cleanup();

    const easy = c.curl_easy_init();
    if (easy) |easy_handle| {
        try provider.authenticate(easy_handle);
        _ = c.curl_easy_cleanup(easy_handle);
    }
}
