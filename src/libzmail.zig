const std = @import("std");
const c = @cImport(@cInclude("curl/curl.h"));
pub const auth = @import("auth");
pub const protocol = @import("protocol");
pub const utils = @import("utils");

pub const std_options: std.Options = .{
    .logFn = utils.logFn,
};

const log = std.log.scoped(.libzmail);

test {
    _ = auth;
    _ = protocol;
    _ = utils;
}
