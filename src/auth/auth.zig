const std = @import("std");
const c = @cImport(@cInclude("curl/curl.h"));

pub const Provider = @import("provider.zig").Provider;
pub const types = @import("types.zig");
