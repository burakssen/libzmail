pub const MailPayload = @import("smtp/types.zig").MailPayload;

pub const imap = @import("imap.zig");
pub const smtp = @import("smtp.zig");
pub const redundancy = @import("redundancy.zig");
pub const errors = @import("errors.zig");

test {
    _ = redundancy;
}
