pub const SmtpProtocol = @import("smtp.zig").SmtpProtocol;
pub const ImapProtocol = @import("imap.zig").ImapProtocol;

pub const MailPayload = @import("smtp/types.zig").MailPayload;

pub const imap = @import("imap.zig");
pub const smtp = @import("smtp.zig");
