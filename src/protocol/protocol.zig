pub const SmtpProtocol = @import("smtp.zig").SmtpProtocol;
pub const ImapProtocol = @import("imap.zig").ImapProtocol;

pub const common = @import("common.zig");
pub const MailPayload = common.MailPayload;

pub const imap = @import("imap.zig");
pub const smtp = @import("smtp.zig");