pub const client = @import("imap/client.zig");
pub const types = @import("imap/types.zig");

pub const ImapProtocol = client.ImapProtocol;
pub const ImapPayload = types.ImapPayload;
pub const Mailbox = types.Mailbox;
pub const MailboxFlags = types.MailboxFlags;