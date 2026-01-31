pub const SmtpPayload = struct {
    hostname: []const u8,
    port: u16 = 587,
    use_tls: bool = true,
};

pub const ImapPayload = struct {
    hostname: []const u8,
    port: u16 = 993,
    use_tls: bool = true,
};

pub const MailPayload = struct {
    from: []const u8,
    to: []const u8,
    subject: []const u8,
    body: []const u8,
};
