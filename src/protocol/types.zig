pub const ProtocolType = enum {
    smtp,
};

pub const SmtpPayload = struct {
    hostname: []const u8,
    port: u16 = 587,
    use_tls: bool = true,
};

pub const ProtocolPayloadType = union(ProtocolType) {
    smtp: SmtpPayload,
};

pub const MailPayload = struct {
    from: []const u8,
    to: []const u8,
    subject: []const u8,
    body: []const u8,
};
