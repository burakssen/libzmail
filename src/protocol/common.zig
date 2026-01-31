pub const MailPayload = struct {
    from: []const u8,
    to: []const u8,
    subject: []const u8,
    body: []const u8,
};
