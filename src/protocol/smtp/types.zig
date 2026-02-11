const redundancy = @import("../redundancy.zig");

pub const SmtpPayload = struct {
    hostname: [:0]const u8,
    port: u16 = 587,
    use_tls: bool = true,
    fallback_endpoints: []const redundancy.Endpoint = &.{},
    redundancy_policy: redundancy.RedundancyPolicy = .{},
};

pub const MailPayload = struct {
    from: [:0]const u8,
    to: [:0]const u8,
    subject: []const u8,
    body: []const u8,
};
