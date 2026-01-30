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
    _ = utils;
}
// Test sending an email using SMTP with OAuth2 authentication
const google_secret = @embedFile("secrets/google");
const microsoft_secret = @embedFile("secrets/microsoft");
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const Provider = auth.Provider(.oauth2);
    const SmtpProtocol = protocol.Protocol(.smtp, Provider);

    const provider = Provider.init(allocator, .{
        .client_id = google_secret,
        .client_options = .google,
    });

    _ = c.curl_global_init(0);
    defer c.curl_global_cleanup();

    var smtp_protocol = SmtpProtocol.init(allocator, .{
        .hostname = "smtp.gmail.com",
        .port = 587,
        .use_tls = true,
    }, provider);
    defer smtp_protocol.deinit();

    try smtp_protocol.connect();

    try smtp_protocol.send(.{
        .from = "burak.pj@gmail.com",
        .to = "burak.sen@tum.de",
        .subject = "Test Email",
        .body = "This is a test email sent from Zmail using SMTP protocol.",
    });
}
