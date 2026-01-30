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
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const Provider = auth.Provider(.oauth2);
    const Protocol = protocol.Protocol(.smtp, Provider);

    var provider = Provider.init(allocator, .{
        .client_id = google_secret,
        .client_options = .google,
    });
    defer provider.deinit();

    _ = c.curl_global_init(0);
    defer c.curl_global_cleanup();

    var mail_protocol = Protocol.init(allocator, .{
        .hostname = "smtp.gmail.com",
        .port = 587,
        .use_tls = true,
    }, provider);
    defer mail_protocol.deinit();

    try mail_protocol.connect();

    try mail_protocol.send(.{
        .from = "burak.pj@gmail.com",
        .to = "burak.sen@tum.de",
        .subject = "Test Email",
        .body = "This is a test email sent from Zmail using SMTP protocol.",
    });
}
