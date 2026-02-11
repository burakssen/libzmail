const std = @import("std");
const libzmail = @import("libzmail");

const log = std.log.scoped(.smtp_basic);

pub const std_options: std.Options = .{
    .logFn = libzmail.utils.logFn,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // 1. Configure authentication provider
    const basic_payload = libzmail.auth.types.OAuth2Payload{
        .client_id = "<client_id>",
        .token_store = .{ .mode = .auto },
        .client_options = .google,
    };
    const ProviderType = libzmail.auth.Provider(.oauth2);
    var provider = ProviderType.init(allocator, basic_payload);
    defer provider.deinit();

    // 2. Configure SMTP payload
    const smtp_payload = libzmail.protocol.smtp.types.SmtpPayload{
        .hostname = "smtp.gmail.com",
        .port = 587,
        .use_tls = true,
    };

    // 3. Initialize SMTP client
    var client = try libzmail.protocol.smtp.Client(ProviderType).init(allocator, smtp_payload, &provider);
    defer client.deinit();

    // 4. Prepare email data
    const mail_data = libzmail.protocol.smtp.types.MailPayload{
        .from = "<from_email>",
        .to = "<to_email>",
        .subject = "Hello from libzmail",
        .body = "This is a test email sent using libzmail with OAuth2 authentication.",
    };

    // 5. Send the email
    log.info("Sending email...", .{});
    try client.send(mail_data);
    log.info("Email sent successfully!", .{});
}
