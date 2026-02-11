const std = @import("std");
const libzmail = @import("libzmail");

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
    var provider = libzmail.auth.Provider(.oauth2).init(allocator, basic_payload);
    defer provider.deinit();

    // 2. Configure SMTP payload
    const smtp_payload = libzmail.protocol.smtp.types.SmtpPayload{
        .hostname = "smtp.gmail.com",
        .port = 587,
        .use_tls = true,
    };

    // 3. Initialize SMTP client
    var client = try libzmail.protocol.smtp.Client(@TypeOf(provider)).init(allocator, smtp_payload, &provider);
    defer client.deinit();

    // 4. Prepare email data
    const mail_data = libzmail.protocol.smtp.types.MailPayload{
        .from = "<from_email>",
        .to = "<to_email>",
        .subject = "Hello from libzmail",
        .body = "This is a test email sent using libzmail with OAuth2 authentication.",
    };

    // 5. Send the email
    std.debug.print("Sending email...\n", .{});
    try client.send(mail_data);
    std.debug.print("Email sent successfully!\n", .{});
}
