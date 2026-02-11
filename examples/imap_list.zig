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

    // 2. Configure IMAP payload
    const imap_payload = libzmail.protocol.imap.types.ImapPayload{
        .hostname = "imap.gmail.com",
        .port = 993,
        .use_tls = true,
    };

    // 3. Initialize IMAP client
    var client = try libzmail.protocol.imap.Client(@TypeOf(provider)).init(allocator, imap_payload, &provider);
    defer client.deinit();

    // 4. List mailboxes
    std.debug.print("Listing mailboxes...\n", .{});
    const mailboxes = try client.listMailboxes();
    defer {
        for (mailboxes) |*mb| {
            mb.deinit(allocator);
        }
        allocator.free(mailboxes);
    }

    // 5. Print results
    std.debug.print("Found {d} mailboxes:\n", .{mailboxes.len});
    for (mailboxes) |mb| {
        std.debug.print("- {s} (Type: {s})\n", .{ mb.displayName(), mb.getType() });
    }
}
