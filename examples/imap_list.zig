const std = @import("std");
const libzmail = @import("libzmail");
const log = std.log.scoped(.imap_list);

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

    // 2. Configure IMAP payload
    const imap_payload = libzmail.protocol.imap.types.ImapPayload{
        .hostname = "imap.gmail.com",
        .port = 993,
        .use_tls = true,
    };

    // 3. Initialize IMAP client
    var client = try libzmail.protocol.imap.Client(ProviderType).init(allocator, imap_payload, &provider);
    defer client.deinit();

    // 4. List mailboxes
    log.info("Listing mailboxes...", .{});
    const mailboxes = try client.listMailboxes();
    defer {
        for (mailboxes) |*mb| {
            mb.deinit(allocator);
        }
        allocator.free(mailboxes);
    }

    // 5. Print results
    log.info("Found {d} mailboxes:", .{mailboxes.len});
    for (mailboxes) |mb| {
        log.info("- {s} (Type: {s})", .{ mb.displayName(), mb.getType() });
    }
}
