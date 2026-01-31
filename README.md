# libzmail

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Zig Version](https://img.shields.io/badge/Zig-0.15.2+-orange.svg)

A low-level Zig email library (SMTP, IMAP, POP3) backed by **libcurl** for robust TLS and networking. Designed for explicit control and predictable memory usage, this is a **protocol and authentication layer**, not a rendering engine.

## Features

### Protocol Support
- [x] **SMTP** - Full email sending capability with TLS support
- [x] **IMAP** - Email retrieval and mailbox management
- [ ] **POP3** - Planned for simple email retrieval

### Authentication Methods
- [x] **Basic Authentication** - Username/password support
- [x] **OAuth 2.0** - Modern, secure authentication with major providers:
  - [x] **Google** - Gmail, Google Workspace
  - [x] **Microsoft** - Outlook, Office 365
- [ ] **SAML/SSO** - Enterprise authentication (planned)

## Installation

### Prerequisites

- **Zig** version 0.15.2 or later
- **libcurl** development libraries

### Using as a Dependency

Add libzmail to your project using Zig's package manager:

```bash
zig fetch --save git+https://github.com/burakssen/libzmail
```

Then in your `build.zig`:
```zig
const libzmail = b.dependency("libzmail", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("libzmail", libzmail.module("libzmail"));
```

## Quick Start

### Basic SMTP with Username/Password

```zig
const std = @import("std");
const libzmail = @import("libzmail");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // 1. Initialize Authentication Provider
    const Provider = libzmail.auth.Provider(.basic);
    var provider = Provider.init(allocator, .{
        .username = "user@example.com",
        .password = "your_password",
    });
    defer provider.deinit();

    // 2. Initialize SMTP Client
    const SmtpClient = libzmail.protocol.smtp.Client(Provider);
    var smtp_client = try SmtpClient.init(allocator, .{
        .hostname = "smtp.example.com",
        .port = 587,
    }, provider);
    defer smtp_client.deinit();

    // 3. Connect and Send
    try smtp_client.connect();

    try smtp_client.send(.{
        .from = "user@example.com",
        .to = "recipient@example.com",
        .subject = "Hello from Zig!",
        .body = "This email was sent using libzmail.",
    });
}
```

### OAuth2 with Google Gmail

```zig
const std = @import("std");
const libzmail = @import("libzmail");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // 1. Initialize OAuth2 Provider
    const Provider = libzmail.auth.Provider(.oauth2);
    var provider = Provider.init(allocator, .{
        .client_id = "YOUR_GOOGLE_CLIENT_ID",
        .client_options = libzmail.auth.types.ClientOptions.google,
    });
    defer provider.deinit();

    // 2. Initialize SMTP Client
    const SmtpClient = libzmail.protocol.smtp.Client(Provider);
    var smtp_client = try SmtpClient.init(allocator, .{
        .hostname = "smtp.gmail.com",
        .port = 587,
    }, provider);
    defer smtp_client.deinit();

    // 3. Authenticate and Send
    // This will automatically handle the OAuth2 flow and open a browser if needed
    try smtp_client.connect();

    try smtp_client.send(.{
        .from = "your-email@gmail.com",
        .to = "recipient@example.com",
        .subject = "OAuth2 Email",
        .body = "Authenticated via Google OAuth2!",
    });
}
```

### IMAP Mailbox Listing

```zig
const std = @import("std");
const libzmail = @import("libzmail");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // 1. Initialize Provider
    const Provider = libzmail.auth.Provider(.basic);
    var provider = Provider.init(allocator, .{
        .username = "user@example.com",
        .password = "your_password",
    });
    defer provider.deinit();

    // 2. Initialize IMAP Client
    const ImapClient = libzmail.protocol.imap.Client(Provider);
    var imap_client = try ImapClient.init(allocator, .{
        .hostname = "imap.example.com",
        .port = 993,
    }, provider);
    defer imap_client.deinit();

    // 3. Connect and List Mailboxes
    try imap_client.connect();

    const mailboxes = try imap_client.listMailboxes();
    defer {
        for (mailboxes) |*mb| mb.deinit(allocator);
        allocator.free(mailboxes);
    }

    for (mailboxes) |mb| {
        std.debug.print("Mailbox: {s} (Type: {s})\n", .{ mb.name, mb.getType() });
    }
}
```

## License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.
