# libzmail

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Zig Version](https://img.shields.io/badge/Zig-0.15.2+-orange.svg)

A low-level Zig email library (SMTP, IMAP, POP3) backed by **libcurl** for robust TLS and networking. Designed for explicit control and predictable memory usage, this is a **protocol and authentication layer**, not a rendering engine.

## Features

### 🚀 **Protocol Support**
- ✅ **SMTP** - Full email sending capability with TLS support
- 🔄 **IMAP** - Planned for email retrieval and management
- 🔄 **POP3** - Planned for simple email retrieval

### 🔐 **Authentication Methods**
- ✅ **Basic Authentication** - Username/password support
- ✅ **OAuth 2.0** - Modern, secure authentication with major providers:
  - **Google** - Gmail, Google Workspace
  - **Microsoft** - Outlook, Office 365
- 🔄 **SAML/SSO** - Enterprise authentication (planned)

## Installation

### Prerequisites

- **Zig** version 0.15.2 or later
- **libcurl** development libraries

### Building libzmail

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/libzmail.git
cd libzmail
```

2. **Build the library**
```bash
zig build
```

3. **Run the example**
```bash
zig build run
```

4. **Run tests**
```bash
zig build test
```

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
exe.linkLibrary(libzmail.artifact("libzmail"));
```

And in your `build.zig`:
```zig
const libzmail = b.dependency("libzmail", .{
    .target = target,
    .optimize = optimize,
});
exe.linkLibrary(libzmail.artifact("libzmail"));
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

    const Provider = auth.Provider(.basic);
    const SmtpProtocol = protocol.Protocol(.smtp, Provider);

    const provider = Provider.init(allocator, .{
        .username = "test@email.com",
        .password = "pass",
    });

    _ = c.curl_global_init(0);
    defer c.curl_global_cleanup();

    var smtp_protocol = SmtpProtocol.init(allocator, .{
        .hostname = "smtp.server.com",
        .port = 587,
        .use_tls = true,
    }, provider);
    defer smtp_protocol.deinit();

    try smtp_protocol.connect();

    try smtp_protocol.send(.{
        .from = "test@email.com",
        .to = "recipient@email.com",
        .subject = "Test Email",
        .body = "This is a test email sent from Zmail using SMTP protocol.",
    });
}
```

### OAuth2 with Google Gmail

```zig
const std = @import("std");
const libzmail = @import("libzmail");
const google_secret = @embedFile("google_secret");
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
        .from = "test@gmail.com",
        .to = "recipient@example.com",
        .subject = "Test Email",
        .body = "This is a test email sent from Zmail using SMTP protocol.",
    });
}
```

### OAuth2 with Microsoft Outlook

```zig
// Similar to Google, but use .microsoft instead of .google
const provider = Provider.init(allocator, .{
    .client_id = microsoft_secret,
    .client_options = .microsoft,
});
```

## License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

