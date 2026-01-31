const std = @import("std");
const utils = @import("utils");

pub const ImapPayload = struct {
    hostname: []const u8,
    port: u16 = 993,
    use_tls: bool = true,
};

/// Represents mailbox flags as defined in RFC 3501
pub const MailboxFlags = struct {
    has_children: bool = false,
    has_no_children: bool = false,
    marked: bool = false,
    unmarked: bool = false,
    noselect: bool = false,
    noinferiors: bool = false,
    // Special-use flags (RFC 6154)
    all: bool = false,
    inbox: bool = false,
    archive: bool = false,
    drafts: bool = false,
    flagged: bool = false,
    junk: bool = false,
    sent: bool = false,
    trash: bool = false,

    pub fn parse(flags_str: []const u8) MailboxFlags {
        var result = MailboxFlags{};

        var it = std.mem.tokenizeAny(u8, flags_str, " () ");
        while (it.next()) |flag| {
            if (std.mem.eql(u8, flag, "\\HasChildren")) {
                result.has_children = true;
            } else if (std.mem.eql(u8, flag, "\\HasNoChildren")) {
                result.has_no_children = true;
            } else if (std.mem.eql(u8, flag, "\\Marked")) {
                result.marked = true;
            } else if (std.mem.eql(u8, flag, "\\Unmarked")) {
                result.unmarked = true;
            } else if (std.mem.eql(u8, flag, "\\Noselect")) {
                result.noselect = true;
            } else if (std.mem.eql(u8, flag, "\\Noinferiors")) {
                result.noinferiors = true;
            } else if (std.mem.eql(u8, flag, "\\All")) {
                result.all = true;
            } else if (std.mem.eql(u8, flag, "\\Inbox")) {
                result.inbox = true;
            } else if (std.mem.eql(u8, flag, "\\Archive")) {
                result.archive = true;
            } else if (std.mem.eql(u8, flag, "\\Drafts")) {
                result.drafts = true;
            } else if (std.mem.eql(u8, flag, "\\Flagged")) {
                result.flagged = true;
            } else if (std.mem.eql(u8, flag, "\\Junk")) {
                result.junk = true;
            } else if (std.mem.eql(u8, flag, "\\Sent")) {
                result.sent = true;
            } else if (std.mem.eql(u8, flag, "\\Trash")) {
                result.trash = true;
            }
        }

        return result;
    }

    pub fn format(
        self: MailboxFlags,
        writer: *std.Io.Writer,
    ) !void {
        var first = true;
        try writer.writeAll("(");

        inline for (@typeInfo(MailboxFlags).@"struct".fields) |field| {
            if (@field(self, field.name)) {
                if (!first) try writer.writeAll(" ");
                first = false;
                try writer.writeAll("\\");
                // Convert snake_case to PascalCase for display
                var buf: [64]u8 = undefined;
                var i: usize = 0;
                var capitalize_next = true;
                for (field.name) |char| {
                    if (char == '_') {
                        capitalize_next = true;
                    } else {
                        buf[i] = if (capitalize_next) std.ascii.toUpper(char) else char;
                        capitalize_next = false;
                        i += 1;
                    }
                }
                try writer.writeAll(buf[0..i]);
            }
        }

        try writer.writeAll(")");
    }
};

/// Represents a single IMAP mailbox
pub const Mailbox = struct {
    name: []const u8,
    delimiter: u8,
    flags: MailboxFlags,
    // Decoded name (UTF-8)
    decoded_name: ?[]const u8 = null,

    pub fn deinit(self: *Mailbox, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        if (self.decoded_name) |decoded| {
            allocator.free(decoded);
        }
    }

    /// Parse a single LIST response line
    /// Format: * LIST (flags) "delimiter" "name"
    pub fn parse(allocator: std.mem.Allocator, line: []const u8) !?Mailbox {
        // Skip if not a LIST response
        if (!std.mem.startsWith(u8, line, "* LIST")) {
            return null;
        }

        // Find the flags section
        const flags_start = std.mem.indexOf(u8, line, "(") orelse return null;
        const flags_end = std.mem.indexOf(u8, line[flags_start..], ")") orelse return null;
        const flags_str = line[flags_start .. flags_start + flags_end + 1];
        const flags = MailboxFlags.parse(flags_str);

        // Find delimiter
        const after_flags = line[flags_start + flags_end + 1 ..];
        const delim_start = std.mem.indexOfScalar(u8, after_flags, '"') orelse return null;
        const delimiter = after_flags[delim_start + 1];

        // Find mailbox name
        const after_delim = after_flags[delim_start + 3 ..]; // Skip "x"
        const name: []const u8 = blk: {
            const trimmed = std.mem.trim(u8, after_delim, " \r\n");
            if (std.mem.startsWith(u8, trimmed, "\"")) {
                // Quoted name - find the closing quote
                const name_end = std.mem.indexOfScalar(u8, trimmed[1..], '"') orelse return null;
                break :blk trimmed[1 .. name_end + 1];
            } else {
                // Unquoted name
                break :blk trimmed;
            }
        };

        const name_copy = try allocator.dupe(u8, name);
        errdefer allocator.free(name_copy);

        // Try to decode modified UTF-7 (IMAP uses this encoding)
        const decoded_name = utils.decodeModifiedUtf7(allocator, name) catch |err| blk: {
            std.log.warn("Failed to decode mailbox name '{s}': {}", .{ name, err });
            break :blk null;
        };

        return Mailbox{
            .name = name_copy,
            .delimiter = delimiter,
            .flags = flags,
            .decoded_name = decoded_name,
        };
    }

    /// Get the display name (decoded if available, otherwise original)
    pub fn displayName(self: Mailbox) []const u8 {
        return self.decoded_name orelse self.name;
    }

    /// Check if this is a special-use mailbox
    pub fn isSpecialUse(self: Mailbox) bool {
        return self.flags.all or self.flags.archive or self.flags.drafts or
            self.flags.flagged or self.flags.junk or self.flags.sent or
            self.flags.trash;
    }

    /// Get the mailbox type as a string
    pub fn getType(self: Mailbox) []const u8 {
        if (self.flags.inbox) return "Inbox";
        if (self.flags.drafts) return "Drafts";
        if (self.flags.sent) return "Sent";
        if (self.flags.trash) return "Trash";
        if (self.flags.junk) return "Junk";
        if (self.flags.archive) return "Archive";
        if (self.flags.all) return "All Mail";
        if (self.flags.flagged) return "Flagged";
        return "Folder";
    }

    pub fn format(
        self: Mailbox,
        writer: *std.Io.Writer,
    ) !void {
        try writer.print("Mailbox{{ .name = \"{s}\", .delimiter = ' {c}', .flags = {f}, .type = {s} }}", .{
            self.displayName(),
            self.delimiter,
            self.flags,
            self.getType(),
        });
    }
};
