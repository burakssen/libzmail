const std = @import("std");

/// Decode modified UTF-7 (as used by IMAP for mailbox names)
pub fn decodeModifiedUtf7(allocator: std.mem.Allocator, encoded: []const u8) ![]const u8 {
    var result: std.Io.Writer.Allocating = .init(allocator);
    errdefer result.deinit();
    var writer = &result.writer;

    var i: usize = 0;
    while (i < encoded.len) {
        if (encoded[i] == '&') {
            const end = std.mem.indexOfScalarPos(u8, encoded, i + 1, '-') orelse encoded.len;

            if (end == i + 1) {
                // &- represents &
                try writer.writeByte('&');
            } else {
                const b64_str = encoded[i + 1 .. end];

                // 1. Calculate padding
                const padding_needed = (4 - (b64_str.len % 4)) % 4;

                // 2. Allocate ONE buffer large enough for content + padding
                var b64_buf = try allocator.alloc(u8, b64_str.len + padding_needed);
                defer allocator.free(b64_buf);

                // 3. Normalize (replace ',' with '/') and copy
                for (b64_str, 0..) |char, idx| {
                    b64_buf[idx] = if (char == ',') '/' else char;
                }

                // 4. Append Padding
                for (0..padding_needed) |pi| {
                    b64_buf[b64_str.len + pi] = '=';
                }

                // 5. Decode
                const decoder = std.base64.standard.Decoder;
                // calcSizeForSlice checks padding and valid chars
                const decoded_size = try decoder.calcSizeForSlice(b64_buf);

                const utf16_bytes = try allocator.alloc(u8, decoded_size);
                defer allocator.free(utf16_bytes);

                try decoder.decode(utf16_bytes, b64_buf);

                // 6. Convert UTF-16BE to UTF-8
                var j: usize = 0;
                while (j + 1 < utf16_bytes.len) : (j += 2) {
                    const high = @as(u16, utf16_bytes[j]) << 8;
                    const low = @as(u16, utf16_bytes[j + 1]);
                    const codepoint = high | low;

                    if (codepoint >= 0xD800 and codepoint <= 0xDBFF and j + 3 < utf16_bytes.len) {
                        // High surrogate
                        const high_surrogate = codepoint;
                        const low_high = @as(u16, utf16_bytes[j + 2]) << 8;
                        const low_low = @as(u16, utf16_bytes[j + 3]);
                        const low_surrogate = low_high | low_low;

                        if (low_surrogate >= 0xDC00 and low_surrogate <= 0xDFFF) {
                            const _high: u32 = high_surrogate;
                            const _low: u32 = low_surrogate;
                            const actual_codepoint: u21 = @intCast(0x10000 + ((_high - 0xD800) << 10) + (_low - 0xDC00));

                            var buf: [4]u8 = undefined;
                            const len = std.unicode.utf8Encode(actual_codepoint, &buf) catch continue;
                            try writer.writeAll(buf[0..len]);
                            j += 2;
                            continue;
                        }
                    }

                    if (codepoint < 0xD800 or codepoint > 0xDFFF) {
                        var buf: [4]u8 = undefined;
                        const len = std.unicode.utf8Encode(@intCast(codepoint), &buf) catch continue;
                        try writer.writeAll(buf[0..len]);
                    }
                }
            }
            i = end + 1;
        } else {
            try writer.writeByte(encoded[i]);
            i += 1;
        }
    }

    return result.toOwnedSlice();
}
