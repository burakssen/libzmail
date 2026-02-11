const std = @import("std");

pub fn logFn(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    const level_txt = comptime switch (level) {
        .err => "ERROR",
        .warn => "WARN ",
        .info => "INFO ",
        .debug => "DEBUG",
    };

    const color = comptime switch (level) {
        .err => "\x1b[31m", // Red
        .warn => "\x1b[33m", // Yellow
        .info => "\x1b[32m", // Green
        .debug => "\x1b[90m", // Gray
    };
    const reset = "\x1b[0m";
    const dim = "\x1b[2m";

    // Get timestamp
    const timestamp = std.time.timestamp();
    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = @intCast(timestamp) };
    const day_seconds = epoch_seconds.getDaySeconds();

    const hours = day_seconds.getHoursIntoDay();
    const minutes = day_seconds.getMinutesIntoHour();
    const secs = day_seconds.getSecondsIntoMinute();

    const stderr = std.fs.File.stderr();
    var stderr_buffer: [1024]u8 = undefined;
    var stderr_writer = stderr.writer(&stderr_buffer);
    const writer = &stderr_writer.interface;
    nosuspend {
        writer.print(dim ++ "{d:0>2}:{d:0>2}:{d:0>2} " ++ reset, .{ hours, minutes, secs }) catch return;
        writer.print(color ++ "{s} " ++ reset, .{level_txt}) catch return;

        if (scope != .default) {
            writer.print(dim ++ "[" ++ @tagName(scope) ++ "] " ++ reset, .{}) catch return;
        }

        writer.print(format ++ "\n", args) catch return;
        writer.flush() catch return;
    }
}
