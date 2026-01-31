const std = @import("std");

pub const CurlHandle = @import("curl_handle.zig");

pub fn logFn(
    comptime level: std.log.Level,
    comptime scope: @TypeOf(.EnumLiteral),
    comptime format: []const u8,
    args: anytype,
) void {
    const level_txt = comptime level.asText();
    const prefix = if (scope == .default) "" else @tagName(scope);

    const color = comptime switch (level) {
        .err => "\x1b[31m", // Red
        .warn => "\x1b[33m", // Yellow
        .info => "\x1b[36m", // Cyan
        .debug => "\x1b[90m", // Gray
    };
    const reset = "\x1b[0m";
    const dim = "\x1b[2m";
    const bold = "\x1b[1m";

    // Get timestamp
    const timestamp = std.time.timestamp();
    const epoch_seconds = std.time.epoch.EpochSeconds{ .secs = @intCast(timestamp) };
    const epoch_day = epoch_seconds.getEpochDay();
    const day_seconds = epoch_seconds.getDaySeconds();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();

    const year = year_day.year;
    const month = month_day.month.numeric();
    const day = month_day.day_index + 1;
    const hours = day_seconds.getHoursIntoDay();
    const minutes = day_seconds.getMinutesIntoHour();
    const secs = day_seconds.getSecondsIntoMinute();

    const stderr_file = std.fs.File.stderr();
    var stderr_writer = stderr_file.writer(&.{});
    const stderr = &stderr_writer.interface;

    if (scope == .default) {
        nosuspend stderr.print(dim ++ "[{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}]" ++ reset ++
            " " ++ color ++ bold ++ "{s:<5}" ++ reset ++ " " ++ format ++ "\n", .{ year, month, day, hours, minutes, secs, level_txt } ++ args) catch return;
    } else {
        nosuspend stderr.print(dim ++ "[{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}]" ++ reset ++
            " " ++ color ++ bold ++ "{s:<5}" ++ reset ++ " " ++
            dim ++ "({s})" ++ reset ++ " " ++ format ++ "\n", .{ year, month, day, hours, minutes, secs, level_txt, prefix } ++ args) catch return;
    }
}
