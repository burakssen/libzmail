const std = @import("std");
const log = std.log.scoped(.redundancy);

pub const Endpoint = struct {
    hostname: [:0]const u8,
    port: u16,
    use_tls: bool = true,
};

pub const RetryPolicy = struct {
    max_attempts: u32 = 3,
    initial_backoff_ms: u32 = 1000,
    max_backoff_ms: u32 = 10000,
    backoff_factor: f32 = 2.0,
    jitter: f32 = 0.1,
};

pub const HealthPolicy = struct {
    cooldown_ms: u32 = 60000, // 1 minute
};

pub const RedundancyPolicy = struct {
    retry: RetryPolicy = .{},
    health: HealthPolicy = .{},
};

pub const HealthState = struct {
    last_failure: ?i64 = null, // unix timestamp in ms

    pub fn isHealthy(self: HealthState, policy: HealthPolicy) bool {
        if (self.last_failure) |lf| {
            const now = std.time.milliTimestamp();
            if (now - lf < policy.cooldown_ms) {
                return false;
            }
        }
        return true;
    }

    pub fn markUnhealthy(self: *HealthState) void {
        self.last_failure = std.time.milliTimestamp();
    }

    pub fn markHealthy(self: *HealthState) void {
        self.last_failure = null;
    }
};

pub fn calculateBackoff(policy: RetryPolicy, attempt: u32) u64 {
    if (attempt == 0) return 0;
    
    const factor = std.math.pow(f32, policy.backoff_factor, @as(f32, @floatFromInt(attempt - 1)));
    var backoff = @as(f32, @floatFromInt(policy.initial_backoff_ms)) * factor;
    
    if (backoff > @as(f32, @floatFromInt(policy.max_backoff_ms))) {
        backoff = @as(f32, @floatFromInt(policy.max_backoff_ms));
    }

    // Apply jitter
    var prng = std.Random.DefaultPrng.init(@intCast(std.time.timestamp()));
    const random = prng.random();
    const jitter_range = backoff * policy.jitter;
    const jitter_val = (random.float(f32) * 2.0 - 1.0) * jitter_range;
    
    return @intFromFloat(backoff + jitter_val);
}

test "backoff calculation" {
    const policy = RetryPolicy{
        .initial_backoff_ms = 1000,
        .backoff_factor = 2.0,
        .jitter = 0.0, // Disable jitter for deterministic test
    };

    try std.testing.expectEqual(@as(u64, 0), calculateBackoff(policy, 0));
    try std.testing.expectEqual(@as(u64, 1000), calculateBackoff(policy, 1));
    try std.testing.expectEqual(@as(u64, 2000), calculateBackoff(policy, 2));
    try std.testing.expectEqual(@as(u64, 4000), calculateBackoff(policy, 3));
}

test "health state logic" {
    var state = HealthState{};
    const policy = HealthPolicy{ .cooldown_ms = 100 };

    try std.testing.expect(state.isHealthy(policy));

    state.markUnhealthy();
    try std.testing.expect(!state.isHealthy(policy));

    std.Thread.sleep(110 * std.time.ns_per_ms);
    try std.testing.expect(state.isHealthy(policy));

    state.markHealthy();
    try std.testing.expect(state.isHealthy(policy));
}
