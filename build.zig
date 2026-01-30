const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const utils_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("src/utils/utils.zig"),
    });

    const auth_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("src/auth/auth.zig"),
        .link_libc = true,
        .imports = &.{
            .{ .name = "utils", .module = utils_mod },
        },
    });

    auth_mod.linkSystemLibrary("curl", .{});

    const protocol_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("src/protocol/protocol.zig"),
        .link_libc = true,
        .imports = &.{
            .{ .name = "auth", .module = auth_mod },
            .{ .name = "utils", .module = utils_mod },
        },
    });

    protocol_mod.linkSystemLibrary("curl", .{});

    const libzmail_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("src/libzmail.zig"),
        .imports = &.{
            .{ .name = "auth", .module = auth_mod },
            .{ .name = "protocol", .module = protocol_mod },
            .{ .name = "utils", .module = utils_mod },
        },
    });

    // This will be removed later for convenience purposes
    {
        const libzmail_exe = b.addExecutable(.{
            .name = "libzmail",
            .root_module = libzmail_mod,
        });

        const run_step = b.step("run", "Run executable");
        const run_cmd = b.addRunArtifact(libzmail_exe);
        run_step.dependOn(&run_cmd.step);
    }

    const test_step = b.step("test", "Run tests");

    inline for (&.{ auth_mod, libzmail_mod }) |mod| {
        const mod_test = b.addTest(.{ .root_module = mod });
        const mod_cmd = b.addRunArtifact(mod_test);
        test_step.dependOn(&mod_cmd.step);
    }
}
