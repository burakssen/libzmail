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

    auth_mod.linkSystemLibrary("curl", .{ .preferred_link_mode = .static });

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

    if (target.result.os.tag == .macos) {
        auth_mod.linkFramework("Security", .{});
        protocol_mod.linkFramework("Security", .{});
    }

    const libzmail_mod = b.addModule("libzmail", .{
        .target = target,
        .optimize = optimize,
        .root_source_file = b.path("src/libzmail.zig"),
        .imports = &.{
            .{ .name = "auth", .module = auth_mod },
            .{ .name = "protocol", .module = protocol_mod },
            .{ .name = "utils", .module = utils_mod },
        },
    });

    const libzmail_lib = b.addLibrary(.{
        .name = "zmail",
        .root_module = libzmail_mod,
    });

    b.installArtifact(libzmail_lib);

    const test_step = b.step("test", "Run tests");

    inline for (&.{ auth_mod, protocol_mod, utils_mod, libzmail_mod }) |mod| {
        const mod_test = b.addTest(.{ .root_module = mod });
        const mod_cmd = b.addRunArtifact(mod_test);
        test_step.dependOn(&mod_cmd.step);
    }

    // Examples
    const examples = [_]struct { name: []const u8, path: []const u8 }{
        .{ .name = "smtp_basic", .path = "examples/smtp_basic.zig" },
        .{ .name = "imap_list", .path = "examples/imap_list.zig" },
    };

    for (examples) |example| {
        const example_mod = b.createModule(.{
            .root_source_file = b.path(example.path),
            .target = target,
            .optimize = optimize,
        });
        example_mod.addImport("libzmail", libzmail_mod);

        const exe = b.addExecutable(.{
            .name = example.name,
            .root_module = example_mod,
        });
        b.installArtifact(exe);

        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());
        if (b.args) |args| {
            run_cmd.addArgs(args);
        }

        const run_step = b.step(b.fmt("run-{s}", .{example.name}), b.fmt("Run the {s} example", .{example.name}));
        run_step.dependOn(&run_cmd.step);
    }
}
