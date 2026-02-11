const std = @import("std");
const c = @cImport(@cInclude("curl/curl.h"));

pub const ErrorCategory = enum {
    transient,
    permanent,
};

pub fn classifyCurlError(code: c.CURLcode) ErrorCategory {
    return switch (code) {
        c.CURLE_OK => .transient, // Should not happen in error path

        // Transient / Network issues
        c.CURLE_COULDNT_RESOLVE_PROXY,
        c.CURLE_COULDNT_RESOLVE_HOST,
        c.CURLE_COULDNT_CONNECT,
        c.CURLE_OPERATION_TIMEDOUT,
        c.CURLE_SSL_CONNECT_ERROR,
        c.CURLE_PEER_FAILED_VERIFICATION,
        c.CURLE_GOT_NOTHING,
        c.CURLE_SEND_ERROR,
        c.CURLE_RECV_ERROR,
        c.CURLE_PARTIAL_FILE,
        => .transient,

        // Permanent / Configuration / Auth issues
        c.CURLE_UNSUPPORTED_PROTOCOL,
        c.CURLE_URL_MALFORMAT,
        c.CURLE_NOT_BUILT_IN,
        c.CURLE_LOGIN_DENIED,
        c.CURLE_REMOTE_ACCESS_DENIED,
        c.CURLE_AUTH_ERROR,
        c.CURLE_OUT_OF_MEMORY,
        => .permanent,

        else => .permanent,
    };
}
