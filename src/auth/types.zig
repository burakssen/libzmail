pub const AuthType = enum {
    basic,
    oauth2,
};

pub const BasicPayload = struct {
    username: []const u8,
    password: []const u8,
};

pub const OAuth2Payload = struct {
    auth_endpoint: []const u8,
    token_endpoint: []const u8,
    redirect_uri: []const u8,
    scope: ?[]const []const u8,
    client_id: []const u8,
};

pub const PayloadType = union(AuthType) {
    basic: BasicPayload,
    oauth2: OAuth2Payload,
};
