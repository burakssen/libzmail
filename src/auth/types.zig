pub const AuthType = enum {
    basic,
    oauth2,
};

pub const BasicPayload = struct {
    username: [:0]const u8,
    password: [:0]const u8,
};

pub const TokenStoreMode = enum {
    auto,
    memory,
    encrypted_file,
};

pub const TokenStoreConfig = struct {
    mode: TokenStoreMode = .auto,
    file_path: ?[:0]const u8 = null,
};

pub const ClientOptions = struct {
    auth_endpoint: [:0]const u8,
    token_endpoint: [:0]const u8,
    userinfo_endpoint: [:0]const u8,
    redirect_uri: [:0]const u8,
    scopes: ?[]const [:0]const u8,
    callback_timeout_ms: u32 = 60000,

    pub const google = ClientOptions{
        .auth_endpoint = "https://accounts.google.com/o/oauth2/v2/auth",
        .token_endpoint = "https://oauth2.googleapis.com/token",
        .userinfo_endpoint = "https://www.googleapis.com/oauth2/v2/userinfo",
        .redirect_uri = "http://127.0.0.1:8080",
        .scopes = &.{
            "https://mail.google.com/",
            "https://www.googleapis.com/auth/userinfo.email",
        },
    };

    pub const microsoft = ClientOptions{
        .auth_endpoint = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        .token_endpoint = "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        .userinfo_endpoint = "https://graph.microsoft.com/oidc/userinfo",
        .redirect_uri = "http://127.0.0.1:8080",
        .scopes = &.{
            "https://outlook.office.com/SMTP.Send",
            "offline_access",
            "openid",
            "email",
        },
    };
};

pub const OAuth2Payload = struct {
    client_id: [:0]const u8,
    client_options: ClientOptions,
    token_store: TokenStoreConfig = .{},
};

pub const PayloadType = union(AuthType) {
    basic: BasicPayload,
    oauth2: OAuth2Payload,
};
