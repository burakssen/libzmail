pub const ProtocolError = error{
    TransientNetwork,
    AuthRecoverable,
    AuthFatal,
    EndpointExhausted,
    CurlSetoptFailed,
    CurlPerformFailed,
    CurlGetinfoFailed,
    AuthenticationFailed,
    AllEndpointsFailed,
};
