package apperrors

type ErrorCode string

const (
	ErrCodeAccessTokenExpired    ErrorCode = "access_token_expired"
	ErrCodeAuthenticationFailure ErrorCode = "authentication_error"
	ErrCodeAuthorizationFailure  ErrorCode = "authorization_error"
	ErrCodeDatabaseError         ErrorCode = "database_error"
	ErrCodeForbidden             ErrorCode = "forbidden"
	ErrCodeInternalError         ErrorCode = "internal_error"
	ErrCodeInvalidRequest        ErrorCode = "invalid_request"
	ErrCodeMalformedBody         ErrorCode = "malformed_body"
	ErrCodeNotImplemented        ErrorCode = "not_implemented"
	ErrCodePasswordTooShort      ErrorCode = "password_too_short"
	ErrCodeRefreshTokenExpired   ErrorCode = "refresh_token_expired"
	ErrCodeRefreshTokenRevoked   ErrorCode = "refresh_token_revoked"
	ErrCodeResourceAlreadyExists ErrorCode = "resource_already_exists"
	ErrCodeResourceNotFound      ErrorCode = "resource_not_found"
	ErrCodeSignalTypeClosed      ErrorCode = "signal_type_closed"
	ErrCodeTokenError            ErrorCode = "token_error"
	ErrCodeUserAlreadyExists     ErrorCode = "user_alread_exists"
	ErrCodeUserNotFound          ErrorCode = "user_not_found"
)
