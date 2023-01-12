package login

import (
	"html/template"
	"time"
)

type Option func(lh *loginHandler)

// TTL for CSRF cookie.
func TTL(duration time.Duration) Option {
	return func(lh *loginHandler) {
		lh.ttl = duration
	}
}

// Redirect after successful login.
func Redirect(path string) Option {
	return func(lh *loginHandler) {
		lh.redirect = path
	}
}

// Key for CSRF HMAC. By default - crypto-random.
func Key(key []byte) Option {
	return func(lh *loginHandler) {
		lh.key = make([]byte, len(key))
		copy(lh.key, key)
	}
}

// Log for errors in handler.
func Log(errLog func(error)) Option {
	return func(lh *loginHandler) {
		lh.errLog = errLog
	}
}

// Template for login page.
//
// Page has context:
//
//	.Fields - list of fields (.Name, .Placeholder, .Title, .Hidden)
//	.CSRF - CSRF token
//	.Error - optional error from previous submission
//
// Page MUST make POST request to the same path and provide all as forms value all fields (named by .Name) and CSRF
// hidden value (named as [CSRFForm]).
func Template(template *template.Template) Option {
	return func(lh *loginHandler) {
		lh.template = template
	}
}

// OWASP recommended headers (enabled by default).
func OWASP(enable bool) Option {
	return func(lh *loginHandler) {
		lh.owasp = enable
	}
}
