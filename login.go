package login

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"time"
)

const (
	csrfCookie = "_csrf"
	CSRFForm   = "_csrf" // form field for CSRF token
)

var ErrCSRF = errors.New("CSRF token miss-matched")

//go:embed default.html
var defaultPage string

// AuthorizeFunc should return nil in case credentials are valid.
// The function SHOULD NOT write response or set status header.
// Provided request and writer can be used for session control in case of successful authorization.
type AuthorizeFunc[T any] func(writer http.ResponseWriter, request *http.Request, credentials T) error

// UserPassword represents single-factor authorization form.
type UserPassword struct {
	User     string `title:"Username" placeholder:"enter username"`
	Password string `title:"Password" placeholder:"enter password" hidden:"true"`
}

// UserPasswordOTP represents two-factor authorization form.
type UserPasswordOTP struct {
	UserPassword
	OTP string `title:"One-Time Pass" placeholder:"enter code from the authenticator"`
}

// New login handler which handles login page and authorization by [AuthorizeFunc]. After
// successful authorization request will be redirected to / (configurable by [Redirect]).
// CSRF (see [CSRFForm], [Key], [TTL]) protection and [OWASP] headers enabled by default.
// If no [Template] provided, default minimalistic (no-js) one will be used.
//
// The handler DOES NOT handle session by itself! It's responsibility of AuthorizeFunc to mark user as authorized.
//
// Field in UI are configurable by structure and annotations (see reference of [UserPassword] and [UserPasswordOTP]).
// Type T must be structure or application may panic.
//
// Supported annotations in type T (applied only for string fields):
//
//	title - title for the field, default is field name
//	placeholder - placeholder in HTML input, default is field name
//	hidden - boolean, default false, marks field as password and masked.
func New[T any](handle AuthorizeFunc[T], options ...Option) http.Handler {
	var v T

	lh := &loginHandler{
		invoker: newInvoker(v),
		handler: func(writer http.ResponseWriter, request *http.Request, val any) error {
			return handle(writer, request, val.(T))
		},
		redirect: "/",
		template: template.Must(template.New("").Parse(defaultPage)),
		key:      mustGenRandom(32),
		ttl:      time.Hour,
		errLog:   func(err error) {},
	}
	for _, opt := range options {
		opt(lh)
	}

	return lh
}

type loginHandler struct {
	invoker  *formInvoker
	handler  func(writer http.ResponseWriter, request *http.Request, val any) error
	redirect string
	template *template.Template
	key      []byte
	ttl      time.Duration
	owasp    bool
	errLog   func(err error)
}

func (lh *loginHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodPost:
		lh.handlePOST(writer, request)
	case http.MethodGet:
		lh.handleGET(writer, request)
	default:
		writer.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (lh *loginHandler) handleGET(writer http.ResponseWriter, request *http.Request) {
	lh.renderPage(writer, http.StatusOK, nil)
}

func (lh *loginHandler) handlePOST(writer http.ResponseWriter, request *http.Request) {
	if err := checkCSRF(request, lh.key); err != nil {
		lh.errLog(err)
		lh.renderPage(writer, http.StatusUnauthorized, err)
		return
	}

	arg := lh.invoker.createArg(request)
	err := lh.handler(writer, request, arg)
	if err != nil {
		lh.errLog(err)
		lh.renderPage(writer, http.StatusUnauthorized, err)
		return
	}

	writer.Header().Set("Location", lh.redirect)
	writer.WriteHeader(http.StatusSeeOther)
}

func (lh *loginHandler) renderPage(writer http.ResponseWriter, status int, sourceErr error) {
	formValue, err := lh.setCSRFCookie(writer, lh.ttl)
	if err != nil {
		lh.errLog(err)
	}
	vc := viewContext{
		Fields: lh.invoker.fields,
		CSRF:   formValue,
	}
	if sourceErr != nil {
		vc.Error = sourceErr.Error()
	}
	writer.Header().Set("Content-Type", "text/html")
	if lh.owasp {
		owaspHeaders(writer)
	}
	writer.WriteHeader(status)
	if err := lh.template.Execute(writer, vc); err != nil {
		lh.errLog(err)
	}
}

func (lh *loginHandler) setCSRFCookie(writer http.ResponseWriter, timeout time.Duration) (formValue string, err error) {
	src, sig, err := generateCSRF(lh.key)
	if err != nil {
		return "", err
	}
	http.SetCookie(writer, &http.Cookie{
		Name:     csrfCookie,
		Value:    sig,
		Path:     ".",
		Expires:  time.Now().Add(timeout),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	return src, nil
}

func checkCSRF(req *http.Request, key []byte) error {
	sigHEX, err := req.Cookie(csrfCookie)
	if err != nil {
		return fmt.Errorf("get CSRF cookie: %w", err)
	}
	sig, err := hex.DecodeString(sigHEX.Value)
	if err != nil {
		return fmt.Errorf("decode CSRF cookie: %w", err)
	}
	value, err := hex.DecodeString(req.FormValue(CSRFForm))
	if err != nil {
		return fmt.Errorf("decode CSRF form value: %w", err)
	}

	mac := hmac.New(sha256.New, key)
	if _, err := mac.Write(value[:]); err != nil {
		return fmt.Errorf("write to MAC: %w", err)
	}
	expectedSig := mac.Sum(nil)

	if !hmac.Equal(expectedSig, sig) {
		return ErrCSRF
	}
	return nil
}

func generateCSRF(key []byte) (source, sig string, err error) {
	// https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#double-submit-cookie
	const valueSize = 20
	var value [valueSize]byte
	if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
		return "", "", fmt.Errorf("read value: %w", err)
	}
	source = hex.EncodeToString(value[:])

	mac := hmac.New(sha256.New, key)
	if _, err := mac.Write(value[:]); err != nil {
		return "", "", fmt.Errorf("write to MAC: %w", err)
	}
	sig = hex.EncodeToString(mac.Sum(nil))
	return
}

func mustGenRandom(size int) []byte {
	var value = make([]byte, size)
	_, err := io.ReadFull(rand.Reader, value)
	if err != nil {
		panic(err)
	}
	return value
}

type viewContext struct {
	Fields []field
	CSRF   string
	Error  string
}

type formInvoker struct {
	t      reflect.Type
	fields []field
}

func (fi *formInvoker) createArg(request *http.Request) interface{} {
	refV := reflect.New(fi.t).Elem()
	for _, f := range fi.fields {
		refV.FieldByName(f.Name).SetString(request.PostFormValue(f.Name))
	}
	return refV.Interface()
}

type field struct {
	Name        string // field name
	Hidden      bool   // is field masked like password
	Title       string // field title
	Placeholder string // field placeholder
}

// scan value for attributed. Value must be struct or pointer to struct. Only string fields are supported.
func newInvoker(obj interface{}) *formInvoker {
	v := reflect.ValueOf(obj)
	t := v.Type()
	if t.Kind() != reflect.Struct {
		return &formInvoker{fields: nil, t: t}
	}
	n := t.NumField()
	var fields []field
	for i := 0; i < n; i++ {
		f := t.Field(i)
		if !f.IsExported() || f.Type.Kind() != reflect.String {
			continue
		}
		name := f.Name
		hidden := false
		if tag, err := strconv.ParseBool(f.Tag.Get("hidden")); err == nil {
			hidden = tag
		}
		title := f.Name
		if tag := f.Tag.Get("title"); tag != "" {
			title = tag
		}
		placeholder := f.Name
		if tag := f.Tag.Get("placeholder"); tag != "" {
			placeholder = tag
		}
		fields = append(fields, field{
			Name:        name,
			Hidden:      hidden,
			Title:       title,
			Placeholder: placeholder,
		})
	}
	return &formInvoker{fields: fields, t: t}
}

func owaspHeaders(writer http.ResponseWriter) {
	writer.Header().Set("X-Frame-Options", "DENY")
	writer.Header().Set("X-XSS-Protection", "0")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
}
