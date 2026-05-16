package oauth

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/algo2go/kite-mcp-users"
)

// ---------------------------------------------------------------------------
// Coverage closure: handlers_admin_mfa.go serveAdminMFAEnrollForm and
// serveAdminMFAVerifyForm error branches.
//
// Production code holds *template.Template pointers parsed at NewHandler
// from embedded FS. Three uncovered branches exist per serve function:
//   - template == nil → 500 with "MFA … template missing"
//   - template.ExecuteTemplate returns error → 500 "internal error"
//   - response WriteTo fails → debug-log only (test via terminated conn)
//
// These tests reach into the unexported template fields to drive each
// branch. Same-package access (oauth) makes this a one-line setup; no
// production-side seam is added.
// ---------------------------------------------------------------------------

// brokenExecTemplate parses a template that references an undefined
// template name, so ExecuteTemplate("base", …) fails at runtime — i.e.
// returns an error WITHOUT crashing the test process. The parse step
// itself MUST succeed; only the execute step must err.
func brokenExecTemplate(t *testing.T) *template.Template {
	t.Helper()
	tmpl, err := template.New("broken").Parse(`{{define "base"}}{{template "missing" .}}{{end}}`)
	require.NoError(t, err, "broken template must parse cleanly; only execute should fail")
	return tmpl
}

// TestServeAdminMFAEnrollForm_NilTemplate — handlers_admin_mfa.go:258-261.
// When adminMfaEnrollTmpl is nil, the handler must short-circuit with
// 500 and a clear error message; the CSRF cookie MUST NOT be set
// (the nil-check fires before generateCSRFToken).
func TestServeAdminMFAEnrollForm_NilTemplate(t *testing.T) {
	t.Parallel()
	h, _ := newMFATestHandler(t, "admin@test.com", true)
	h.adminMfaEnrollTmpl = nil

	rec := httptest.NewRecorder()
	h.serveAdminMFAEnrollForm(rec, "admin@test.com", "TESTSECRET", "/admin/ops", "")

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "MFA enrollment template missing")
	// Defence in depth: the early-return path is BEFORE generateCSRFToken,
	// so the csrf_token_admin_mfa cookie must not appear in the response.
	for _, c := range rec.Result().Cookies() {
		assert.NotEqual(t, "csrf_token_admin_mfa", c.Name,
			"CSRF cookie must not be set when template is nil — early-return precedes csrf generation")
	}
}

// TestServeAdminMFAEnrollForm_ExecuteError — handlers_admin_mfa.go:301-305.
// When the parsed template fails at ExecuteTemplate (e.g. references an
// undefined inner template), the handler logs and returns 500.
func TestServeAdminMFAEnrollForm_ExecuteError(t *testing.T) {
	t.Parallel()
	h, _ := newMFATestHandler(t, "admin@test.com", true)
	h.adminMfaEnrollTmpl = brokenExecTemplate(t)

	rec := httptest.NewRecorder()
	h.serveAdminMFAEnrollForm(rec, "admin@test.com", "TESTSECRET", "/admin/ops", "")

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "internal error")
	// CSRF cookie IS set in this path — generateCSRFToken runs before
	// the failing ExecuteTemplate call. Pin that observable too so a
	// regression that reorders generateCSRFToken below ExecuteTemplate
	// would be caught.
	csrfFound := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == "csrf_token_admin_mfa" {
			csrfFound = true
		}
	}
	assert.True(t, csrfFound,
		"CSRF cookie must be set BEFORE ExecuteTemplate runs (regression guard)")
}

// TestServeAdminMFAVerifyForm_NilTemplate — handlers_admin_mfa.go:314-317.
// Mirror of TestServeAdminMFAEnrollForm_NilTemplate for the verify path.
func TestServeAdminMFAVerifyForm_NilTemplate(t *testing.T) {
	t.Parallel()
	h, _ := newMFATestHandler(t, "admin@test.com", true)
	h.adminMfaVerifyTmpl = nil

	rec := httptest.NewRecorder()
	h.serveAdminMFAVerifyForm(rec, "/admin/ops", "")

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "MFA verify template missing")
	for _, c := range rec.Result().Cookies() {
		assert.NotEqual(t, "csrf_token_admin_mfa", c.Name,
			"CSRF cookie must not be set when verify template is nil")
	}
}

// TestServeAdminMFAVerifyForm_ExecuteError — handlers_admin_mfa.go:344-348.
// Mirror of the enroll execute-error path on the verify side.
func TestServeAdminMFAVerifyForm_ExecuteError(t *testing.T) {
	t.Parallel()
	h, _ := newMFATestHandler(t, "admin@test.com", true)
	h.adminMfaVerifyTmpl = brokenExecTemplate(t)

	rec := httptest.NewRecorder()
	h.serveAdminMFAVerifyForm(rec, "/admin/ops", "")

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "internal error")
	csrfFound := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == "csrf_token_admin_mfa" {
			csrfFound = true
		}
	}
	assert.True(t, csrfFound,
		"CSRF cookie must be set BEFORE ExecuteTemplate runs (regression guard)")
}

// ---------------------------------------------------------------------------
// Coverage closure: checkAdminMFACSRF helper — handlers_admin_mfa.go:244-254.
// Three branches:
//   - cookie missing or empty → false (lines 246-248)
//   - form value empty → false (lines 250-252)
//   - cookie != form → false (line 253)
//   - cookie == form → true (already covered by the positive-path tests)
// ---------------------------------------------------------------------------

func TestCheckAdminMFACSRF_NoCookie_False(t *testing.T) {
	t.Parallel()
	h, _ := newMFATestHandler(t, "admin@test.com", true)
	form := url.Values{}
	form.Set("csrf_token", "anything")
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-mfa/enroll", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	require.NoError(t, req.ParseForm())
	// No csrf_token_admin_mfa cookie attached.
	assert.False(t, h.checkAdminMFACSRF(req),
		"missing CSRF cookie must reject — first guard at line 246-248")
}

func TestCheckAdminMFACSRF_EmptyCookieValue_False(t *testing.T) {
	t.Parallel()
	h, _ := newMFATestHandler(t, "admin@test.com", true)
	form := url.Values{}
	form.Set("csrf_token", "anything")
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-mfa/enroll", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin_mfa", Value: ""})
	require.NoError(t, req.ParseForm())
	assert.False(t, h.checkAdminMFACSRF(req),
		"empty CSRF cookie value must reject — same guard at line 246-248")
}

func TestCheckAdminMFACSRF_EmptyFormValue_False(t *testing.T) {
	t.Parallel()
	h, _ := newMFATestHandler(t, "admin@test.com", true)
	// Empty form — no csrf_token field at all.
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-mfa/enroll", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin_mfa", Value: "non-empty-cookie"})
	require.NoError(t, req.ParseForm())
	assert.False(t, h.checkAdminMFACSRF(req),
		"empty form token must reject — guard at line 250-252")
}

func TestCheckAdminMFACSRF_Mismatch_False(t *testing.T) {
	t.Parallel()
	h, _ := newMFATestHandler(t, "admin@test.com", true)
	form := url.Values{}
	form.Set("csrf_token", "form-value-A")
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-mfa/enroll", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin_mfa", Value: "cookie-value-B"})
	require.NoError(t, req.ParseForm())
	assert.False(t, h.checkAdminMFACSRF(req),
		"cookie/form mismatch must reject — return at line 253")
}

// ---------------------------------------------------------------------------
// Coverage closure: HandleAdminMFAEnroll POST persistence error path —
// handlers_admin_mfa.go:108-112 (h.userStore.SetTOTPSecret error).
//
// SetTOTPSecret returns "encryption key not configured" when the store
// was created WITHOUT a key. The newMFATestHandler helper takes an
// encryptionEnabled bool flag — pass false to drive the error.
// ---------------------------------------------------------------------------

func TestHandleAdminMFAEnroll_POST_SetTOTPError_Refused(t *testing.T) {
	t.Parallel()
	// Encryption disabled — SetTOTPSecret will fail at the encryption-key
	// guard before any persistence touches the user record.
	h, store := newMFATestHandler(t, "admin@test.com", false)

	secret, err := users.GenerateTOTPSecret()
	require.NoError(t, err)
	code, err := users.GenerateTOTPCode(secret, time.Now())
	require.NoError(t, err)

	form := url.Values{}
	form.Set("secret", secret)
	form.Set("code", code)
	form.Set("redirect", "/admin/ops")
	form.Set("csrf_token", "csrf-test-token")
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-mfa/enroll", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin_mfa", Value: "csrf-test-token"})
	req = req.WithContext(ContextWithEmail(req.Context(), "admin@test.com"))
	rec := httptest.NewRecorder()
	h.HandleAdminMFAEnroll(rec, req)

	// Expect a form re-render with the encryption error, NOT a redirect
	// — failure path leaves the user un-enrolled and surfaces a message.
	assert.Equal(t, http.StatusOK, rec.Code, "persistence error re-renders form")
	assert.Contains(t, rec.Body.String(), "Could not save enrollment",
		"persistence error must surface via the enroll form's error slot")
	assert.False(t, store.HasTOTP("admin@test.com"),
		"failed SetTOTPSecret must not leave a half-enrolled user")
	// No MFA cookie may be set on failure.
	for _, c := range rec.Result().Cookies() {
		assert.NotEqual(t, "kite_admin_mfa", c.Name,
			"no MFA cookie may be minted when SetTOTPSecret errored")
	}
}

// ---------------------------------------------------------------------------
// Coverage closure: HandleAdminMFAVerify POST infrastructure error path —
// handlers_admin_mfa.go:169-173 (h.userStore.VerifyTOTP error).
//
// users.Store.VerifyTOTP returns (false, nil) on every failure mode it
// observes (not enrolled, decrypt error, etc.). To exercise the (_, err)
// branch in the handler we need a mock AdminUserStore that returns an
// explicit error from VerifyTOTP — the existing mockAdminUserStoreWithVerifyError
// in handlers_admin_test.go stubs VerifyTOTP to (false, nil), which isn't
// what we want here. Add a dedicated mock.
// ---------------------------------------------------------------------------

// mockAdminStoreVerifyTOTPInfraError is a minimal AdminUserStore that
// reports HasTOTP=true (so HandleAdminMFAVerify enters the POST flow)
// and returns an error from VerifyTOTP (so the handler enters the
// infra-error branch at handlers_admin_mfa.go:169-173). All other
// methods are inert stubs sufficient to satisfy the interface contract.
type mockAdminStoreVerifyTOTPInfraError struct{}

func (m *mockAdminStoreVerifyTOTPInfraError) GetRole(email string) string   { return "admin" }
func (m *mockAdminStoreVerifyTOTPInfraError) GetStatus(email string) string { return "active" }
func (m *mockAdminStoreVerifyTOTPInfraError) VerifyPassword(email, password string) (bool, error) {
	return false, nil
}
func (m *mockAdminStoreVerifyTOTPInfraError) EnsureGoogleUser(email string)            {}
func (m *mockAdminStoreVerifyTOTPInfraError) HasTOTP(email string) bool                { return true }
func (m *mockAdminStoreVerifyTOTPInfraError) SetTOTPSecret(email, plain string) error  { return nil }
func (m *mockAdminStoreVerifyTOTPInfraError) VerifyTOTP(email, code string) (bool, error) {
	// The injected infrastructure error — matches the production case
	// of "encryption key missing" or a downstream DB read failure.
	return false, errSimulatedInfraFailure
}
func (m *mockAdminStoreVerifyTOTPInfraError) ClearTOTPSecret(email string) error { return nil }

var errSimulatedInfraFailure = mfaTestError("simulated VerifyTOTP infra error")

type mfaTestError string

func (e mfaTestError) Error() string { return string(e) }

// TestHandleAdminMFAVerify_NoEmailContext_Unauthorized — handlers_admin_mfa.go:144-147.
// Direct mirror of TestHandleAdminMFAEnroll_GET_NoEmailContext for the
// verify endpoint. Missing email context → 401, no redirect.
func TestHandleAdminMFAVerify_NoEmailContext_Unauthorized(t *testing.T) {
	t.Parallel()
	h, _ := newMFATestHandler(t, "admin@test.com", true)
	req := httptest.NewRequest(http.MethodGet, "/auth/admin-mfa/verify", nil)
	// No ContextWithEmail call — email-from-context returns "".
	rec := httptest.NewRecorder()
	h.HandleAdminMFAVerify(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code,
		"verify endpoint must 401 when upstream auth did not set email — guards lines 144-147")
}

// TestHandleAdminMFAVerify_POST_BadCSRF_Refused — handlers_admin_mfa.go:164-167.
// POST verify with a mismatched CSRF cookie/form pair must re-render the
// form with the CSRF error and NOT attempt verification.
func TestHandleAdminMFAVerify_POST_BadCSRF_Refused(t *testing.T) {
	t.Parallel()
	h, store := newMFATestHandler(t, "admin@test.com", true)
	secret, err := users.GenerateTOTPSecret()
	require.NoError(t, err)
	require.NoError(t, store.SetTOTPSecret("admin@test.com", secret),
		"precondition: user must be enrolled for verify to reach CSRF check")

	form := url.Values{}
	form.Set("code", "anything")
	form.Set("redirect", "/admin/ops")
	form.Set("csrf_token", "form-token")
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-mfa/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Cookie token != form token → CSRF guard rejects.
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin_mfa", Value: "cookie-token"})
	req = req.WithContext(ContextWithEmail(req.Context(), "admin@test.com"))
	rec := httptest.NewRecorder()
	h.HandleAdminMFAVerify(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code,
		"CSRF mismatch on verify re-renders the form")
	assert.Contains(t, rec.Body.String(), "Invalid or expired CSRF token",
		"CSRF failure message must appear in the re-rendered form")
	// No MFA cookie may be set.
	for _, c := range rec.Result().Cookies() {
		assert.NotEqual(t, "kite_admin_mfa", c.Name,
			"no MFA cookie may be minted when CSRF check failed")
	}
}

func TestHandleAdminMFAVerify_POST_VerifyInfraError_Refused(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	h.SetUserStore(&mockAdminStoreVerifyTOTPInfraError{})

	form := url.Values{}
	form.Set("code", "123456")
	form.Set("redirect", "/admin/ops")
	form.Set("csrf_token", "csrf-verify-token")
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-mfa/verify", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin_mfa", Value: "csrf-verify-token"})
	req = req.WithContext(ContextWithEmail(req.Context(), "admin@test.com"))
	rec := httptest.NewRecorder()
	h.HandleAdminMFAVerify(rec, req)

	// Expect form re-render with infra-error message. NO redirect, NO MFA cookie.
	assert.Equal(t, http.StatusOK, rec.Code,
		"VerifyTOTP infra-error must re-render the verify form (not redirect)")
	assert.Contains(t, rec.Body.String(), "Verification temporarily unavailable",
		"infra-error path must surface the temp-unavailable message — line 171")
	for _, c := range rec.Result().Cookies() {
		assert.NotEqual(t, "kite_admin_mfa", c.Name,
			"no MFA cookie may be minted when VerifyTOTP errored")
	}
}
