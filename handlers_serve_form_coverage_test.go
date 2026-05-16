package oauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ---------------------------------------------------------------------------
// Coverage closure for the template-Execute error branches in serve-form
// helpers. Nil-template branches are already covered by:
//   - TestServeAdminLoginForm_NilTemplate (handlers_admin_test.go:266)
//   - TestServeEmailPrompt_NilTemplate (handlers_browser_test.go:616)
//   - TestServeAdminMFAEnrollForm_NilTemplate (this file's MFA sibling)
//   - TestServeAdminMFAVerifyForm_NilTemplate (this file's MFA sibling)
//
// What remains uncovered: the ExecuteTemplate error branch in each helper.
// Injecting brokenExecTemplate(t) (parses cleanly, ExecuteTemplate fails
// at runtime due to an undefined inner template) is the minimal-blast
// way to drive that branch without modifying production code.
// ---------------------------------------------------------------------------

// TestServeAdminLoginForm_ExecuteError — handlers_admin.go:
// ExecuteTemplate error branch. CSRF cookie IS set first (the SetCookie
// guard precedes ExecuteTemplate); pin that observable so a reordering
// regression that drops the cookie on this path is caught.
func TestServeAdminLoginForm_ExecuteError(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()
	h.adminLoginTmpl = brokenExecTemplate(t)

	rec := httptest.NewRecorder()
	h.serveAdminLoginForm(rec, "/admin/ops", "", "csrf-token-value")

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "Internal server error")
	csrfFound := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == "csrf_token_admin" {
			csrfFound = true
		}
	}
	assert.True(t, csrfFound,
		"CSRF cookie must be set before ExecuteTemplate; regression guard")
}

// TestServeEmailPrompt_ExecuteError — handlers_oauth.go: ExecuteTemplate
// error branch (CSRF cookie set first; pin via assertion).
func TestServeEmailPrompt_ExecuteError(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()
	h.emailPromptTmpl = brokenExecTemplate(t)

	rec := httptest.NewRecorder()
	state := oauthState{
		ClientID:      "test-client",
		RedirectURI:   "https://example.com/cb",
		State:         "abc",
		CodeChallenge: "challenge",
	}
	h.serveEmailPrompt(rec, state, "")

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "Internal server error")
	csrfFound := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == "csrf_token" {
			csrfFound = true
		}
	}
	assert.True(t, csrfFound,
		"CSRF cookie must be set before ExecuteTemplate; regression guard")
}
