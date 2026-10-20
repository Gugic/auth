package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/crypto"
	mail "github.com/supabase/auth/internal/mailer"
	"github.com/supabase/auth/internal/mailer/mockclient"
	"github.com/supabase/auth/internal/models"
)

func securityTestAPI(t *testing.T) (*API, *mockclient.MockMailer) {
	t.Helper()
	mailer := &mockclient.MockMailer{}
	a, _, err := setupAPIForTest(WithMailer(mailer))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, a.db.Close()) })
	require.NoError(t, models.TruncateAll(a.db))
	return a, mailer
}

func securityRequest(a *API, path string, body any) *httptest.ResponseRecorder {
	data, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(data))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.handler.ServeHTTP(w, r)
	return w
}

func securityGenerateLink(t *testing.T, a *API, kind, email string, newEmail ...string) GenerateLinkResponse {
	t.Helper()
	body := map[string]string{"type": kind, "email": email, "password": "test-password"}
	if len(newEmail) > 0 {
		body["new_email"] = newEmail[0]
	}
	data, err := json.Marshal(body)
	require.NoError(t, err)
	r := httptest.NewRequest(http.MethodPost, "/admin/generate_link", bytes.NewReader(data))
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, &AccessTokenClaims{Role: "supabase_admin"}).SignedString([]byte(a.config.JWT.Secret))
	require.NoError(t, err)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.handler.ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var result GenerateLinkResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	return result
}

func TestVerificationSecurityIndependentLink(t *testing.T) {
	for _, redemption := range []string{"hash", "code"} {
		t.Run(redemption, func(t *testing.T) {
			a, _ := securityTestAPI(t)
			link := securityGenerateLink(t, a, mail.MagicLinkVerification, "security@example.com")
			guess := crypto.GenerateTokenHash(link.GetEmail(), link.EmailOtp)
			require.NotEqual(t, guess, link.HashedToken, "knowing the numeric code must not reveal the link credential")
			require.Len(t, link.HashedToken, 64)
			_, err := models.FindEmailTokenByOTP(a.db, link.GetEmail(), a.config.JWT.Aud, guess, models.ConfirmationToken, models.RecoveryToken)
			require.NoError(t, err)
			w := securityRequest(a, "/verify", map[string]string{"type": link.VerificationType, "token_hash": guess})
			require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
			body := map[string]string{"type": link.VerificationType, "token_hash": link.HashedToken}
			if redemption == "code" {
				body = map[string]string{"type": link.VerificationType, "email": link.GetEmail(), "token": link.EmailOtp}
			}
			w = securityRequest(a, "/verify", body)
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			w = securityRequest(a, "/verify", map[string]string{"type": link.VerificationType, "token_hash": link.HashedToken})
			require.Equal(t, http.StatusForbidden, w.Code, "either redemption must consume both credentials")
		})
	}
}

func TestVerificationSecurityAttemptsSurviveResendAndReplica(t *testing.T) {
	a, _ := securityTestAPI(t)
	link := securityGenerateLink(t, a, mail.MagicLinkVerification, "security@example.com")
	for range 10 {
		w := securityRequest(a, "/verify", map[string]string{"type": "email", "email": link.GetEmail(), "token": "wrong-code"})
		require.Equal(t, http.StatusForbidden, w.Code)
	}
	// Admin minting replaces the challenge, just as a resend does.
	link = securityGenerateLink(t, a, mail.MagicLinkVerification, link.GetEmail())
	b, _, err := setupAPIForTest()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, b.db.Close()) })
	w := securityRequest(b, "/verify", map[string]string{"type": link.VerificationType, "email": link.GetEmail(), "token": link.EmailOtp})
	require.Equal(t, http.StatusForbidden, w.Code, "another replica and a new challenge must share the failure budget")
	w = securityRequest(b, "/verify", map[string]string{"type": link.VerificationType, "token_hash": link.HashedToken})
	require.Equal(t, http.StatusOK, w.Code, "numeric-code exhaustion must not lock out a user holding their email link")
}

func TestVerificationSecurityConcurrentRedemption(t *testing.T) {
	a, _ := securityTestAPI(t)
	link := securityGenerateLink(t, a, mail.MagicLinkVerification, "security@example.com")
	start := make(chan struct{})
	results := make(chan int, 32)
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			body := map[string]string{"type": link.VerificationType, "token_hash": link.HashedToken}
			if i%2 == 0 {
				body = map[string]string{"type": link.VerificationType, "email": link.GetEmail(), "token": link.EmailOtp}
			}
			w := securityRequest(a, "/verify", body)
			results <- w.Code
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	for code := range results {
		if code == http.StatusOK {
			successes++
		} else {
			require.Equal(t, http.StatusForbidden, code)
		}
	}
	require.Equal(t, 1, successes, "a challenge must mint at most one session under concurrent redemption")
}

func TestVerificationSecurityAdminActions(t *testing.T) {
	for _, kind := range []string{mail.SignupVerification, mail.InviteVerification, mail.RecoveryVerification} {
		t.Run(kind, func(t *testing.T) {
			a, _ := securityTestAPI(t)
			if kind == mail.RecoveryVerification {
				securityGenerateLink(t, a, mail.SignupVerification, "security@example.com")
			}
			link := securityGenerateLink(t, a, kind, "security@example.com")
			w := securityRequest(a, "/verify", map[string]string{"type": link.VerificationType, "email": link.GetEmail(), "token": link.EmailOtp})
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			w = securityRequest(a, "/verify", map[string]string{"type": link.VerificationType, "token_hash": link.HashedToken})
			require.Equal(t, http.StatusForbidden, w.Code)
		})
	}
}

func TestVerificationSecurityEmailChange(t *testing.T) {
	for _, currentFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "current-first", false: "new-first"}[currentFirst], func(t *testing.T) {
			a, _ := securityTestAPI(t)
			initial := securityGenerateLink(t, a, mail.MagicLinkVerification, "security@example.com")
			require.Equal(t, http.StatusOK, securityRequest(a, "/verify", map[string]string{"type": initial.VerificationType, "token_hash": initial.HashedToken}).Code)
			current := securityGenerateLink(t, a, mail.EmailChangeCurrentVerification, initial.GetEmail(), "new@example.com")
			changed := securityGenerateLink(t, a, mail.EmailChangeNewVerification, initial.GetEmail(), "new@example.com")
			steps := []map[string]string{
				{"type": mail.EmailChangeVerification, "email": initial.GetEmail(), "token": current.EmailOtp},
				{"type": mail.EmailChangeVerification, "email": "new@example.com", "token": changed.EmailOtp},
			}
			if !currentFirst {
				steps[0], steps[1] = steps[1], steps[0]
			}
			for _, body := range steps {
				w := securityRequest(a, "/verify", body)
				require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			}
			user, err := models.FindUserByID(a.db, initial.ID)
			require.NoError(t, err)
			require.Equal(t, "new@example.com", user.GetEmail())
			for _, token := range []string{current.HashedToken, changed.HashedToken} {
				w := securityRequest(a, "/verify", map[string]string{"type": mail.EmailChangeVerification, "token_hash": token})
				require.Equal(t, http.StatusForbidden, w.Code)
			}
		})
	}
}

func TestVerificationSecurityServerErrorsRefundBudget(t *testing.T) {
	a, _ := securityTestAPI(t)
	a.config.Mailer.OtpMaxAttempts = 2
	link := securityGenerateLink(t, a, mail.MagicLinkVerification, "security@example.com")
	require.NoError(t, a.db.RawQuery(`CREATE FUNCTION fail_security_test_session() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'forced test failure'; END $$`).Exec())
	t.Cleanup(func() {
		require.NoError(t, a.db.RawQuery("DROP FUNCTION fail_security_test_session() CASCADE").Exec())
	})
	require.NoError(t, a.db.RawQuery(`CREATE TRIGGER fail_security_test_session BEFORE INSERT ON sessions
FOR EACH ROW EXECUTE FUNCTION fail_security_test_session()`).Exec())
	body := map[string]string{"type": link.VerificationType, "email": link.GetEmail(), "token": link.EmailOtp}
	for range 4 {
		w := securityRequest(a, "/verify", body)
		require.Equal(t, http.StatusInternalServerError, w.Code, "upstream failures must neither consume the challenge nor exhaust its attempt budget")
	}
	require.NoError(t, a.db.RawQuery("DROP TRIGGER fail_security_test_session ON sessions").Exec())
	w := securityRequest(a, "/verify", body)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
}
