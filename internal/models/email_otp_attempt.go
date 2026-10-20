package models

import (
	"database/sql"
	"errors"
	"time"

	"github.com/gofrs/uuid"
	"github.com/supabase/auth/internal/observability"
	"github.com/supabase/auth/internal/storage"
)

// EmailOTPAttempt holds reservations and failed guesses across replicas and
// challenge replacements. Key is a digest of the audience and email address.
type EmailOTPAttempt struct {
	WindowID uuid.UUID `db:"window_id"`
}

func (EmailOTPAttempt) TableName() string { return "email_otp_attempts" }

// ReserveEmailOTPAttempt atomically bounds failures plus in-flight attempts.
// Successful requests and non-credential errors release their reservation.
func ReserveEmailOTPAttempt(db *storage.Connection, key string, limit int, window time.Duration) (uuid.UUID, bool, error) {
	ctx, span := observability.Tracer("gotrue").Start(db.Context(), "email-otp-attempt-reserve")
	defer span.End()
	db = db.WithContext(ctx)
	// Cleanup uses a separate autocommit statement so pruning one address
	// cannot hold its row lock while reserving another address's budget.
	if err := db.RawQuery(`DELETE FROM email_otp_attempts WHERE key IN (
SELECT key FROM email_otp_attempts WHERE expires_at <= now()
ORDER BY expires_at LIMIT 100 FOR UPDATE SKIP LOCKED)`).Exec(); err != nil {
		return uuid.Nil, false, err
	}
	result := EmailOTPAttempt{}
	err := db.RawQuery(`
INSERT INTO email_otp_attempts AS budget (key, window_id, attempts, expires_at)
VALUES (?, ?, 1, now() + (? * interval '1 second'))
ON CONFLICT (key) DO UPDATE SET
    attempts = CASE WHEN budget.expires_at <= now() THEN 1 ELSE budget.attempts + 1 END,
    window_id = CASE WHEN budget.expires_at <= now() THEN EXCLUDED.window_id ELSE budget.window_id END,
    expires_at = CASE WHEN budget.expires_at <= now() THEN EXCLUDED.expires_at ELSE budget.expires_at END
WHERE budget.expires_at <= now() OR budget.attempts < ?
RETURNING window_id`, key, uuid.Must(uuid.NewV4()), window.Seconds(), limit).First(&result)
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, false, nil
	}
	return result.WindowID, err == nil, err
}

func ReleaseEmailOTPAttempt(db *storage.Connection, key string, window uuid.UUID) error {
	ctx, span := observability.Tracer("gotrue").Start(db.Context(), "email-otp-attempt-release")
	defer span.End()
	// A late response must not refund an attempt from a newer window.
	return db.WithContext(ctx).RawQuery(`UPDATE email_otp_attempts SET attempts = attempts - 1
WHERE key = ? AND window_id = ? AND attempts > 0`, key, window).Exec()
}
