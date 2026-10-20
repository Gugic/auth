package models

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf/confload"
	"github.com/supabase/auth/internal/storage/test"
)

func TestEmailOTPAttempts(t *testing.T) {
	config, err := confload.LoadGlobal(modelsTestConfig)
	require.NoError(t, err)
	db, err := test.SetupDBConnection(config)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	key := uuid.Must(uuid.NewV4()).String()
	var admitted atomic.Int32
	var wg sync.WaitGroup
	errors := make(chan error, 64)
	start := make(chan struct{})
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, allowed, err := ReserveEmailOTPAttempt(db, key, 3, time.Minute)
			if err != nil {
				errors <- err
			}
			if allowed {
				admitted.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
	require.EqualValues(t, 3, admitted.Load(), "concurrent replicas must share an atomic budget")
	// Force an expired window, without a timing-dependent sleep.
	require.NoError(t, db.RawQuery("UPDATE email_otp_attempts SET expires_at = now() - interval '1 second' WHERE key = ?", key).Exec())
	window, allowed, err := ReserveEmailOTPAttempt(db, key, 3, time.Minute)
	require.NoError(t, err)
	require.True(t, allowed)
	require.NoError(t, ReleaseEmailOTPAttempt(db, key, window))
	for range 3 {
		_, allowed, err = ReserveEmailOTPAttempt(db, key, 3, time.Minute)
		require.NoError(t, err)
		require.True(t, allowed, "a successful or unavailable verification must refund its reservation")
	}
	_, allowed, err = ReserveEmailOTPAttempt(db, key, 3, time.Minute)
	require.NoError(t, err)
	require.False(t, allowed)
	other := uuid.Must(uuid.NewV4()).String()
	old, allowed, err := ReserveEmailOTPAttempt(db, other, 1, time.Minute)
	require.NoError(t, err)
	require.True(t, allowed)
	require.NoError(t, db.RawQuery("UPDATE email_otp_attempts SET expires_at = now() - interval '1 second' WHERE key = ?", other).Exec())
	current, allowed, err := ReserveEmailOTPAttempt(db, other, 1, time.Minute)
	require.NoError(t, err)
	require.True(t, allowed)
	require.NotEqual(t, old, current)
	require.NoError(t, ReleaseEmailOTPAttempt(db, other, old))
	_, allowed, err = ReserveEmailOTPAttempt(db, other, 1, time.Minute)
	require.NoError(t, err)
	require.False(t, allowed, "a stale request must not refund a new window")
	require.NoError(t, db.RawQuery("UPDATE email_otp_attempts SET expires_at = now() - interval '1 second' WHERE key = ?", other).Exec())
	_, _, err = ReserveEmailOTPAttempt(db, key, 3, time.Minute)
	require.NoError(t, err)
	var count struct{ Count int }
	require.NoError(t, db.RawQuery("SELECT count(*) AS count FROM email_otp_attempts WHERE key = ?", other).First(&count))
	require.Zero(t, count.Count, "expired addresses must be pruned without enabling general database cleanup")
}
