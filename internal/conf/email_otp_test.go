package conf

import (
	"testing"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/stretchr/testify/require"
)

func TestEmailOTPBudgetConfiguration(t *testing.T) {
	var config MailerConfiguration
	require.NoError(t, envconfig.Process("GOTRUE_TEST_MAILER", &config))
	require.NoError(t, config.Validate())
	require.Equal(t, 10, config.OtpMaxAttempts)
	require.Equal(t, 15*time.Minute, config.OtpAttemptWindow)
	require.NoError(t, config.Validate())
	t.Setenv("GOTRUE_TEST_MAILER_OTP_MAX_ATTEMPTS", "3")
	t.Setenv("GOTRUE_TEST_MAILER_OTP_ATTEMPT_WINDOW", "5m")
	require.NoError(t, envconfig.Process("GOTRUE_TEST_MAILER", &config))
	require.Equal(t, 3, config.OtpMaxAttempts)
	require.Equal(t, 5*time.Minute, config.OtpAttemptWindow)
	config.OtpMaxAttempts = 0
	require.NoError(t, config.Validate())
	require.Equal(t, 10, config.OtpMaxAttempts)
	config.OtpMaxAttempts = -1
	require.Error(t, config.Validate())
	config.OtpMaxAttempts = 3
	config.OtpAttemptWindow = -time.Second
	require.Error(t, config.Validate())
}
