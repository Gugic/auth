package api

import (
	"crypto/sha256"
	"fmt"
	"strings"

	mail "github.com/supabase/auth/internal/mailer"
	"github.com/supabase/auth/internal/models"
)

func emailOTPBudgetKey(aud, email string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%d:%s%s", len(aud), aud, strings.ToLower(email)))))
}

func emailOTPTokenTypes(kind string) (models.OneTimeTokenType, models.OneTimeTokenType, bool) {
	switch kind {
	case mail.EmailOTPVerification:
		return models.ConfirmationToken, models.RecoveryToken, true
	case mail.SignupVerification, mail.InviteVerification:
		return models.ConfirmationToken, models.ConfirmationToken, true
	case mail.RecoveryVerification, mail.MagicLinkVerification:
		return models.RecoveryToken, models.RecoveryToken, true
	case mail.EmailChangeVerification:
		return models.EmailChangeTokenCurrent, models.EmailChangeTokenNew, true
	default:
		return 0, 0, false
	}
}
