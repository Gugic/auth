package api

import (
	tst "testing"
	"time"

	"encoding/xml"
	"net/http"
	"net/http/httptest"

	"github.com/crewjam/saml"
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
	"github.com/supabase/auth/internal/conf/confload"
)

// samlOverrideConfig builds a SAML-enabled config with the given ACS URL / entity id overrides.
func samlOverrideConfig(t *tst.T, acsURL, entityID string) *conf.GlobalConfiguration {
	config, err := confload.LoadGlobal(apiTestConfig)
	require.NoError(t, err)
	config.API.ExternalURL = "https://projectref.supabase.co/auth/v1/"
	config.API.MaxRequestDuration = 5 * time.Second
	config.SAML.Enabled = true
	config.SAML.PrivateKey = samlTestPrimaryKey
	config.SAML.AcsURL = acsURL
	config.SAML.EntityID = entityID

	require.NoError(t, config.ApplyDefaults())
	require.NoError(t, config.SAML.PopulateFields(config.API.ExternalURL))
	return config
}

func samlOverrideMetadata(t *tst.T, config *conf.GlobalConfiguration) *saml.EntityDescriptor {
	api := NewAPI(config, nil)

	req := httptest.NewRequest(http.MethodGet, "http://localhost/sso/saml/metadata", nil)
	w := httptest.NewRecorder()
	api.handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	metadata := &saml.EntityDescriptor{}
	require.NoError(t, xml.Unmarshal(w.Body.Bytes(), metadata))
	return metadata
}

// TestSAMLAcsURLOverride pins the reason the override exists: the ACS URL is named inside the signed
// assertion (SubjectConfirmationData/@Recipient, Response/@Destination), so an SP that must accept
// assertions addressed to a pre-existing endpoint has to treat that endpoint as its ACS. The
// published metadata and the outbound AuthnRequest have to agree with it, or the IdP and the SP
// disagree about where responses go.
func TestSAMLAcsURLOverride(t *tst.T) {
	const legacyACS = "https://auth.example.com/__/auth/handler"

	config := samlOverrideConfig(t, legacyACS, "")
	metadata := samlOverrideMetadata(t, config)

	require.Equal(t, 1, len(metadata.SPSSODescriptors))
	acs := metadata.SPSSODescriptors[0].AssertionConsumerServices
	require.Equal(t, 2, len(acs))
	require.Equal(t, legacyACS, acs[0].Location)
	require.Equal(t, legacyACS, acs[1].Location)

	// Entity id is untouched by the ACS override, and SLO keeps the derived URL: only the two values
	// an IdP is configured with are overridable.
	require.Equal(t, "https://projectref.supabase.co/auth/v1/sso/saml/metadata", metadata.EntityID)
	require.Equal(
		t,
		"https://projectref.supabase.co/auth/v1/sso/saml/slo",
		metadata.SPSSODescriptors[0].SingleLogoutServices[0].Location,
	)
}

// TestSAMLEntityIDOverride covers the second half: the entity id is checked by the IdP as the
// assertion's AudienceRestriction and as the Issuer of the AuthnRequest we send.
func TestSAMLEntityIDOverride(t *tst.T) {
	const legacyEntityID = "https://platform.example.com/saml/sp"

	config := samlOverrideConfig(t, "", legacyEntityID)
	metadata := samlOverrideMetadata(t, config)

	require.Equal(t, legacyEntityID, metadata.EntityID)
	// ACS stays derived when only the entity id is overridden.
	require.Equal(
		t,
		"https://projectref.supabase.co/auth/v1/sso/saml/acs",
		metadata.SPSSODescriptors[0].AssertionConsumerServices[0].Location,
	)
}

// TestSAMLOverridesUnsetKeepDerivedURLs is the regression guard that matters most: with both
// overrides empty the SP must behave exactly as it did before the patch.
func TestSAMLOverridesUnsetKeepDerivedURLs(t *tst.T) {
	config := samlOverrideConfig(t, "", "")
	metadata := samlOverrideMetadata(t, config)

	require.Equal(t, "https://projectref.supabase.co/auth/v1/sso/saml/metadata", metadata.EntityID)
	require.Equal(
		t,
		"https://projectref.supabase.co/auth/v1/sso/saml/acs",
		metadata.SPSSODescriptors[0].AssertionConsumerServices[0].Location,
	)
}

// TestSAMLAcsURLOverrideRejectsMalformed keeps the failure at boot rather than at the first sign-in:
// newSAMLServiceProvider panics on an unparseable value, so Validate has to catch it first.
func TestSAMLAcsURLOverrideRejectsMalformed(t *tst.T) {
	config, err := confload.LoadGlobal(apiTestConfig)
	require.NoError(t, err)
	config.SAML.Enabled = true
	config.SAML.PrivateKey = samlTestPrimaryKey
	config.SAML.AcsURL = "not a url at all"

	require.Error(t, config.SAML.Validate())
}
