package core

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResourceType(t *testing.T) {
	baseURL := "http://localhost:9999/scim/v2"

	t.Run("locates a resource that is its own endpoint", func(t *testing.T) {
		meta := NewMeta(baseURL, ResourceType{Name: "Resource", Endpoint: "/Resources"})

		require.Equal(t, ResourceTypeName("Resource"), meta.ResourceType)
		require.Equal(t, baseURL+"/Resources", meta.Location)
		require.Zero(t, meta.Created)
		require.Zero(t, meta.LastModified)
	})

	t.Run("NewResourceType", func(t *testing.T) {
		schema := NewSchema(baseURL, SchemaUser, ResourceTypeUser.Name).Describe("User Account")

		resourceType := NewResourceType(baseURL, schema, ResourceTypeUser.Endpoint)

		t.Run("takes its identity and description from the schema", func(t *testing.T) {
			require.Equal(t, ResourceTypeUser.Name, resourceType.ID)
			require.Equal(t, ResourceTypeUser.Name, resourceType.Name)
			require.Equal(t, "User Account", resourceType.Description)
			require.Equal(t, SchemaUser, resourceType.Schema)
		})

		t.Run("locates itself under the ResourceTypes endpoint", func(t *testing.T) {
			require.Equal(t, ResourceTypeResourceType.Name, resourceType.Meta.ResourceType)
			require.Equal(t, baseURL+"/ResourceTypes/User", resourceType.Meta.Location)
		})

		t.Run("reports no timestamps, because it is static", func(t *testing.T) {
			body, err := json.Marshal(resourceType)

			require.NoError(t, err)
			require.NotContains(t, string(body), `"created"`)
			require.NotContains(t, string(body), `"lastModified"`)
		})
	})
}
