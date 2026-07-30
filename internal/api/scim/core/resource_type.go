package core

import "time"

var (
	ResourceTypeGroup = ResourceType{
		Name:     "Group",
		Endpoint: "/Groups",
	}

	ResourceTypeResourceType = ResourceType{
		Name:     "ResourceType",
		Endpoint: "/ResourceTypes",
	}

	ResourceTypeSchema = ResourceType{
		Name:     "Schema",
		Endpoint: "/Schemas",
	}

	ResourceTypeServiceProviderConfig = ResourceType{
		Name:     "ServiceProviderConfig",
		Endpoint: "/ServiceProviderConfig",
	}

	ResourceTypeUser = ResourceType{
		Name:     "User",
		Endpoint: "/Users",
	}
)

type ResourceTypeName string

// ResourceType is the resource type metadata defined in RFC 7643, Section 6.
// The package-level values above carry only the name and endpoint, which is
// all that locating a resource needs; NewResourceType fills in the rest for
// the ones served from /ResourceTypes.
type ResourceType struct {
	Schemas     []SchemaURI      `json:"schemas,omitempty"`
	ID          ResourceTypeName `json:"id,omitempty"`
	Name        ResourceTypeName `json:"name"`
	Description string           `json:"description,omitempty"`
	Endpoint    string           `json:"endpoint"`
	Schema      SchemaURI        `json:"schema,omitempty"`
	Meta        Meta             `json:"meta,omitzero"`
}

// NewResourceType builds the resource type describing schema, served at
// endpoint. Taking the schema rather than its URI is what makes RFC 7643,
// Section 6 hold by construction: the resource type's schema attribute "MUST
// be equal to the id attribute of the associated Schema resource".
func NewResourceType(baseURL string, schema *Schema, endpoint string) *ResourceType {
	resourceType := &ResourceType{
		Schemas:     []SchemaURI{SchemaResourceType},
		ID:          schema.Name,
		Name:        schema.Name,
		Description: schema.Description,
		Endpoint:    endpoint,
		Schema:      schema.ID,
	}
	resourceType.Meta = NewMeta(baseURL, ResourceTypeResourceType).For(resourceType)

	return resourceType
}

func (r ResourceType) Location(baseURL string) string {
	return baseURL + r.Endpoint
}

func (r *ResourceType) ResourceID() string { return string(r.ID) }

func (r *ResourceType) ResourceType() ResourceType { return ResourceTypeResourceType }

// Timestamps reports none, because a resource type is static.
func (r *ResourceType) Timestamps() (created, updated time.Time) { return }
