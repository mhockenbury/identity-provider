package fga

// Type prefixes used in OpenFGA tuples. Always written as
// "<type>:<id>" — these constants are the prefix INCLUDING the colon
// so callers can write `fga.TypeUser + uid.String()` without manually
// adding the separator and risking a typo.
//
// The strings here MUST match the type names in internal/fga/model.fga.
// If you add a type to model.fga, add a const here.
const (
	TypeUser     = "user:"
	TypeGroup    = "group:"
	TypeFolder   = "folder:"
	TypeDocument = "document:"
)

// Relation names referenced in Check, Write, and tuple construction.
// Same source-of-truth note as Type*: must match model.fga.
const (
	RelOwner  = "owner"
	RelEditor = "editor"
	RelViewer = "viewer"
	RelMember = "member"
	RelParent = "parent"
)
