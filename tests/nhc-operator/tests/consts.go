package tests

// Shared string-literal constants for the nhc-operator test package. These
// deduplicate repeated literals flagged by goconst; each value is byte-identical
// to the literal it replaces.
const (
	// Kubernetes unstructured field keys.
	keyAPIVersion          = "apiVersion"
	keyKind                = "kind"
	keyName                = "name"
	keyNamespace           = "namespace"
	keySpec                = "spec"
	keyType                = "type"
	keyStatus              = "status"
	keyDuration            = "duration"
	keyTimeout             = "timeout"
	keyObject              = "object"
	keyRemediationTemplate = "remediationTemplate"

	// Node condition type and status strings used in unhealthyConditions.
	// "Ready" is the condition type; "False"/"Unknown" are condition statuses.
	conditionTypeReady     = "Ready"
	conditionStatusFalse   = "False"
	conditionStatusUnknown = "Unknown"

	// testRemediationTemplateKind is the Kind string for the dummy
	// TestRemediationTemplate CRs used by multi-NHC tests.
	testRemediationTemplateKind = "TestRemediationTemplate"
)
