package tests

// Shared string constants used across the snr-operator tests package to
// avoid repeated string literals (goconst).
const (
	// Kubernetes unstructured field keys.
	keyAPIVersion          = "apiVersion"
	keyKind                = "kind"
	keyMetadata            = "metadata"
	keyName                = "name"
	keyNamespace           = "namespace"
	keySpec                = "spec"
	keyRemediationStrategy = "remediationStrategy"

	// SNR custom resource kinds.
	selfNodeRemediationKind         = "SelfNodeRemediation"
	selfNodeRemediationTemplateKind = "SelfNodeRemediationTemplate"
)
