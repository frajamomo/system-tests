package tests

// Shared string constants for the sbr-operator test suite. Extracted to satisfy
// goconst (repeated string literals) without changing runtime behavior.
const (
	// SBRC/SBR field keys used when building unstructured CRs and map payloads.
	sharedStorageClassKey = "sharedStorageClass"
	sbrTimeoutSecondsKey  = "sbrTimeoutSeconds"

	// Kubernetes CR kinds.
	storageBasedRemediationTemplateKind = "StorageBasedRemediationTemplate"
	nodeHealthCheckKind                 = "NodeHealthCheck"

	// Common Kubernetes unstructured field keys.
	keyAPIVersion = "apiVersion"
	keyKind       = "kind"
	keyName       = "name"
	keyNamespace  = "namespace"
	keySpec       = "spec"
	keyType       = "type"
	keyStatus     = "status"
	keyDuration   = "duration"

	// iptables/nsenter CLI flags used to disrupt CephFS traffic.
	flagPID       = "--pid"
	flagMount     = "--mount"
	flagNet       = "--net"
	flagDport     = "--dport"
	flagSport     = "--sport"
	portRange6800 = "6800:7300"

	// nsenter binary and iptables chain names.
	cmdNsenter       = "nsenter"
	cmdIptables      = "iptables"
	iptablesChainIn  = "INPUT"
	iptablesChainOut = "OUTPUT"
	flagTarget       = "--target"
	iptablesReject   = "REJECT"
	protoTCP         = "tcp"
)
