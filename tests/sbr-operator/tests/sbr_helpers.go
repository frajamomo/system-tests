package tests

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/rh-ecosystem-edge/eco-goinfra/pkg/pod"

	. "github.com/medik8s/system-tests/tests/internal/medik8sinittools"
	"github.com/medik8s/system-tests/tests/internal/medik8sparams"
	"github.com/medik8s/system-tests/tests/sbr-operator/internal/sbrparams"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

// getNodeBootID returns the bootID of the named node.
func getNodeBootID(nodeName string) (string, error) {
	node, err := APIClient.CoreV1Interface.Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("get node %s: %w", nodeName, err)
	}

	bootID := node.Status.NodeInfo.BootID
	if bootID == "" {
		return "", fmt.Errorf("node %s boot-id is empty", nodeName)
	}

	return bootID, nil
}

// cephFSRejectBidirectional defines nsenter + iptables REJECT rules for both INPUT and OUTPUT
// chains covering all CephFS port groups: 3300 (msgr2), 6789 (msgr1 mon), 6800-7300 (OSD/MDS).
var cephFSRejectBidirectional = [][]string{
	{cmdNsenter, flagTarget, "1", flagNet, flagMount, "--",
		cmdIptables, "-I", iptablesChainOut, "-p", protoTCP, flagDport, "3300", "-j", iptablesReject},
	{cmdNsenter, flagTarget, "1", flagNet, flagMount, "--",
		cmdIptables, "-I", iptablesChainIn, "-p", protoTCP, flagSport, "3300", "-j", iptablesReject},
	{cmdNsenter, flagTarget, "1", flagNet, flagMount, "--",
		cmdIptables, "-I", iptablesChainOut, "-p", protoTCP, flagDport, "6789", "-j", iptablesReject},
	{cmdNsenter, flagTarget, "1", flagNet, flagMount, "--",
		cmdIptables, "-I", iptablesChainIn, "-p", protoTCP, flagSport, "6789", "-j", iptablesReject},
	{cmdNsenter, flagTarget, "1", flagNet, flagMount, "--",
		cmdIptables, "-I", iptablesChainOut, "-p", protoTCP, flagDport, portRange6800, "-j", iptablesReject},
	{cmdNsenter, flagTarget, "1", flagNet, flagMount, "--",
		cmdIptables, "-I", iptablesChainIn, "-p", protoTCP, flagSport, portRange6800, "-j", iptablesReject},
}

// cephFSFlushBidirectional defines the corresponding -D (delete) rules for cephFSRejectBidirectional.
var cephFSFlushBidirectional = [][]string{
	{cmdNsenter, flagTarget, "1", flagNet, flagMount, "--",
		cmdIptables, "-D", iptablesChainOut, "-p", protoTCP, flagDport, "3300", "-j", iptablesReject},
	{cmdNsenter, flagTarget, "1", flagNet, flagMount, "--",
		cmdIptables, "-D", iptablesChainIn, "-p", protoTCP, flagSport, "3300", "-j", iptablesReject},
	{cmdNsenter, flagTarget, "1", flagNet, flagMount, "--",
		cmdIptables, "-D", iptablesChainOut, "-p", protoTCP, flagDport, "6789", "-j", iptablesReject},
	{cmdNsenter, flagTarget, "1", flagNet, flagMount, "--",
		cmdIptables, "-D", iptablesChainIn, "-p", protoTCP, flagSport, "6789", "-j", iptablesReject},
	{cmdNsenter, flagTarget, "1", flagNet, flagMount, "--",
		cmdIptables, "-D", iptablesChainOut, "-p", protoTCP, flagDport, portRange6800, "-j", iptablesReject},
	{cmdNsenter, flagTarget, "1", flagNet, flagMount, "--",
		cmdIptables, "-D", iptablesChainIn, "-p", protoTCP, flagSport, portRange6800, "-j", iptablesReject},
}

// cephFSRejectOutput defines nsenter + iptables REJECT rules for the OUTPUT chain only.
var cephFSRejectOutput = [][]string{
	{cmdNsenter, flagTarget, "1", flagNet, flagMount, "--",
		cmdIptables, "-I", iptablesChainOut, "-p", protoTCP, flagDport, "3300", "-j", iptablesReject},
	{cmdNsenter, flagTarget, "1", flagNet, flagMount, "--",
		cmdIptables, "-I", iptablesChainOut, "-p", protoTCP, flagDport, "6789", "-j", iptablesReject},
	{cmdNsenter, flagTarget, "1", flagNet, flagMount, "--",
		cmdIptables, "-I", iptablesChainOut, "-p", protoTCP, "--match", "multiport",
		"--dports", portRange6800, "-j", iptablesReject},
}

// cephFSFlushOutput defines the corresponding -D (delete) rules for cephFSRejectOutput.
var cephFSFlushOutput = [][]string{
	{cmdNsenter, flagTarget, "1", flagNet, flagMount, "--",
		cmdIptables, "-D", iptablesChainOut, "-p", protoTCP, flagDport, "3300", "-j", iptablesReject},
	{cmdNsenter, flagTarget, "1", flagNet, flagMount, "--",
		cmdIptables, "-D", iptablesChainOut, "-p", protoTCP, flagDport, "6789", "-j", iptablesReject},
	{cmdNsenter, flagTarget, "1", flagNet, flagMount, "--",
		cmdIptables, "-D", iptablesChainOut, "-p", protoTCP, "--match", "multiport",
		"--dports", portRange6800, "-j", iptablesReject},
}

// injectCephFSRejectBidirectional inserts iptables REJECT rules on both INPUT and OUTPUT chains
// for all CephFS ports via nsenter into the host network and mount namespaces.
// Calls Skip when the first iptables rule fails (e.g. nftables-only node without the
// iptables compatibility layer) so the test is skipped rather than hard-failed.
func injectCephFSRejectBidirectional(injectorPod *pod.Builder, nodeName string) {
	By(fmt.Sprintf("Injecting CephFS iptables REJECT rules (INPUT+OUTPUT) on node %s", nodeName))

	for ruleIdx, rule := range cephFSRejectBidirectional {
		if _, execErr := injectorPod.ExecCommand(rule); execErr != nil {
			if ruleIdx == 0 {
				Skip(fmt.Sprintf("iptables bidirectional injection not available on node %s: %v; "+
					"skipping test", nodeName, execErr))
			}

			Fail(fmt.Sprintf("Failed to inject iptables rule %v on node %q (rule %d of %d succeeded earlier): %v",
				rule, nodeName, ruleIdx, len(cephFSRejectBidirectional), execErr))
		}
	}
}

// removeCephFSRejectBidirectional deletes the iptables REJECT rules added by
// injectCephFSRejectBidirectional. Failures are logged as warnings; cleanup is best-effort.
func removeCephFSRejectBidirectional(injectorPod *pod.Builder) {
	for _, rule := range cephFSFlushBidirectional {
		if _, flushErr := injectorPod.ExecCommand(rule); flushErr != nil {
			GinkgoWriter.Printf("Warning: iptables cleanup (cmd %v): %v\n", rule, flushErr)
		}
	}
}

// injectCephFSRejectOutput inserts iptables OUTPUT-only REJECT rules for all CephFS ports.
// Calls Skip when iptables returns a non-zero exit code so that CI runs on nodes where the
// OUTPUT chain is not writable do not hard-fail.
func injectCephFSRejectOutput(injectorPod *pod.Builder, nodeName string) {
	By(fmt.Sprintf("Injecting CephFS iptables OUTPUT REJECT rules on node %s", nodeName))

	for _, rule := range cephFSRejectOutput {
		if _, execErr := injectorPod.ExecCommand(rule); execErr != nil {
			Skip(fmt.Sprintf("iptables OUTPUT injection not available on node %s (exit code 1): %v; "+
				"skipping test", nodeName, execErr))
		}
	}
}

// removeCephFSRejectOutput deletes the iptables OUTPUT rules added by injectCephFSRejectOutput.
// Failures are logged as warnings; cleanup is best-effort.
func removeCephFSRejectOutput(injectorPod *pod.Builder) {
	for _, rule := range cephFSFlushOutput {
		if _, flushErr := injectorPod.ExecCommand(rule); flushErr != nil {
			GinkgoWriter.Printf("Warning: iptables cleanup (cmd %v): %v\n", rule, flushErr)
		}
	}
}

// isNHCCRDInstalled returns true when the NodeHealthCheck CRD is registered in the cluster.
// Returns false only when the CRD is genuinely absent (IsNotFound). Transient API errors
// are propagated as test failures to avoid silently skipping NHC-dependent tests.
func isNHCCRDInstalled() bool {
	crd := &apiextensionsv1.CustomResourceDefinition{}

	err := APIClient.Get(context.TODO(),
		types.NamespacedName{Name: sbrparams.NHCCRDName}, crd)
	if err == nil {
		return true
	}

	if k8serrors.IsNotFound(err) {
		GinkgoWriter.Printf("isNHCCRDInstalled: CRD %s not found\n", sbrparams.NHCCRDName)

		return false
	}

	Fail(fmt.Sprintf("isNHCCRDInstalled: unexpected error checking CRD %s: %v",
		sbrparams.NHCCRDName, err))

	return false
}

// buildNHC returns an unstructured NodeHealthCheck CR that triggers SBR-based remediation
// when a worker node reports SBRStorageUnhealthy=True for NHCUnhealthyDuration.
func buildNHC(name string) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			keyAPIVersion: sbrparams.NHCAPIGroup + "/" + sbrparams.NHCAPIVersion,
			keyKind:       nodeHealthCheckKind,
			"metadata": map[string]interface{}{
				keyName: name,
			},
			keySpec: map[string]interface{}{
				// NHC requires exactly one of minHealthy/maxUnhealthy; omitting both is
				// rejected by the validating webhook ("one of minHealthy and maxUnhealthy
				// should be specified"). Since NHC v0.10.0 (maxUnhealthy support, PR #372)
				// the previous 51% default on minHealthy was removed to make the two fields
				// mutually exclusive, so it must now be set explicitly. 51% matches the
				// former default and the sample CRs.
				"minHealthy": "51%",
				"selector": map[string]interface{}{
					"matchExpressions": []interface{}{
						map[string]interface{}{
							"key":      medik8sparams.WorkerRoleLabel,
							"operator": "Exists",
						},
					},
				},
				"unhealthyConditions": []interface{}{
					map[string]interface{}{
						keyType:     sbrparams.SBRStorageUnhealthyCondition,
						keyStatus:   string(corev1.ConditionTrue),
						keyDuration: sbrparams.NHCUnhealthyDuration,
					},
				},
				"remediationTemplate": map[string]interface{}{
					keyAPIVersion: sbrparams.CRDGroup + "/" + sbrparams.CRDVersion,
					keyKind:       storageBasedRemediationTemplateKind,
					keyName:       sbrparams.SBRTemplateName,
					keyNamespace:  medik8sparams.OperatorNs,
				},
			},
		},
	}
}

// cleanupNHCCR deletes the named NodeHealthCheck CR. Safe to call when CR may not exist.
func cleanupNHCCR(name string) {
	nhc := &unstructured.Unstructured{}
	nhc.SetAPIVersion(sbrparams.NHCAPIGroup + "/" + sbrparams.NHCAPIVersion)
	nhc.SetKind(nodeHealthCheckKind)
	nhc.SetName(name)

	err := APIClient.Delete(context.TODO(), nhc)
	if err != nil && !k8serrors.IsNotFound(err) {
		GinkgoT().Logf("Warning: cleanup NHC %s: %v", name, err)
	}
}

// pickTargetWorkerNode returns the first schedulable worker node that does not host an SBR controller pod.
func pickTargetWorkerNode() string {
	controllerNodes := controllerPodNodes()

	nodeList, err := APIClient.CoreV1Interface.Nodes().List(context.TODO(), metav1.ListOptions{
		LabelSelector: medik8sparams.WorkerRoleLabel,
	})
	Expect(err).ToNot(HaveOccurred(), "Failed to list worker nodes")

	for nodeIdx := range nodeList.Items {
		node := &nodeList.Items[nodeIdx]
		if controllerNodes[node.Name] {
			GinkgoWriter.Printf("Skipping node %s (SBR controller pod runs there)\n", node.Name)

			continue
		}

		if isNodeSchedulable(node) {
			return node.Name
		}
	}

	return ""
}

// getSBRCRCondition returns the named status condition from an unstructured SBR CR, or nil.
func getSBRCRCondition(sbrObj *unstructured.Unstructured, condType string) map[string]interface{} {
	conditions, found, err := unstructured.NestedSlice(sbrObj.Object, keyStatus, "conditions")
	if err != nil || !found {
		return nil
	}

	for _, c := range conditions {
		cond, ok := c.(map[string]interface{})
		if !ok {
			continue
		}

		if cond[keyType] == condType {
			return cond
		}
	}

	return nil
}
