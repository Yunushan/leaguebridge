package releaseassessment

import (
	"errors"

	"github.com/Yunushan/leaguebridge/internal/readiness"
)

// These are the six external rows in the reviewed production composition.
// They are checked against the authenticated released scorecard, not against
// a caller-supplied report or the build's current embedded scorecard.
var productionCriteria = []struct {
	category string
	item     readiness.Subcriterion
}{
	{"architecture-contracts", readiness.Subcriterion{ID: "architecture-upstream-authorization", Name: "Authorized upstream extension contract", Weight: 2, EvidenceType: readiness.VendorAuthorization, VerifierID: "riot-linux-bsd-authorization-v1"}},
	{"implementation", readiness.Subcriterion{ID: "implementation-native-validated-integration", Name: "Native validated platform integration", Weight: 3, EvidenceType: readiness.NativeRuntimeV2, VerifierID: "native-integration-v2"}},
	{"tests-ci", readiness.Subcriterion{ID: "tests-native-bsd-physical-smoke", Name: "Native BSD and physical-hardware smoke tests", Weight: 5, EvidenceType: readiness.NativeRuntimeV2, VerifierID: "native-bsd-physical-smoke-v2"}},
	{"security-supply-chain", readiness.Subcriterion{ID: "security-independent-audit-closed", Name: "Closed independent audit findings", Weight: 2, EvidenceType: readiness.IndependentAuditV1, VerifierID: "independent-audit-v1"}},
	{"packaging-operations", readiness.Subcriterion{ID: "packaging-native-os-packages", Name: "Native OS packages", Weight: 3, EvidenceType: readiness.PackageAttestation, VerifierID: "native-packages-v1"}},
	{"packaging-operations", readiness.Subcriterion{ID: "packaging-install-uninstall-native-smoke", Name: "Install/uninstall and native smoke evidence", Weight: 2, EvidenceType: readiness.NativeRuntimeV2, VerifierID: "install-native-smoke-v2"}},
}

func checkProductionContract(card readiness.Scorecard) error {
	for _, expected := range productionCriteria {
		count := 0
		for _, category := range card.Engineering {
			for _, item := range category.Subcriteria {
				if item.ID != expected.item.ID {
					continue
				}
				count++
				if category.ID != expected.category || item.Name != expected.item.Name ||
					item.Weight != expected.item.Weight || item.EvidenceType != expected.item.EvidenceType ||
					item.VerifierID != expected.item.VerifierID || len(item.Evidence) != 0 {
					return errors.New("released scorecard does not match the reviewed production criterion contract")
				}
			}
		}
		if count != 1 {
			return errors.New("released scorecard lacks a unique reviewed production criterion")
		}
	}
	return nil
}
