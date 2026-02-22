package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValidCenterType(t *testing.T) {
	tests := []struct {
		name    string
		center  string
		subType string
		want    bool
	}{
		// Valid combinations
		{"CBER/EBLA", "CBER", "EBLA", true},
		{"CDER/ECTD", "CDER", "ECTD", true},
		{"CDRH/GUDID", "CDRH", "GUDID", true},
		{"HFP/NDI", "HFP", "NDI", true},
		{"CTP/Adverse Events", "CTP", "Adverse Events", true},
		{"CVM/eSubmitter", "CVM", "eSubmitter", true},
		{"OC/SPL", "OC", "SPL", true},
		{"OII/Document_Requests", "OII", "Document_Requests", true},
		{"OOPD/HUD_Designation_Requests", "OOPD", "HUD_Designation_Requests", true},
		{"OPQ/7044a4_Pharma_Inspection_Records", "OPQ", "7044a4_Pharma_Inspection_Records", true},
		{"Health Canada/Transaction", "Health Canada", "Transaction", true},

		// Shared types
		{"CBER/AERS (shared with CDER)", "CBER", "AERS", true},
		{"CDER/AERS (shared with CBER)", "CDER", "AERS", true},
		{"CBER/EIND (shared with CDER)", "CBER", "EIND", true},
		{"CDER/EIND (shared with CBER)", "CDER", "EIND", true},
		{"CDRH/Adverse Events (shared with CTP)", "CDRH", "Adverse Events", true},
		{"CTP/Adverse Events (shared with CDRH)", "CTP", "Adverse Events", true},
		{"OII/POR Small Molecule Documents (shared with OPQ)", "OII", "POR Small Molecule Documents", true},
		{"OPQ/POR Small Molecule Documents (shared with OII)", "OPQ", "POR Small Molecule Documents", true},

		// Invalid combinations
		{"CBER type in CDER", "CDER", "EBLA", false},
		{"CDER type in CBER", "CBER", "ECTD", false},
		{"HFP type in CBER", "CBER", "NDI", false},
		{"unknown center", "GWTEST", "EBLA", false},
		{"unknown type", "CBER", "NONEXISTENT", false},
		{"empty center", "", "EBLA", false},
		{"empty type", "CBER", "", false},
		{"both empty", "", "", false},

		// CFSAN should NOT work (we use HFP)
		{"CFSAN is not a valid center", "CFSAN", "NDI", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidCenterType(tt.center, tt.subType)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestIsValidCenter(t *testing.T) {
	validCenters := []string{
		"CBER", "CDER", "CDRH", "HFP", "CTP",
		"CVM", "OC", "OII", "OOPD", "OPQ", "Health Canada",
	}
	for _, c := range validCenters {
		t.Run(c+" is valid", func(t *testing.T) {
			assert.True(t, IsValidCenter(c))
		})
	}

	invalidCenters := []string{"CFSAN", "GWTEST", "", "cber", "FDA"}
	for _, c := range invalidCenters {
		t.Run(c+" is invalid", func(t *testing.T) {
			assert.False(t, IsValidCenter(c))
		})
	}
}

func TestAllCentersHaveTypes(t *testing.T) {
	for center, types := range ValidCenterTypes {
		assert.NotEmpty(t, types, "center %q has no submission types", center)
	}
}

func TestValidCenterTypesCount(t *testing.T) {
	// Sanity check: we expect 11 centers per the FDA Center Submission Types table.
	assert.Equal(t, 11, len(ValidCenterTypes), "expected 11 FDA centers")
}
