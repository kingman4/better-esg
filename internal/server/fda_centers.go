package server

// ValidCenterTypes maps each FDA center code to its valid submission types.
// Source: FDA ESG NextGen Center Submission Types table (March 2025).
var ValidCenterTypes = map[string][]string{
	"CBER": {
		"510K", "AERS", "AERS Attachments", "AERS_PREMKT_CBER",
		"EBLA", "eDMF", "EIDE", "EIND", "EUA",
		"Lot_Release_Protocol", "NDA", "PMA", "Pre_IND",
		"Promotional_Materials", "QSUBS", "SEND_PILOT", "SPL_LDD", "VAERS",
	},
	"CDER": {
		"ACA6004_Drug_Samples", "AERS", "AERS Attachments", "AERS_PREMKT_CDER",
		"ECTD", "ECTD WAIVED", "EDMF_TYPEIII", "EIND", "FFU-PILOT",
		"GDUFA_Facility_Registration", "PFC",
		"POR Large Molecule Documents", "Voluntary_Direct_Aes",
	},
	"CDRH": {
		"Adverse Events", "Electronic_Submissions", "GUDID",
	},
	"HFP": {
		"DSR_Adverse_Events", "EON-Payload-Files", "Food_Pilot_Listing",
		"Form3479", "Form3480", "Form3480A", "Form3503",
		"Form3665", "Form3666", "Form3667",
		"NDI", "Threshold_of_Regulation",
	},
	"CTP": {
		"Adverse Events", "Electronic_Submission",
	},
	"CVM": {
		"Adverse_Events_Reports", "eSubmitter",
	},
	"OC": {
		"SPL", "OCAC",
	},
	"OII": {
		"Document_Requests", "POR Small Molecule Documents",
	},
	"OOPD": {
		"HUD_Designation_Requests", "Orphan_drug_Designation_Requests",
	},
	"OPQ": {
		"7044a4_Pharma_Inspection_Records", "POR Small Molecule Documents",
	},
	"Health Canada": {
		"Transaction",
	},
}

// validCenterTypeLookup is a set for O(1) lookup of "center|type" pairs.
var validCenterTypeLookup map[string]struct{}

func init() {
	validCenterTypeLookup = make(map[string]struct{})
	for center, types := range ValidCenterTypes {
		for _, t := range types {
			validCenterTypeLookup[center+"|"+t] = struct{}{}
		}
	}
}

// IsValidCenterType returns true if the center/type combination is recognized.
func IsValidCenterType(center, subType string) bool {
	_, ok := validCenterTypeLookup[center+"|"+subType]
	return ok
}

// IsValidCenter returns true if the center code is recognized.
func IsValidCenter(center string) bool {
	_, ok := ValidCenterTypes[center]
	return ok
}
