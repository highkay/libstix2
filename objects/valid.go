// Copyright 2015-2020 Bret Jordan, All rights reserved.
//
// Use of this source code is governed by an Apache 2.0 license that can be
// found in the LICENSE file in the root of the source tree.

package objects

// ----------------------------------------------------------------------
// Public Methods
// ----------------------------------------------------------------------

/*
ValidSDO - This method will verify and test all of the properties on a STIX
Domain Object to make sure they are valid per the specification. It will return
a boolean, an integer that tracks the number of problems found, and a slice of
strings that contain the detailed results, whether good or bad.
*/
func (o *CommonObjectProperties) ValidSDO() (bool, int, []string) {
	problemsFound := 0
	resultDetails := make([]string, 0)

	// Verify object Type property is present
	_, pType, dType := o.TypeProperty.VerifyExists()
	problemsFound += pType
	resultDetails = append(resultDetails, dType...)

	// Verify Spec Version property is present
	_, pSpecVersion, dSpecVersion := o.SpecVersionProperty.VerifyExists()
	problemsFound += pSpecVersion
	resultDetails = append(resultDetails, dSpecVersion...)

	// Verify object ID property is present
	_, pID, dID := o.IDProperty.VerifyExists()
	problemsFound += pID
	resultDetails = append(resultDetails, dID...)

	// Verify object Created property is present
	_, pCreated, dCreated := o.CreatedProperty.VerifyExists()
	problemsFound += pCreated
	resultDetails = append(resultDetails, dCreated...)

	// Verify object Created property is present
	_, pModified, dModified := o.ModifiedProperty.VerifyExists()
	problemsFound += pModified
	resultDetails = append(resultDetails, dModified...)

	if problemsFound > 0 {
		return false, problemsFound, resultDetails
	}

	return true, 0, resultDetails
}

/*
ValidSTIXObjectType - This function will take in a STIX Object Type and return
true if the string represents an actual STIX object type. This is used for
determining if input from an outside source is actually a defined STIX object or
not.
*/
func ValidSTIXObjectType(t string) bool {
	valid := false

	switch t {
	case "attack-pattern":
		valid = true
	case "campaign":
		valid = true
	case "course-of-action":
		valid = true
	case "identity":
		valid = true
	case "indicator":
		valid = true
	case "intrusion-set":
		valid = true
	case "location":
		valid = true
	case "malware":
		valid = true
	case "marking-definition":
		valid = true
	case "note":
		valid = true
	case "observed-data":
		valid = true
	case "opinion":
		valid = true
	case "relationship":
		valid = true
	case "report":
		valid = true
	case "sighting":
		valid = true
	case "threat-actor":
		valid = true
	case "tool":
		valid = true
	case "vulnerability":
		valid = true
	}
	return valid
}
