// Copyright 2015-2019 Bret Jordan, All rights reserved.
//
// Use of this source code is governed by an Apache 2.0 license that can be
// found in the LICENSE file in the root of the source tree.

/*
Package objects implements the STIX 2.1 object model.
*/
package objects

import (
	"encoding/json"
	"fmt"

	"github.com/freetaxii/libstix2/objects/attackpattern"
	"github.com/freetaxii/libstix2/objects/baseobject"
	"github.com/freetaxii/libstix2/objects/campaign"
	"github.com/freetaxii/libstix2/objects/courseofaction"
	"github.com/freetaxii/libstix2/objects/identity"
	"github.com/freetaxii/libstix2/objects/indicator"
	"github.com/freetaxii/libstix2/objects/infrastructure"
	"github.com/freetaxii/libstix2/objects/intrusionset"
	"github.com/freetaxii/libstix2/objects/malware"
	"github.com/freetaxii/libstix2/objects/observeddata"
	"github.com/freetaxii/libstix2/objects/properties"
	"github.com/freetaxii/libstix2/objects/relationship"
	"github.com/freetaxii/libstix2/objects/report"
	"github.com/freetaxii/libstix2/objects/sighting"
	"github.com/freetaxii/libstix2/objects/threatactor"
	"github.com/freetaxii/libstix2/objects/tool"
	"github.com/freetaxii/libstix2/objects/vulnerability"
)

/*
STIXObject - This interface defines what methods an object must have to be
considered a STIX Object.
*/
type STIXObject interface {
	GetObjectType() string
	GetID() string
	GetModified() string
	GetCommonProperties() *baseobject.CommonObjectProperties
}

/*
ValidType - This function will take in a STIX Object Type and return true if
the string represents an actual STIX object type. This is used for determining
if input from an outside source is actually a defined STIX object or not.
*/
func ValidType(t string) bool {

	var m = map[string]int{
		"attack-pattern":     1,
		"campaign":           1,
		"course-of-action":   1,
		"identity":           1,
		"indicator":          1,
		"intrusion-set":      1,
		"location":           1,
		"malware":            1,
		"marking-definition": 1,
		"note":               1,
		"observed-data":      1,
		"opinion":            1,
		"relationship":       1,
		"report":             1,
		"sighting":           1,
		"threat-actor":       1,
		"tool":               1,
		"vulnerability":      1,
	}

	if _, ok := m[t]; ok {
		return true
	}
	return false
}

/*
DecodeType - This function will take in a slice of bytes representing a
random STIX object encoded as JSON and return the STIX object type as a string.
*/
func DecodeType(data []byte) (string, error) {
	var o properties.TypeProperty
	err := json.Unmarshal(data, &o)
	if err != nil {
		return "", err
	}

	if valid, err := o.Valid(); valid != true {
		return "", fmt.Errorf("invalid STIX object: %s", err)
	}

	return o.ObjectType, nil
}

/*
Decode - This function will take in a slice of bytes representing a
random STIX object encoded as JSON, decode it to the appropriate STIX object
struct, and return the object itself as an interface and any possible errors.
*/
func Decode(data []byte) (STIXObject, error) {
	var err error
	// TODO this probably does not belong here, since it down references objects
	// which is bad form.  This probably needs to be in a different part of the
	// library or just in the application code.

	// Make a first pass to decode just the object type value. Once we have this
	// value we can easily make a second pass and decode the rest of the object.
	stixtype, err := DecodeType(data)
	if err != nil {
		return nil, err
	}

	switch stixtype {
	case "attack-pattern":
		return attackpattern.Decode(data)
	case "campaign":
		return campaign.Decode(data)
	case "course-of-action":
		return courseofaction.Decode(data)
	case "identity":
		return identity.Decode(data)
	case "indicator":
		return indicator.Decode(data)
	case "infrastructure":
		return infrastructure.Decode(data)
	case "intrusion-set":
		return intrusionset.Decode(data)
	case "malware":
		return malware.Decode(data)
	case "observed-data":
		return observeddata.Decode(data)
	case "relationship":
		return relationship.Decode(data)
	case "report":
		return report.Decode(data)
	case "sighting":
		return sighting.Decode(data)
	case "threat-actor":
		return threatactor.Decode(data)
	case "tool":
		return tool.Decode(data)
	case "vulnerability":
		return vulnerability.Decode(data)
	default:
		return baseobject.Decode(data)
	}
	return nil, nil
}
