// Copyright 2015-2020 Bret Jordan, All rights reserved.
//
// Use of this source code is governed by an Apache 2.0 license that can be
// found in the LICENSE file in the root of the source tree.

package campaign

import (
	"github.com/freetaxii/libstix2/objects"
	"github.com/freetaxii/libstix2/objects/properties"
)

// ----------------------------------------------------------------------
// Define Object Type
// ----------------------------------------------------------------------

/* Campaign - This type implements the STIX 2 Campaign SDO and defines all of
the properties and methods needed to create and work with this object. All of
the methods not defined local to this type are inherited from the individual
properties. */
type Campaign struct {
	objects.CommonObjectProperties
	properties.NameProperty
	properties.DescriptionProperty
	properties.AliasesProperty
	properties.SeenProperties
	Objective string `json:"objective,omitempty"`
}

// ----------------------------------------------------------------------
// Initialization Functions
// ----------------------------------------------------------------------

/* New - This function will create a new STIX Campaign object and return it as a
pointer. It will also initialize the object by setting all of the basic
properties. */
func New() *Campaign {
	var obj Campaign
	obj.InitSDO("campaign")
	return &obj
}
