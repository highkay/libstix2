// Copyright 2015-2020 Bret Jordan, All rights reserved.

//

// Use of this source code is governed by an Apache 2.0 license that can be

// found in the LICENSE file in the root of the source tree.

package objects

import (
	"reflect"
	"testing"
)

func TestDecode(t *testing.T) {
	type args struct {
		data []byte
	}
	tests := []struct {
		name    string
		args    []byte
		want    string
		wantErr bool
	}{
		{
			"反序列化",
			[]byte("{\"type\":\"threat-actor\",\"spec_version\":\"2.1\",\"id\":\"threat-actor--56f3f0db-b5d5-431c-ae56-c18f02caf500\",\"created\":\"2016-08-08T15:50:10.983Z\",\"modified\":\"2016-08-08T15:50:10.983Z\",\"name\":\"Fake BPP (Branistan Peoples Party)\",\"threat_actor_types\":[\"nation-state\"],\"roles\":[\"director\"],\"goals\":[\"Influence the election in Branistan\"],\"sophistication\":\"strategic\",\"resource_level\":\"government\",\"primary_motivation\":\"ideology\",\"secondary_motivations\":[\"dominance\"]}"),
			"threat-actor--56f3f0db-b5d5-431c-ae56-c18f02caf500",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decode(tt.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("Decode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got.GetID, tt.want) {
				t.Errorf("Decode() = %v, want %v", got.GetID(), tt.want)
			}
		})
	}
}
