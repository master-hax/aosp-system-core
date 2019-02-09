// Copyright (C) 2019 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package json2pb

import (
	// "strings"

	"github.com/google/blueprint"
	"github.com/google/blueprint/proptools"

	"android/soong/android"
)

var (
	pctx = android.NewPackageContext("android/soong/json2pb")

	json2pbRule = pctx.AndroidStaticRule("json2pb", blueprint.RuleParams{
		Command:     `echo ${json2pbCmd} ${inSchema} ${in} ${out}`,
		CommandDeps:  []string{"${json2pbCmd}"},
		Description: "json2pb ${inSchema} ${in}",
	}, "inSchema")
)

type PrebuiltEtcJsonProperties struct {
	// Optional Protobuf schema
	Schema *string
}

type PrebuiltEtcJsonRule struct {
	android.PrebuiltEtc

	properties PrebuiltEtcJsonProperties
}

func init() {
	pctx.HostBinToolVariable("json2pbCmd", "json2pb")
	android.RegisterModuleType("prebuilt_etc_json", prebuiltEtcJsonFactory)
}

func prebuiltEtcJsonFactory() android.Module {
	g := &PrebuiltEtcJsonRule{}
	g.AddProperties(&g.properties)
	android.InitPrebuiltEtcModule(&g.PrebuiltEtc)
	// This module is device-only
	android.InitAndroidArchModule(g, android.DeviceSupported, android.MultilibCommon)
	return g
}

func (g *PrebuiltEtcJsonRule) DepsMutator(ctx android.BottomUpMutatorContext) {
	g.PrebuiltEtc.DepsMutator(ctx)

	// To support ":modulename" in schema
	android.ExtractSourceDeps(ctx, g.properties.Schema)
}

func (g *PrebuiltEtcJsonRule) GenerateAndroidBuildActions(ctx android.ModuleContext) {

	g.PrebuiltEtc.GenerateAndroidBuildActions(ctx)

	gen_message := android.PathForModuleGen(ctx, "protobuf_message")

	if g.properties.Schema != nil {
		schema := ctx.ExpandSource(proptools.String(g.properties.Schema), "schema")

		ctx.Build(pctx, android.BuildParams{
			Rule:        json2pbRule,
			Description: "json2pb",
			Input:       g.PrebuiltEtc.SourceFilePath(ctx),
			Output:      gen_message,
			Implicit:    schema,
			Args: map[string]string{
				"inSchema": schema.String(),
			},
		})
		g.SetAdditionalDependencies([]android.Path{gen_message})
	}
}
