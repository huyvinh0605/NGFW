package dataplane

import (
	"github.com/kltngfw/ngfw/internal/connectivity"
	"github.com/kltngfw/ngfw/internal/domain"
)

func CompileM3Bundle(c domain.Config, options M2CompileOptions, plan InspectionPlan) (RulesetBundle, error) {
	m2, err := CompileM2Ruleset(c, options)
	if err != nil {
		return RulesetBundle{}, err
	}
	runtimeSchema, policy := splitRuntimeTable(m2)
	inspectionRules, err := RenderInspectionRules(plan, c)
	if err != nil {
		return RulesetBundle{}, err
	}
	return RulesetBundle{RuntimeSchema: runtimeSchema, InspectionSchema: InspectionSchemaScript(), PolicyTransaction: policy + "\n" + inspectionRules, ExpectedObjects: []string{"inet/ngfw", "inet/ngfw_runtime", "inet/ngfw_inspection"}}, nil
}

func CompileM3(c domain.Config, generation uint64, options M2CompileOptions) (connectivity.Program, InspectionPlan, RulesetBundle, error) {
	program, err := connectivity.CompileM3(c, generation)
	if err != nil {
		return connectivity.Program{}, InspectionPlan{}, RulesetBundle{}, err
	}
	plan, err := CompileInspectionPlan(c, program)
	if err != nil {
		return connectivity.Program{}, InspectionPlan{}, RulesetBundle{}, err
	}
	bundle, err := CompileM3Bundle(c, options, plan)
	return program, plan, bundle, err
}
