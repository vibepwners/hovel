package main

import (
	"testing"

	"github.com/Vibe-Pwners/hovel/sdk/go/hovel"
)

func TestMockSurveyInfo(t *testing.T) {
	info := MockSurvey{}.Info()
	if info.Name != "mock-survey-go" || info.Type != hovel.TypeSurvey {
		t.Fatalf("info = %#v", info)
	}
}

func TestMockSurveySchema(t *testing.T) {
	schema := MockSurvey{}.Schema()
	if len(schema.TargetConfig) != 2 {
		t.Fatalf("targetConfig = %#v", schema.TargetConfig)
	}
	if schema.TargetConfig[0].Key != "target.host" {
		t.Fatalf("first requirement = %#v", schema.TargetConfig[0])
	}
}
