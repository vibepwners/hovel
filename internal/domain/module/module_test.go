package module

import "testing"

func TestNewModuleIDRejectsEmpty(t *testing.T) {
	invalid := []string{"", " ", "   "}
	for _, value := range invalid {
		if _, err := NewModuleID(value); err == nil {
			t.Fatalf("NewModuleID(%q) returned nil error, want error", value)
		}
	}

	id, err := NewModuleID("abc-123")
	if err != nil {
		t.Fatalf("NewModuleID(%q) returned error: %v", "abc-123", err)
	}
	if id.String() != "abc-123" {
		t.Fatalf("NewModuleID(%q).String() = %q, want %q", "abc-123", id.String(), "abc-123")
	}
}

func TestNewModuleNameValidation(t *testing.T) {
	valid := []string{
		"hello-world",
		"ssh-survey-01",
		"survey",
		"a",
		"0abc",
		"abc123",
		"abc-def-ghi",
	}
	for _, value := range valid {
		name, err := NewModuleName(value)
		if err != nil {
			t.Fatalf("NewModuleName(%q) returned error: %v", value, err)
		}
		if name.String() != value {
			t.Fatalf("NewModuleName(%q).String() = %q, want %q", value, name.String(), value)
		}
	}

	invalid := []string{
		"",
		" ",
		"Hello",       // uppercase not allowed
		"UPPERCASE",   // uppercase not allowed
		"-leading",    // leading hyphen not allowed
		"has space",   // spaces not allowed
		"has_under",   // underscores not allowed
		"has.dot",     // dots not allowed
		"has/slash",   // slashes not allowed
		"trailinghyphen-", // trailing hyphen not allowed
	}
	for _, value := range invalid {
		if _, err := NewModuleName(value); err == nil {
			t.Fatalf("NewModuleName(%q) returned nil error, want error", value)
		}
	}
}

func TestNewModuleVersionRejectsEmpty(t *testing.T) {
	invalid := []string{"", " ", "   "}
	for _, value := range invalid {
		if _, err := NewModuleVersion(value); err == nil {
			t.Fatalf("NewModuleVersion(%q) returned nil error, want error", value)
		}
	}

	version, err := NewModuleVersion("1.0.0")
	if err != nil {
		t.Fatalf("NewModuleVersion(%q) returned error: %v", "1.0.0", err)
	}
	if version.String() != "1.0.0" {
		t.Fatalf("NewModuleVersion(%q).String() = %q, want %q", "1.0.0", version.String(), "1.0.0")
	}
}

func TestNewModuleTypeValidation(t *testing.T) {
	valid := []string{
		"survey",
		"transport",
		"access",
		"deliver",
		"payload",
		"post_action",
		"cleanup",
		"transform",
		"provider",
		"chain",
		"utility",
		"service_client",
	}
	for _, value := range valid {
		typ, err := NewModuleType(value)
		if err != nil {
			t.Fatalf("NewModuleType(%q) returned error: %v", value, err)
		}
		if typ.String() != value {
			t.Fatalf("NewModuleType(%q).String() = %q, want %q", value, typ.String(), value)
		}
	}

	invalid := []string{
		"",
		"unknown",
		"SURVEY",
		"Survey",
		"implant",
		"run",
	}
	for _, value := range invalid {
		if _, err := NewModuleType(value); err == nil {
			t.Fatalf("NewModuleType(%q) returned nil error, want error", value)
		}
	}
}

func TestNewDescriptorRequiresAllFields(t *testing.T) {
	validID, _ := NewModuleID("mod-001")
	validName, _ := NewModuleName("ssh-survey")
	validVersion, _ := NewModuleVersion("0.1.0")
	validType, _ := NewModuleType("survey")

	// all valid fields should succeed
	desc, err := New(validID, validName, validVersion, validType)
	if err != nil {
		t.Fatalf("New with valid fields returned error: %v", err)
	}
	if desc.ID != validID {
		t.Fatalf("desc.ID = %q, want %q", desc.ID, validID)
	}
	if desc.Name != validName {
		t.Fatalf("desc.Name = %q, want %q", desc.Name, validName)
	}
	if desc.Version != validVersion {
		t.Fatalf("desc.Version = %q, want %q", desc.Version, validVersion)
	}
	if desc.Type != validType {
		t.Fatalf("desc.Type = %q, want %q", desc.Type, validType)
	}

	// zero-value fields should fail
	if _, err := New(ModuleID(""), validName, validVersion, validType); err == nil {
		t.Fatal("New with empty ID returned nil error, want error")
	}
	if _, err := New(validID, ModuleName(""), validVersion, validType); err == nil {
		t.Fatal("New with empty Name returned nil error, want error")
	}
	if _, err := New(validID, validName, ModuleVersion(""), validType); err == nil {
		t.Fatal("New with empty Version returned nil error, want error")
	}
	if _, err := New(validID, validName, validVersion, ModuleType("")); err == nil {
		t.Fatal("New with empty Type returned nil error, want error")
	}
}
