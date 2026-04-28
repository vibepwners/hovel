package service

import "testing"

func TestNewIDRejectsEmpty(t *testing.T) {
	for _, value := range []string{"", " ", "   "} {
		t.Run(value, func(t *testing.T) {
			if _, err := NewID(value); err == nil {
				t.Fatalf("NewID(%q) returned nil error, want error", value)
			}
		})
	}

	id, err := NewID("svc-001")
	if err != nil {
		t.Fatalf("NewID(%q) returned error: %v", "svc-001", err)
	}
	if id.String() != "svc-001" {
		t.Fatalf("NewID(%q).String() = %q, want %q", "svc-001", id.String(), "svc-001")
	}
}

func TestNewNameValidation(t *testing.T) {
	valid := []string{
		"hello-world",
		"listener-01",
		"payload-provider",
		"a",
		"0abc",
		"abc123",
		"abc-def-ghi",
	}
	for _, value := range valid {
		t.Run("valid/"+value, func(t *testing.T) {
			name, err := NewName(value)
			if err != nil {
				t.Fatalf("NewName(%q) returned error: %v", value, err)
			}
			if name.String() != value {
				t.Fatalf("NewName(%q).String() = %q, want %q", value, name.String(), value)
			}
		})
	}

	invalid := []string{
		"",
		" ",
		"Hello",
		"UPPERCASE",
		"-leading",
		"has space",
		"has_under",
		"has.dot",
		"has/slash",
		"trailinghyphen-",
	}
	for _, value := range invalid {
		t.Run("invalid/"+value, func(t *testing.T) {
			if _, err := NewName(value); err == nil {
				t.Fatalf("NewName(%q) returned nil error, want error", value)
			}
		})
	}
}

func TestNewVersionRejectsEmpty(t *testing.T) {
	for _, value := range []string{"", " ", "   "} {
		t.Run(value, func(t *testing.T) {
			if _, err := NewVersion(value); err == nil {
				t.Fatalf("NewVersion(%q) returned nil error, want error", value)
			}
		})
	}

	version, err := NewVersion("1.0.0")
	if err != nil {
		t.Fatalf("NewVersion(%q) returned error: %v", "1.0.0", err)
	}
	if version.String() != "1.0.0" {
		t.Fatalf("NewVersion(%q).String() = %q, want %q", "1.0.0", version.String(), "1.0.0")
	}
}

func TestNewTypeValidation(t *testing.T) {
	valid := []string{
		"payload_provider",
		"listener",
		"session_broker",
		"credential_broker",
		"artifact_server",
		"callback_listener",
		"inventory_sync",
		"generic",
	}
	for _, value := range valid {
		t.Run("valid/"+value, func(t *testing.T) {
			typ, err := NewType(value)
			if err != nil {
				t.Fatalf("NewType(%q) returned error: %v", value, err)
			}
			if typ.String() != value {
				t.Fatalf("NewType(%q).String() = %q, want %q", value, typ.String(), value)
			}
		})
	}

	invalid := []string{
		"",
		"unknown",
		"LISTENER",
		"Listener",
		"survey",
		"module",
	}
	for _, value := range invalid {
		t.Run("invalid/"+value, func(t *testing.T) {
			if _, err := NewType(value); err == nil {
				t.Fatalf("NewType(%q) returned nil error, want error", value)
			}
		})
	}
}

func TestNewDescriptorRequiresAllFields(t *testing.T) {
	validID, _ := NewID("svc-001")
	validName, _ := NewName("picblob-provider")
	validVersion, _ := NewVersion("0.1.0")
	validType, _ := NewType("payload_provider")

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

	if _, err := New(ID(""), validName, validVersion, validType); err == nil {
		t.Fatal("New with empty ID returned nil error, want error")
	}
	if _, err := New(validID, Name(""), validVersion, validType); err == nil {
		t.Fatal("New with empty Name returned nil error, want error")
	}
	if _, err := New(validID, validName, Version(""), validType); err == nil {
		t.Fatal("New with empty Version returned nil error, want error")
	}
	if _, err := New(validID, validName, validVersion, Type("")); err == nil {
		t.Fatal("New with empty Type returned nil error, want error")
	}
}
