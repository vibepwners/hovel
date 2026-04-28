package service

import "testing"

func TestNewServiceIDRejectsEmpty(t *testing.T) {
	invalid := []string{"", " ", "   "}
	for _, value := range invalid {
		if _, err := NewServiceID(value); err == nil {
			t.Fatalf("NewServiceID(%q) returned nil error, want error", value)
		}
	}

	id, err := NewServiceID("svc-001")
	if err != nil {
		t.Fatalf("NewServiceID(%q) returned error: %v", "svc-001", err)
	}
	if id.String() != "svc-001" {
		t.Fatalf("NewServiceID(%q).String() = %q, want %q", "svc-001", id.String(), "svc-001")
	}
}

func TestNewServiceNameValidation(t *testing.T) {
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
		name, err := NewServiceName(value)
		if err != nil {
			t.Fatalf("NewServiceName(%q) returned error: %v", value, err)
		}
		if name.String() != value {
			t.Fatalf("NewServiceName(%q).String() = %q, want %q", value, name.String(), value)
		}
	}

	invalid := []string{
		"",
		" ",
		"Hello",             // uppercase not allowed
		"UPPERCASE",         // uppercase not allowed
		"-leading",          // leading hyphen not allowed
		"has space",         // spaces not allowed
		"has_under",         // underscores not allowed
		"has.dot",           // dots not allowed
		"has/slash",         // slashes not allowed
		"trailinghyphen-",   // trailing hyphen not allowed
	}
	for _, value := range invalid {
		if _, err := NewServiceName(value); err == nil {
			t.Fatalf("NewServiceName(%q) returned nil error, want error", value)
		}
	}
}

func TestNewServiceVersionRejectsEmpty(t *testing.T) {
	invalid := []string{"", " ", "   "}
	for _, value := range invalid {
		if _, err := NewServiceVersion(value); err == nil {
			t.Fatalf("NewServiceVersion(%q) returned nil error, want error", value)
		}
	}

	version, err := NewServiceVersion("1.0.0")
	if err != nil {
		t.Fatalf("NewServiceVersion(%q) returned error: %v", "1.0.0", err)
	}
	if version.String() != "1.0.0" {
		t.Fatalf("NewServiceVersion(%q).String() = %q, want %q", "1.0.0", version.String(), "1.0.0")
	}
}

func TestNewServiceTypeValidation(t *testing.T) {
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
		typ, err := NewServiceType(value)
		if err != nil {
			t.Fatalf("NewServiceType(%q) returned error: %v", value, err)
		}
		if typ.String() != value {
			t.Fatalf("NewServiceType(%q).String() = %q, want %q", value, typ.String(), value)
		}
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
		if _, err := NewServiceType(value); err == nil {
			t.Fatalf("NewServiceType(%q) returned nil error, want error", value)
		}
	}
}

func TestNewDescriptorRequiresAllFields(t *testing.T) {
	validID, _ := NewServiceID("svc-001")
	validName, _ := NewServiceName("picblob-provider")
	validVersion, _ := NewServiceVersion("0.1.0")
	validType, _ := NewServiceType("payload_provider")

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
	if _, err := New(ServiceID(""), validName, validVersion, validType); err == nil {
		t.Fatal("New with empty ID returned nil error, want error")
	}
	if _, err := New(validID, ServiceName(""), validVersion, validType); err == nil {
		t.Fatal("New with empty Name returned nil error, want error")
	}
	if _, err := New(validID, validName, ServiceVersion(""), validType); err == nil {
		t.Fatal("New with empty Version returned nil error, want error")
	}
	if _, err := New(validID, validName, validVersion, ServiceType("")); err == nil {
		t.Fatal("New with empty Type returned nil error, want error")
	}
}
