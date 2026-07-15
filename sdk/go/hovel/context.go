package hovel

import (
	"fmt"
	"reflect"
	"strings"
)

// Logger emits structured log records back to the daemon as "module/log"
// notifications. Records appear in the throw transcript alongside the host's own
// logs. The variadic args are key/value pairs, like log/slog:
//
//	ctx.Log.Info("connected", "host", host, "port", port)
type Logger struct {
	name string
	emit func(record logRecord)
}

func (l *Logger) log(level, message string, args ...any) {
	if l == nil || l.emit == nil {
		return
	}
	l.emit(logRecord{
		Level:   level,
		Message: message,
		Logger:  l.name,
		Fields:  fieldsFromArgs(args),
	})
}

// Debug, Info, Warn, and Error emit a record at the named level. Extra args are
// key/value pairs added as structured fields.
func (l *Logger) Debug(message string, args ...any) { l.log("debug", message, args...) }
func (l *Logger) Info(message string, args ...any)  { l.log("info", message, args...) }
func (l *Logger) Warn(message string, args ...any)  { l.log("warning", message, args...) }
func (l *Logger) Error(message string, args ...any) { l.log("error", message, args...) }

func fieldsFromArgs(args []any) map[string]any {
	if len(args) == 0 {
		return nil
	}
	fields := make(map[string]any, len(args)/2)
	for i := 0; i+1 < len(args); i += 2 {
		key := fmt.Sprint(args[i])
		fields[key] = sanitizeLogField(args[i+1])
	}
	return fields
}

type logFieldVisit struct {
	typeOf reflect.Type
	kind   reflect.Kind
	ptr    uintptr
}

type logFieldSanitizer struct {
	visiting map[logFieldVisit]struct{}
}

func sanitizeLogField(value any) any {
	sanitized, _ := (&logFieldSanitizer{
		visiting: make(map[logFieldVisit]struct{}),
	}).sanitize(reflect.ValueOf(value))
	return sanitized
}

func (s *logFieldSanitizer) sanitize(value reflect.Value) (any, bool) {
	if !value.IsValid() {
		return nil, false
	}
	if isNilLogFieldValue(value) {
		return nil, false
	}
	if value.CanInterface() {
		if marker, secret := credentialLogRedaction(value.Interface()); secret {
			return marker, true
		}
	}

	switch value.Kind() {
	case reflect.Interface:
		return s.sanitize(value.Elem())
	case reflect.Pointer:
		if !s.enter(value) {
			return "<recursive value redacted>", true
		}
		defer s.leave(value)
		sanitized, changed := s.sanitize(value.Elem())
		if changed {
			return sanitized, true
		}
	case reflect.Map:
		return s.sanitizeMap(value)
	case reflect.Slice, reflect.Array:
		return s.sanitizeSequence(value)
	case reflect.Struct:
		return s.sanitizeStruct(value)
	}
	if value.CanInterface() {
		return value.Interface(), false
	}
	return nil, false
}

func credentialLogRedaction(value any) (string, bool) {
	switch value.(type) {
	case CredentialBytes, *CredentialBytes:
		return redactedCredentialBytes, true
	case CredentialSecretReference, *CredentialSecretReference,
		CredentialProtectedPath, *CredentialProtectedPath,
		CredentialMaterialValue, *CredentialMaterialValue,
		ResolvedCredentialMaterial, *ResolvedCredentialMaterial,
		CredentialArtifactContent, *CredentialArtifactContent:
		return redactedCredentialSecret, true
	default:
		return "", false
	}
}

func isNilLogFieldValue(value reflect.Value) bool {
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (s *logFieldSanitizer) sanitizeMap(value reflect.Value) (any, bool) {
	if !s.enter(value) {
		return "<recursive value redacted>", true
	}
	defer s.leave(value)

	type entry struct {
		key       string
		value     any
		changed   bool
		keyChange bool
	}
	entries := make([]entry, 0, value.Len())
	changed := false
	iterator := value.MapRange()
	for iterator.Next() {
		keyValue, keyChanged := s.sanitize(iterator.Key())
		fieldValue, fieldChanged := s.sanitize(iterator.Value())
		entries = append(entries, entry{
			key:       fmt.Sprint(keyValue),
			value:     fieldValue,
			changed:   fieldChanged,
			keyChange: keyChanged,
		})
		changed = changed || fieldChanged || keyChanged
	}
	if !changed && value.CanInterface() {
		return value.Interface(), false
	}
	result := make(map[string]any, len(entries))
	for _, item := range entries {
		result[item.key] = item.value
	}
	return result, true
}

func (s *logFieldSanitizer) sanitizeSequence(value reflect.Value) (any, bool) {
	if value.Kind() == reflect.Slice {
		if !s.enter(value) {
			return "<recursive value redacted>", true
		}
		defer s.leave(value)
	}
	result := make([]any, value.Len())
	changed := false
	for i := range value.Len() {
		var itemChanged bool
		result[i], itemChanged = s.sanitize(value.Index(i))
		changed = changed || itemChanged
	}
	if !changed && value.CanInterface() {
		return value.Interface(), false
	}
	return result, true
}

func (s *logFieldSanitizer) sanitizeStruct(value reflect.Value) (any, bool) {
	typeOf := value.Type()
	result := make(map[string]any, value.NumField())
	changed := false
	for i := range value.NumField() {
		field := typeOf.Field(i)
		if field.PkgPath != "" {
			continue
		}
		name, include := logFieldJSONName(field)
		if !include {
			continue
		}
		fieldValue, fieldChanged := s.sanitize(value.Field(i))
		result[name] = fieldValue
		changed = changed || fieldChanged
	}
	if !changed && value.CanInterface() {
		return value.Interface(), false
	}
	return result, true
}

func logFieldJSONName(field reflect.StructField) (string, bool) {
	tag := field.Tag.Get("json")
	name, _, _ := strings.Cut(tag, ",")
	if name == "-" {
		return "", false
	}
	if name == "" {
		name = field.Name
	}
	return name, true
}

func (s *logFieldSanitizer) enter(value reflect.Value) bool {
	visit := logFieldVisit{
		typeOf: value.Type(),
		kind:   value.Kind(),
		ptr:    uintptr(value.UnsafePointer()),
	}
	if _, exists := s.visiting[visit]; exists {
		return false
	}
	s.visiting[visit] = struct{}{}
	return true
}

func (s *logFieldSanitizer) leave(value reflect.Value) {
	delete(s.visiting, logFieldVisit{
		typeOf: value.Type(),
		kind:   value.Kind(),
		ptr:    uintptr(value.UnsafePointer()),
	})
}

// Context carries everything a module needs for one execution: the run and
// target identity, the resolved configuration, a [Logger], and access to
// sessions. It is created by the SDK and passed to [Module.Run].
type Context struct {
	RunID        string
	ModuleID     string
	Target       string
	Inputs       map[string]any
	ChainConfig  map[string]any
	TargetConfig map[string]any
	Agent        *AgentContext
	Log          *Logger

	sessions *sessionRegistry
}

// Input resolves a configuration value, preferring per-run inputs, then
// target-level config, then chain-level config, and finally the given default.
func (c *Context) Input(key string, def any) any {
	if value, ok := c.Inputs[key]; ok {
		return value
	}
	if value, ok := c.TargetConfig[key]; ok {
		return value
	}
	if value, ok := c.ChainConfig[key]; ok {
		return value
	}
	return def
}

// InputString is Input coerced to a string, falling back to def.
func (c *Context) InputString(key, def string) string {
	if value := c.Input(key, nil); value != nil {
		if s, ok := value.(string); ok {
			return s
		}
		return fmt.Sprint(value)
	}
	return def
}

// OpenSession registers an interactive session opened by the module. The session
// outlives Run: the daemon keeps the module process alive and drives the session
// on the operator's behalf. The returned [SessionRef] should be included in the
// module's [Result] (the SDK also attaches it automatically).
func (c *Context) OpenSession(session Session, opts ...SessionOption) (SessionRef, error) {
	if c.sessions == nil {
		return SessionRef{}, fmt.Errorf("hovel: session support is not available in this runtime")
	}
	return c.sessions.open(session, opts...)
}
