package hovel

import "fmt"

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
		fields[key] = args[i+1]
	}
	return fields
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
