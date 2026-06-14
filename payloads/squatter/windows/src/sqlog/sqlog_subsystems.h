/* sqlog_subsystems.h -- the subsystem registry, as an X-macro table.
 *
 * This is the ONE place to add a logging subsystem. Add a row to the table and
 * everything else -- the enum, the count, the name lookup, the per-subsystem
 * runtime level array -- regenerates from it. No parallel lists to keep in sync,
 * which is the entire point of the X-macro idiom.
 *
 *   Row:  X(ENUM_SUFFIX, "display name")
 *
 * The enumerator is SQLOG_SUB_<ENUM_SUFFIX>; the display name is what appears in
 * the formatted log line. Keep GENERAL first so it is the zero value (a sensible
 * default for code that has not picked a subsystem yet).
 *
 * To extend in your own project without editing this file, define
 * SQLOG_SUBSYSTEM_TABLE before including <sqlog/sqlog.h> and these defaults are
 * skipped.
 */
#ifndef SQLOG_SUBSYSTEMS_H
#define SQLOG_SUBSYSTEMS_H

#ifndef SQLOG_SUBSYSTEM_TABLE
#define SQLOG_SUBSYSTEM_TABLE(X)                                                                                       \
        X(GENERAL, "general")                                                                                          \
        X(NET, "net")                                                                                                  \
        X(IOCP, "iocp")                                                                                                \
        X(SERVER, "server")                                                                                            \
        X(HANDLER, "handler")                                                                                          \
        X(UI, "ui")                                                                                                    \
        X(MUX, "mux")                                                                                                  \
        X(TEST, "test")
#endif

#endif /* SQLOG_SUBSYSTEMS_H */
