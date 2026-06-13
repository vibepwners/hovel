/* module.h -- the module contract.
 *
 * A module is the easiest thing in this system to write: a single function that
 * is handed a connected named-pipe HANDLE plus an argc/argv, and does whatever
 * it likes with the pipe. The runtime takes care of multiplexing that pipe onto
 * one stream of a shared connection; the module neither knows nor cares.
 *
 * The pipe is a Windows MESSAGE-MODE pipe: every WriteFile is delivered to the
 * other side as one whole message, and every ReadFile returns exactly one whole
 * message. That is what lets a module speak in discrete messages without doing
 * any framing of its own.
 *
 * The module does NOT own `pipe`; it must not close it. Returning from the
 * function ends the stream (the runtime closes the pipe and emits a CLOSE).
 */
#ifndef SQ_MUX_MODULE_H
#define SQ_MUX_MODULE_H

#include "base/win.h"

#ifdef __cplusplus
extern "C" {
#endif

/* argv[0] is the module name; argv[argc] is NULL. Return value is the module's
 * exit status (logged; 0 = success). */
typedef int (*sq_module_fn)(HANDLE pipe, int argc, wchar_t **argv);

typedef struct sq_module {
    const char *name;
    sq_module_fn fn;
} sq_module;

typedef struct sq_module_table {
    const sq_module *modules;
    int count;
} sq_module_table;

/* Return the function registered under `name`, or NULL if none. */
sq_module_fn sq_module_lookup(const sq_module_table *table, const char *name);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SQ_MUX_MODULE_H */
