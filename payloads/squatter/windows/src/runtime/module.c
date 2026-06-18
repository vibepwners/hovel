#include "runtime/module.h"

/* Module names are ASCII registry keys; the incoming name is UTF-8 from the
 * wire. A plain byte compare (not lstrcmpA) keeps this off the ANSI WinAPI: a
 * name with non-ASCII bytes simply matches no registered module. */
static int name_equal(const char *a, const char *b)
{
        int i = 0;

        for (i = 0; a[i] != '\0' && b[i] != '\0'; i++)
        {
                if (a[i] != b[i])
                {
                        return 0;
                }
        }
        return a[i] == b[i];
}

sq_module_fn sq_module_lookup(const sq_module_table *table, const char *name)
{
        int i = 0;

        if (table == NULL || name == NULL)
        {
                return NULL;
        }
        for (i = 0; i < table->count; i++)
        {
                if (table->modules[i].name != NULL && name_equal(table->modules[i].name, name))
                {
                        return table->modules[i].fn;
                }
        }
        return NULL;
}
