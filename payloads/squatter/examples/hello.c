/* Smoke test for the cross toolchain: must compile to a PE and pull in a
 * Windows header so the builtin-include-dir probing is actually exercised. */
#include <windows.h>

#include <stdio.h>

int main(void)
{
    DWORD const tick = GetTickCount();
    (void)printf("hello from squatter; tick=%lu\n", (unsigned long)tick);
    return 0;
}
