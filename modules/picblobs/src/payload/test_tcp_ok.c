/*
 * test_tcp_ok — inner payload for stager_tcp testing.
 *
 * Writes "TCP_OK" to stdout and exits 0.
 */

#include "picblobs/os/linux.h"
#include "picblobs/reloc.h"
#include "picblobs/section.h"
#include "picblobs/sys/exit_group.h"
#include "picblobs/sys/write.h"

PIC_RODATA
static const char msg[] = "TCP_OK";

PIC_ENTRY
void _start(void)
{
	PIC_SELF_RELOCATE();
	pic_write(1, msg, 6);
	pic_exit_group(0);
}
