/*
 * test_pass — minimal inner payload for alloc_jump testing.
 *
 * Writes "PASS" to stdout and exits 0. Uses raw Linux syscalls so it
 * can run as an inner payload under any runner (the runner process is
 * always a Linux binary executing under QEMU).
 */

#include "picblobs/os/linux.h"
#include "picblobs/reloc.h"
#include "picblobs/section.h"
#include "picblobs/sys/exit_group.h"
#include "picblobs/sys/write.h"

PIC_RODATA
static const char msg[] = "PASS";

PIC_ENTRY
void _start(void)
{
	PIC_SELF_RELOCATE();
	pic_write(1, msg, 4);
	pic_exit_group(0);
}
