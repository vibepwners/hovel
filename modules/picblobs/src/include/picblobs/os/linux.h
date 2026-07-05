/* Target OS: Linux. Include before any picblobs syscall headers. */
#ifndef PICBLOBS_OS_LINUX_H
#define PICBLOBS_OS_LINUX_H
#if !defined(PICBLOBS_OS_FREEBSD) && !defined(PICBLOBS_OS_WINDOWS)
#define PICBLOBS_OS_LINUX 1
#define PICBLOBS_OS_NAME "linux"
#endif
#endif
