/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 */
#ifndef _ASM_ARM64_NUMA_H
#define _ASM_ARM64_NUMA_H

#ifdef CONFIG_OF_NUMA
#include <linux/of_numa.h>

extern u64 arch_cpu_to_hwid(int cpu);
#else
#define of_numa_init()			do { } while (0)
#define numa_init()			do { } while (0)
#endif

#endif /* _ASM_ARM64_NUMA_H */
