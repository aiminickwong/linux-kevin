/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * This file contains NUMA specific prototypes and definitions.
 *
 * Author: Zhen Lei <thunder.leizhen@huawei.com>
 *
 */
#ifndef _OF_NUMA_H
#define _OF_NUMA_H

#ifdef CONFIG_OF_NUMA
#include <asm/mmzone.h>

extern cpumask_t node_to_cpumask_map[MAX_NUMNODES];
extern int __node_distance(int, int);
#define node_distance(a, b)		__node_distance(a, b)
#define numa_clear_node(cpu)		numa_set_node(cpu, NUMA_NO_NODE)

extern int early_cpu_to_node(int cpu);
extern void of_numa_init(void);
extern void numa_init(void);
#endif /* CONFIG_OF_NUMA */

#endif /* _OF_NUMA_H */
