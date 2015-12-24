/*
 * fdt NUMA support
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Copyright (C) 2015 Hisilicon Limited
 *
 * Author: Zhen Lei <thunder.leizhen@huawei.com>
 *
 */

#define pr_fmt(fmt) "of_numa: " fmt

#include <linux/bootmem.h>
#include <linux/memblock.h>
#include <linux/percpu.h>
#include <linux/of_fdt.h>
#include <linux/of.h>

#include <asm/sections.h>
#include <asm/numa.h>

#define NR_MEMBLKS			(MAX_NUMNODES * 4)

struct numa_meminfo {
	u64	base;
	u64	size;
	int	nid;
};

struct numa_cpuinfo {
	u64	hwid;
	phandle phandle;
	int	nid;
};

struct numa_info {
	int nr_blks;
	int nr_cpus;
	struct numa_meminfo meminfo[NR_MEMBLKS];
	struct numa_cpuinfo cpuinfo[NR_CPUS];
	phandle node_phandle[MAX_NUMNODES];
};

static int next_nid __initdata;
static struct numa_info numa_info;
static int nodes_distance[MAX_NUMNODES][MAX_NUMNODES];

cpumask_t node_to_cpumask_map[MAX_NUMNODES];
EXPORT_SYMBOL(node_to_cpumask_map);

struct pglist_data *node_data[MAX_NUMNODES];
EXPORT_SYMBOL(node_data);

static void __init check_cpu_duplicate(struct numa_cpuinfo *new)
{
	int i;

	for (i = 0; i < (numa_info.nr_cpus - 1); i++)
		WARN_ON(numa_info.cpuinfo[i].phandle == new->phandle);
}

static int __init is_override(struct numa_meminfo *a, struct numa_meminfo *b)
{
	if ((b->base >= a->base) && (b->base < a->base + a->size))
		return 1;

	if ((b->base <= a->base) && (b->base + b->size > a->base))
		return 1;

	return 0;
}

static void __init check_mem_override(struct numa_meminfo *new)
{
	int i;

	for (i = 0; i < (numa_info.nr_blks - 1); i++)
		WARN_ON(is_override(&numa_info.meminfo[i], new));
}

static void __init check_mem_coverage(void)
{
	unsigned long start_pfn, end_pfn;
	int i, nid;

	for_each_mem_pfn_range(i, MAX_NUMNODES, &start_pfn, &end_pfn, &nid)
		if (nid == MAX_NUMNODES)
			pr_warn("mem %llx-%llx is not belong to any node\n",
				(u64)start_pfn << PAGE_SHIFT,
				((u64)end_pfn << PAGE_SHIFT) - 1);
}

static phandle __init early_get_phandle(unsigned long node)
{
	const __be32 *reg;

	reg = of_get_flat_dt_prop(node, "phandle", NULL);
	if (reg == NULL)
		reg = of_get_flat_dt_prop(node, "linux,phandle", NULL);
	if (!reg)
		return 0;

	return be32_to_cpup(reg);
}

static int phandle_to_nid(phandle phandle)
{
	int nid;

	for (nid = 0; nid < MAX_NUMNODES; nid++)
		if (numa_info.node_phandle[nid] == phandle)
			return nid;

	return MAX_NUMNODES;
}

static int __init early_init_dt_numa_node(unsigned long node)
{
	const __be32 *prop, *endp;
	int nid, len, nr_blk = 0;

	if (next_nid >= MAX_NUMNODES) {
		pr_err("too many numa nodes\n");
		return 0;
	}

	nid = next_nid++;
	numa_info.node_phandle[nid] = early_get_phandle(node);

	prop = of_get_flat_dt_prop(node, "mem-ranges", &len);
	endp = prop ? prop + (len / sizeof(__be32)) : prop;

	while ((endp - prop) >= (dt_root_addr_cells + dt_root_size_cells)) {
		u64 base, size;
		struct numa_meminfo *meminfo;

		if (numa_info.nr_blks >= NR_MEMBLKS) {
			pr_err("too many memblk ranges\n");
			break;
		}

		base = dt_mem_next_cell(dt_root_addr_cells, &prop);
		size = dt_mem_next_cell(dt_root_size_cells, &prop);

		if (base >= base + size)
			continue;

		meminfo = &numa_info.meminfo[numa_info.nr_blks++];
		meminfo->base = base;
		meminfo->size = size;
		meminfo->nid  = nid;
		nr_blk++;

		check_mem_override(meminfo);
	}

	if (!nr_blk)
		pr_warn("found a permanent memoryless node\n");

	/* a memory node may have no cpu */
	prop = of_get_flat_dt_prop(node, "cpus-list", &len);
	if (!prop)
		return 0;

	endp = prop + (len / sizeof(__be32));
	while (prop < endp) {
		struct numa_cpuinfo *cpuinfo;

		if (numa_info.nr_cpus >= NR_CPUS) {
			pr_err("too many cpus\n");
			break;
		}

		cpuinfo = &numa_info.cpuinfo[numa_info.nr_cpus++];
		cpuinfo->phandle = be32_to_cpup(prop++);
		cpuinfo->nid = nid;

		check_cpu_duplicate(cpuinfo);
	}

	return 0;
}

static int __init early_init_dt_numa_distance(unsigned long node)
{
	const __be32 *prop, *endp;
	int i, j, len;

	prop = of_get_flat_dt_prop(node, "distance-list", &len);
	if (!prop)
		goto set_default_distance;

	endp = prop + (len / sizeof(__be32));
	while ((endp - prop) >= 3) {
		int a, b, distance;

		a = be32_to_cpup(prop++);
		b = be32_to_cpup(prop++);
		distance = be32_to_cpup(prop++);

		a = phandle_to_nid(a);
		b = phandle_to_nid(b);
		BUG_ON((a == MAX_NUMNODES) || (b == MAX_NUMNODES));
		WARN_ON(distance < LOCAL_DISTANCE);

		nodes_distance[a][b] = distance;
	}

set_default_distance:
	for (i = 0; i < MAX_NUMNODES; i++)
		for (j = 0; j < MAX_NUMNODES; j++)
			if (i == j)
				nodes_distance[i][j] = LOCAL_DISTANCE;
			else if (!nodes_distance[i][j])
				nodes_distance[i][j] = nodes_distance[j][i] ? : REMOTE_DISTANCE;

	return 0;
}

static u64 __init alloc_node_data_from_nearest_node(int nid, const size_t size)
{
	int i, best_nid, distance;
	u64 pa;
	DECLARE_BITMAP(nodes_map, MAX_NUMNODES);

	bitmap_zero(nodes_map, MAX_NUMNODES);
	bitmap_set(nodes_map, nid, 1);

find_nearest_node:
	best_nid = NUMA_NO_NODE;
	distance = INT_MAX;

	for_each_clear_bit(i, nodes_map, MAX_NUMNODES)
		if (nodes_distance[nid][i] < distance) {
			best_nid = i;
			distance = nodes_distance[nid][i];
		}

	pa = memblock_alloc_nid(size, PAGE_SIZE, best_nid);
	if (!pa) {
		BUG_ON(best_nid == NUMA_NO_NODE);
		bitmap_set(nodes_map, best_nid, 1);
		goto find_nearest_node;
	}

	return pa;
}

static void __init alloc_node_data(int nid)
{
	const size_t size = roundup(sizeof(pg_data_t), PAGE_SIZE);
	u64 pa;

	/* Allocate node data from local node memory. */
	pa = memblock_alloc_nid(size, PAGE_SIZE, nid);
	if (!pa)
		pa = alloc_node_data_from_nearest_node(nid, size);
	NODE_DATA(nid) = __va(pa);

	memset(NODE_DATA(nid), 0, sizeof(pg_data_t));

	node_set_online(nid);
}

static void __init numa_register_memblks(void)
{
	int i;
	struct numa_meminfo *meminfo;

	if (!numa_info.nr_blks) {
		meminfo = &numa_info.meminfo[numa_info.nr_blks++];
		meminfo->base = 0;
		meminfo->size = -1;
		meminfo->nid  = 0;

		next_nid = 1;
		nodes_distance[0][0] = LOCAL_DISTANCE;
	}

	for (i = 0; i < numa_info.nr_blks; i++) {
		meminfo = &numa_info.meminfo[i];
		memblock_set_node(meminfo->base, meminfo->size,
					&memblock.memory, meminfo->nid);
	}

	/* memoryless nodes maybe exist */
	for (i = 0; i < next_nid; i++)
		alloc_node_data(i);

	check_mem_coverage();
}

static int __init early_init_dt_scan_numa_info(unsigned long node,
						const char *uname,
						int depth, void *data)
{
	static int found;
	static unsigned long distance_node;

	if (!found && (depth == 1) && !strcmp(uname, "numa-nodes-info")) {
		found = 1;
		return 0;
	} else if (!found) {
		return 0;
	} else if (found && depth < 2) {
		/*
		 * scanning of /numa-nodes-info has been finished.
		 */
		early_init_dt_numa_distance(distance_node);

		return 1;
	}

	if (!strcmp(uname, "nodes-distance")) {
		/*
		 * Here just simply mark the offset of node "nodes-distance".
		 * We should wait all brother nodes scanning finished. So
		 * that, all phandle,nid relationship had been built.
		 */
		distance_node = node;

		return 0;
	}

	return early_init_dt_numa_node(node);
}

static void __init early_numa_set_hwid(phandle phandle, u64 hwid)
{
	int i;
	struct numa_cpuinfo *cpuinfo = numa_info.cpuinfo;

	for (i = 0; i < numa_info.nr_cpus; i++, cpuinfo++)
		if (phandle == cpuinfo->phandle) {
			cpuinfo->hwid = hwid;
			return;
		}
}

static int __init early_init_dt_scan_cpu_info(unsigned long node,
					const char *uname,
					int depth, void *data)
{
	const char *type = of_get_flat_dt_prop(node, "device_type", NULL);
	const __be32 *reg;
	int len;
	u64 hwid;

	if ((type == NULL) || (strcmp(type, "cpu") != 0))
		return 0;

	reg = of_get_flat_dt_prop(node, "reg", &len);
	if (reg == NULL)
		return 0;
	hwid = of_read_number(reg, (len / sizeof(__be32)));

	if (!numa_info.nr_blks) {
		struct numa_cpuinfo *cpuinfo;

		if (numa_info.nr_cpus >= NR_CPUS) {
			pr_err("too many cpus\n");
			return 0;
		}

		cpuinfo = &numa_info.cpuinfo[numa_info.nr_cpus++];
		cpuinfo->hwid = hwid;
		cpuinfo->nid = 0;

		return 0;
	}

	early_numa_set_hwid(early_get_phandle(node), hwid);

	return 0;
}

int __init early_cpu_to_node(int cpu)
{
	int i;
	struct numa_cpuinfo *cpuinfo = numa_info.cpuinfo;

	for (i = 0; i < numa_info.nr_cpus; i++, cpuinfo++)
		if (cpuinfo->hwid == arch_cpu_to_hwid(cpu))
			return cpuinfo->nid;

	return NUMA_NO_NODE;
}

void __init of_numa_init(void)
{
	of_scan_flat_dt(early_init_dt_scan_numa_info, NULL);
	if (!numa_info.nr_blks)
		numa_info.nr_cpus = 0;
	of_scan_flat_dt(early_init_dt_scan_cpu_info, NULL);
	numa_register_memblks();
}

void __weak __init numa_init(void)
{
	unsigned int cpu;
	int rr_next_nid = first_online_node;

	for_each_possible_cpu(cpu) {
		int nid;

		nid = early_cpu_to_node(cpu);
		if (nid == NUMA_NO_NODE) {
			nid = rr_next_nid;
			pr_warn("set missed cpu%d to node%d\n", cpu, nid);

			rr_next_nid = next_online_node(rr_next_nid);
			if (rr_next_nid == MAX_NUMNODES)
				rr_next_nid = first_online_node;
		}
		cpumask_set_cpu(cpu, &node_to_cpumask_map[nid]);
		set_cpu_numa_node(cpu, nid);
	}
}

unsigned long __per_cpu_offset[NR_CPUS] __read_mostly;
EXPORT_SYMBOL(__per_cpu_offset);

static int __init pcpu_cpu_distance(unsigned int from, unsigned int to)
{
#ifdef CONFIG_NEED_MULTIPLE_NODES
	if (early_cpu_to_node(from) == early_cpu_to_node(to))
		return LOCAL_DISTANCE;
	else
		return REMOTE_DISTANCE;
#else
	return LOCAL_DISTANCE;
#endif
}

static void * __init pcpu_fc_alloc(unsigned int cpu, size_t size,
				       size_t align)
{
	int nid = early_cpu_to_node(cpu);

	return  memblock_virt_alloc_try_nid(size, align,
			__pa(MAX_DMA_ADDRESS), MEMBLOCK_ALLOC_ACCESSIBLE, nid);
}

static void __init pcpu_fc_free(void *ptr, size_t size)
{
	memblock_free_early(__pa(ptr), size);
}

void __init setup_per_cpu_areas(void)
{
	unsigned long delta;
	unsigned int cpu;
	int rc;

	/*
	 * Always reserve area for module percpu variables.  That's
	 * what the legacy allocator did.
	 */
	rc = pcpu_embed_first_chunk(PERCPU_MODULE_RESERVE,
				    PERCPU_DYNAMIC_RESERVE, PAGE_SIZE,
				    pcpu_cpu_distance,
				    pcpu_fc_alloc, pcpu_fc_free);
	if (rc < 0)
		panic("Failed to initialize percpu areas.");

	delta = (unsigned long)pcpu_base_addr - (unsigned long)__per_cpu_start;
	for_each_possible_cpu(cpu)
		__per_cpu_offset[cpu] = delta + pcpu_unit_offsets[cpu];
}

int __node_distance(int a, int b)
{
	if ((a >= MAX_NUMNODES) || (b >= MAX_NUMNODES))
		return a == b ? LOCAL_DISTANCE : REMOTE_DISTANCE;

	return nodes_distance[a][b];
}
EXPORT_SYMBOL(__node_distance);

int of_node_to_nid(struct device_node *device)
{
	int nid = -1;

	of_node_get(device);
	while (device) {
		struct device_node *child;
		struct device_node *numa_dev;

		numa_dev = of_parse_phandle(device, "numa-node", 0);
		if (numa_dev) {
			nid = phandle_to_nid(numa_dev->phandle);
			if (nid != MAX_NUMNODES)
				break;
		}

		child = device;
		device = of_get_parent(child);
		of_node_put(child);
	}
	of_node_put(device);

	return nid;
}
EXPORT_SYMBOL_GPL(of_node_to_nid);

#ifdef CONFIG_MEMORY_HOTPLUG
int memory_add_physaddr_to_nid(u64 start)
{
	int i;

	for (i = 0; i < numa_info.nr_blks; i++) {
		struct numa_meminfo *mi = &numa_info.meminfo[i];

		if ((mi->base <= start) && (mi->base + mi->size > start))
			return mi->nid;
	}

	return first_online_node;
}
EXPORT_SYMBOL_GPL(memory_add_physaddr_to_nid);
#endif
