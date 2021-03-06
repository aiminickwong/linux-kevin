/*
 * Copyright (C) 2014, Linaro Ltd.
 *	Author: Tomasz Nowicki <tomasz.nowicki@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef ARM_GIC_ACPI_H_
#define ARM_GIC_ACPI_H_

#ifdef CONFIG_ACPI

/*
 * Hard code here, we can not get memory size from MADT (but FDT does),
 * Actually no need to do that, because this size can be inferred
 * from GIC spec.
 */
#define ACPI_GICV2_DIST_MEM_SIZE	(SZ_4K)
#define ACPI_GICV3_DIST_MEM_SIZE	(SZ_64K)
#define ACPI_GIC_CPU_IF_MEM_SIZE	(SZ_8K)

struct acpi_table_header;

void acpi_gic_init(void);
int gic_v2_acpi_init(struct acpi_table_header *table);
int gic_v3_acpi_init(struct acpi_table_header *table);
#else
static inline void acpi_gic_init(void) { }
#endif

#endif /* ARM_GIC_ACPI_H_ */
