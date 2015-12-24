#ifndef _ASM_ARM64_MMZONE_H
#define _ASM_ARM64_MMZONE_H

#include <linux/numa.h>

extern struct pglist_data *node_data[];
#define NODE_DATA(nid)		(node_data[nid])

#endif /* _ASM_ARM64_MMZONE_H */
