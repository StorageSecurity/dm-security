#include "region-mapper.h"
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>

struct device_identifier {
    struct list_head list;
    char* name;
    int major;
    int minor;
};
LIST_HEAD(all_devices);

struct mapping_table {
    struct list_head list;
    // number of mapping entries in this mapping page
    int entry_count;
    // dynamic allocating page to hold mapping entries,
    // maybe a memory page size (4KB) or partial.
    // each entry is a 32 bit integer, something like:
    // |----------+----------+------------------|
    // | rd_hot:1 | wr_hot:1 | target region:30 |
    // |----------+----------+------------------|
    int* page;
};

static int __init region_mapper_init(void);
static void __exit region_mapper_exit(void);

module_init(region_mapper_init);
module_exit(region_mapper_exit);

MODULE_AUTHOR("Peihong Chen");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Region mapper");
MODULE_VERSION("0.1");

static init __init region_mapper_init(void) {
    pr_info("region_mapper_init\n");
    return 0;
}

static void __exit region_mapper_exit(void) {
    pr_info("region_mapper: exit\n");
}

/* Export Symbols*/

static struct list_head get_all_devices(void) {
    return all_devices;
}
EXPORT_SYMBOL(get_all_devices);
