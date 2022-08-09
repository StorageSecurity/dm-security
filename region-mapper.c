#include "region-mapper.h"
#include <asm/page_types.h>
#include <linux/blkdev.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

struct dev_id {
    struct list_head list;
    char* name;
    int major;
    int minor;
};
LIST_HEAD(all_devices);

struct mapping_table {
    int entry_count;
    // indicate whether the mapping table entry in use
    int* bitmap;
    // dynamic allocating page to hold mapping entries,
    // maybe a memory page size (4KB) or partial.
    // each entry is a 32 bit integer, something like:
    // |----------+----------+------------------|
    // | exp_rw:2 | cur_rw:2 | target region:28 |
    // |----------+----------+------------------|
    int* mapping_page;
};

struct dev_region_mapper {
    struct dev_id* dev;
    struct mapping_table* mapping_tbl;
};

#define PROC_REGION_MAPPER_DIR ("region-mapper")
struct proc_dir_entry* proc_region_mapper;
static int region_mapper_open_proc(struct inode* inode, struct file* file);
static int region_mapper_release_proc(struct inode* inode, struct file* file);
static ssize_t region_mapper_read_proc(struct file* filp,
                                       char __user* buf,
                                       size_t count,
                                       loff_t* offset);
static ssize_t region_mapper_write_proc(struct file* filp,
                                        const char* buf,
                                        size_t count,
                                        loff_t* offset);
static struct proc_ops proc_fops = {
    .proc_open = region_mapper_open_proc,
    .proc_release = region_mapper_release_proc,
    .proc_read = region_mapper_read_proc,
    .proc_write = region_mapper_write_proc,
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
    proc_region_mapper = proc_mkdir(PROC_REGION_MAPPER_DIR, NULL);
    if (proc_region_mapper == NULL) {
        pr_err("proc_mkdir failed: %s\n", PROC_REGION_MAPPER_DIR);
        return -ENOMEM;
    }
    return 0;
}

static void __exit region_mapper_exit(void) {
    pr_info("region_mapper: exit\n");
    remove_proc_entry(PROC_REGION_MAPPER_DIR, NULL);
}

/* procfs*/

static int region_mapper_open_proc(struct inode* inode, struct file* file) {
    pr_info("region_mapper_open_proc\n");
    return 0;
}

static int region_mapper_release_proc(struct inode* inode, struct file* file) {
    pr_info("region_mapper_release_proc\n");
    return 0;
}

static ssize_t region_mapper_read_proc(struct file* filp,
                                       char __user* buf,
                                       size_t count,
                                       loff_t* offset) {
    ssize_t ret = 0;
    int** mapping_entry = pde_data(file_inode(filp));
    int rw_flags = ((**mapping_entry) >> CURRENT_RDWR_SHIFT) & REGION_TYPE_MASK;
    char out[3];
    pr_info("region_mapper_read_proc\n");

    if (*offset != 0) {
        *offset = 0;
        return ret;
    }
    ret = sprintf(out, "%d%d\n", REGION_READ_BIT(rw_flags),
                  REGION_WRITE_BIT(rw_flags));
    if (copy_to_user(buf, out, ret)) {
        pr_err("copy_to_user failed\n");
        return -EFAULT;
    }
    return ret;
}

static ssize_t region_mapper_write_proc(struct file* filp,
                                        const char* buf,
                                        size_t count,
                                        loff_t* offset) {
    int** mapping_entry = pde_data(file_inode(filp));
    char in[3];
    int rw_flags = 0;
    pr_info("region_mapper_write_proc\n");

    if (copy_from_user(in, buf, count)) {
        pr_err("copy_from_user failed\n");
        return -EFAULT;
    }
    if (count != 2) {
        pr_err("invalid input\n");
        return -EINVAL;
    }
    if (in[0] == '0' || in[0] == '1') {
        rw_flags |= REGION_READ_BIT(in[0] - '0');
    } else {
        pr_err("invalid input\n");
        return -EINVAL;
    }
    if (in[1] == '0' || in[1] == '1') {
        rw_flags |= REGION_WRITE_BIT(in[1] - '0');
    } else {
        pr_err("invalid input\n");
        return -EINVAL;
    }

    **mapping_entry = EXPECT_RDWR_CLEAR_THEN_SET(**mapping_entry, rw_flags);

    return count;
}

/* Export Symbols*/

static struct list_head get_all_devices(void) {
    return all_devices;
}
EXPORT_SYMBOL(get_all_devices);

static struct mapping_table* alloc_mapping_table(sector_t sectors) {
    struct mapping_table* tbl =
        kmalloc(sizeof(struct mapping_table), GFP_KERNEL);

    if (!tbl) {
        pr_err("region_mapper: failed to allocate mapping table\n");
        return NULL;
    }

    tbl->entry_count = (sectors << SECTOR_SHIFT) >> CHUNK_SHIFT;
    tbl->bitmap = kzalloc(tbl->entry_count >> sizeof(int), GFP_KERNEL);
    tbl->mapping_page = vmalloc(tbl->entry_count << sizeof(int));

    return tbl;
}
EXPORT_SYMBOL(alloc_mapping_table);

static void free_mapping_table(struct mapping_table* tbl) {
    kfree(tbl->bitmap);
    vfree(tbl->mapping_page);
    kfree(tbl);
}
EXPORT_SYMBOL(free_mapping_table);

static struct dev_region_mapper* dev_create_region_mapper(char* name,
                                                          dev_t dev,
                                                          sector_t sectors) {
    struct dev_id* dev_id = kmalloc(sizeof(struct dev_id), GFP_KERNEL);
    struct dev_region_mapper* mapper =
        kmalloc(sizeof(struct dev_region_mapper), GFP_KERNEL);
    struct mapping_table* tbl = alloc_mapping_table(sectors);
    struct proc_dir_entry* entry;
    int i;
    char proc_dev[16];
    char proc_chk[16];
    if (!dev_id || !mapper || !tbl) {
        pr_err("region_mapper: failed to allocate dev_id or mapper or tbl\n");
        goto err;
    }

    dev_id->name = name;
    dev_id->major = MAJOR(dev);
    dev_id->minor = MINOR(dev);
    mapper->dev = dev_id;
    mapper->mapping_table = tbl;
    list_add(&dev_id->list, &all_devices);

    sprintf(proc_dev, "%d:%d", MAJOR(dev), MINOR(dev));
    entry = proc_mkdir(proc_dev, proc_region_mapper);
    for (i = 0; i < tbl->entry_count; i++) {
        sprintf(proc_chk, "%d", i);
        proc_create_data(proc_dev, 0777, entry, &proc_fops,
                         &mapper->mapping_tbl[i]);
    }

    return mapper;

err:
    if (dev_id)
        kfree(dev_id);
    if (mapper)
        kfree(mapper);
    if (tbl)
        kfree(tbl);
    return NULL;
}
EXPORT_SYMBOL(dev_create_region_mapper);
