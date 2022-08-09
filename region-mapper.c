#include "region-mapper.h"
#include <asm/page_types.h>
#include <linux/blk_types.h>
#include <linux/blkdev.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

struct dev_id {
    struct list_head list;
    char* name;
    int major;
    int minor;
};
LIST_HEAD(all_devices);

struct mapping_table {
    unsigned int entry_count;
    // indicate whether the target chunk in use
    // bitmap line start from less significant bit to most significant bit
    unsigned int* bitmap;
    // dynamic allocating page to hold mapping entries,
    // maybe a memory page size (4KB) or partial.
    // each entry is a 32 bit integer, something like:
    // |----------+----------+----------+-----------------|
    // | exp_rw:2 | cur_rw:2 | in_use:1 |target region:28 |
    // |----------+----------+----------+-----------------|
    unsigned int* mapping_page;
};

struct dev_region_mapper {
    struct dev_id* dev;
    sector_t start;  // device start sector
    sector_t len;    // device length in sectors
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

static int __init region_mapper_init(void) {
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
    unsigned** mapping_entry = pde_data(file_inode(filp));
    unsigned rw_flags =
        ((**mapping_entry) >> CURRENT_RDWR_SHIFT) & REGION_TYPE_MASK;
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
    unsigned int** mapping_entry = pde_data(file_inode(filp));
    char in[3];
    unsigned int rw_flags = 0;
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

struct list_head get_all_devices(void) {
    return all_devices;
}
EXPORT_SYMBOL(get_all_devices);

struct mapping_table* alloc_mapping_table(sector_t sectors) {
    struct mapping_table* tbl =
        kmalloc(sizeof(struct mapping_table), GFP_KERNEL);

    if (!tbl) {
        pr_err("region_mapper: failed to allocate mapping table\n");
        return NULL;
    }

    tbl->entry_count = (sectors << SECTOR_SHIFT) >> CHUNK_SHIFT;
    tbl->mapping_page = vmalloc(tbl->entry_count << sizeof(unsigned int));
    tbl->bitmap = kzalloc(tbl->entry_count >> sizeof(unsigned int), GFP_KERNEL);
    // reserve the first target chunk for unmapped read io
    tbl->bitmap[0] = 0x1;

    return tbl;
}
EXPORT_SYMBOL(alloc_mapping_table);

void free_mapping_table(struct mapping_table* tbl) {
    kfree(tbl->bitmap);
    vfree(tbl->mapping_page);
    kfree(tbl);
}
EXPORT_SYMBOL(free_mapping_table);

struct dev_region_mapper* dev_create_region_mapper(char* name,
                                                   dev_t dev,
                                                   sector_t start,
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
    mapper->mapping_tbl = tbl;
    list_add(&dev_id->list, &all_devices);
    mapper->start = start;
    mapper->len = sectors;

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

void dev_destroy_region_mapper(struct dev_region_mapper* mapper) {
    struct dev_id* dev_id = mapper->dev;
    struct mapping_table* tbl = mapper->mapping_tbl;
    char proc_dev[16];
    int i;
    sprintf(proc_dev, "%d:%d", dev_id->major, dev_id->minor);
    list_del(&dev_id->list);
    kfree(dev_id);
    for (i = 0; i < tbl->entry_count; i++) {
        char proc_chk[16];
        sprintf(proc_chk, "%d", i);
        remove_proc_entry(proc_chk, proc_region_mapper);
    }
    remove_proc_entry(proc_dev, proc_region_mapper);
    free_mapping_table(tbl);
    kfree(mapper);
}
EXPORT_SYMBOL(dev_destroy_region_mapper);

unsigned int get_mapping_entry(struct mapping_table* tbl, sector_t sectors) {
    int logical_chunk = SECTOR_TO_CHUNK(sectors);

    if (logical_chunk >= tbl->entry_count) {
        pr_err("region_mapper: logical chunk '%d' out of range\n",
               logical_chunk);
        return 0;
    }

    if (!MAPPING_ENTRY_IN_USE(tbl->mapping_page[logical_chunk])) {
        pr_err("region_mapper: invalid mapping entry\n");
        return 0;
    }
    return tbl->mapping_page[logical_chunk];
}
EXPORT_SYMBOL(get_mapping_entry);

int alloc_new_mapping_entry(struct mapping_table* tbl) {
    int i, j;

    // quickly find out not fully allocated bitmap line
    for (i = 0; i < tbl->entry_count; i++) {
        if (tbl->bitmap[i] != 0xFFFFFFFF) {
            break;
        }
    }

    // find out the exact not allocated bit in the bitmap line
    for (j = 0; j < sizeof(unsigned int) * 8; j++) {
        if (!(tbl->bitmap[i] & (1 << j))) {
            tbl->bitmap[i] |= (1 << j);
            return i * sizeof(unsigned int) * 8 + j;
        }
    }
    return -1;
}
EXPORT_SYMBOL(alloc_new_mapping_entry);

/* BIO map functions */

void bio_region_map(struct dev_region_mapper* mapper, struct bio* bio) {
    unsigned int expect_type;
    unsigned int current_type;
    struct mapping_table* tbl = mapper->mapping_tbl;
    sector_t sectors = bio->bi_iter->bi_sector - mapper->start;
    unsigned int entry = get_mapping_entry(tbl, sectors);

    if (entry) {
        expect_type = EXPECT_RDWR_TYPE(entry);
        current_type = CURRENT_TYPE(entry);
        pr_info("region_mapper: expect type %d, current type %d\n", expect_type,
                current_type);
        if (expect_type == current_type) {
            __bio_region_map(mapper, bio, entry);
            return;
        }
    }

    if (bio_data_dir(bio) == READ) {
        if (!entry) {
            __bio_region_map(mapper, bio, entry);
            return;
        }
        bio_read_region_map(mapper, bio);
    } else {
        bio_write_region_map(mapper, bio);
    }
}
EXPORT_SYMBOL(bio_region_map);

inline void __bio_region_map(struct dev_region_mapper* mapper,
                             struct bio* bio,
                             unsigned int entry) {
    bio->bi_iter->bi_sector = TARGET_CHUNK(entry) * CHUNK_SIZE + mapper->start;
}

void bio_read_region_map(struct dev_region_mapper* mapper, struct bio* bio, unsigned int entry) {

}

void bio_write_region_map(struct dev_region_mapper* mapper, struct bio* bio) {

}

