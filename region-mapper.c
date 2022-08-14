#include "region-mapper.h"
#include <asm/page_types.h>
#include <linux/bio.h>
#include <linux/blk_types.h>
#include <linux/blkdev.h>
#include <linux/container_of.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm_types.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#define SYNC_POOL_SIZE 64
#define SYNC_BIO_POOL_SIZE 2

static struct bio_set sync_bio_set;
static mempool_t sync_page_pool;

struct dev_id {
    struct list_head list;
    const char* name;
    int major;
    int minor;
};
LIST_HEAD(all_devices);

struct mapping_table {
    unsigned int entry_count;
    // indicate whether the physical chunk in use
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

struct sync_table {
    struct list_head list;
    unsigned int logical_chunk;
    unsigned int original_physical_chunk;
    unsigned int target_physical_chunk;
    unsigned int remain;
    unsigned int* bitmap;
    void* private;
};
struct dev_sync_table {
    struct list_head list;
    struct list_head sync_table_head;
    struct dev_id* dev;
    void* private;
};
LIST_HEAD(all_dev_sync_tables);

#define PROC_REGION_MAPPER_DIR ("region-mapper")
struct proc_dir_entry* proc_region_mapper;
char etx_array[20] = "try_proc_array\n";
static int len = 1;
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
    int ret;
    pr_info("region_mapper_init\n");

    ret = mempool_init_page_pool(&sync_page_pool, SYNC_POOL_SIZE, 0);
    BUG_ON(ret);
    pr_info("sync pool size: %d pages\n", SYNC_POOL_SIZE);

    ret = bioset_init(&sync_bio_set, SYNC_BIO_POOL_SIZE, 0, 0);
    BUG_ON(ret);
    pr_info("sync bio pool size: %d pages\n", SYNC_BIO_POOL_SIZE);

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
    unsigned int* mapping_entry = pde_data(file_inode(filp));
    // unsigned int rw_flags =
    //     ((*mapping_entry) >> CURRENT_RDWR_SHIFT) & REGION_TYPE_MASK;
    char out[128];
    pr_info("region_mapper_read_proc, mapping entry: 0x%04x\n", *mapping_entry);

    if (len) {
        len = 0;
    } else {
        len = 1;
        return 0;
    }

    sprintf(out,
            "expect: 0x%04x, current: 0x%04x, in_use: %d, physical_chunk: %d\n",
            EXPECT_RDWR_TYPE(*mapping_entry), CURRENT_RDWR_TYPE(*mapping_entry),
            MAPPING_ENTRY_IN_USE_STATE(*mapping_entry),
            TARGET_CHUNK(*mapping_entry));
    pr_info("%s", out);

    if (copy_to_user(buf, out, strlen(out))) {
        pr_err("copy_to_user failed: %ld\n", count);
        return 0;
    }

    return count;
}

static ssize_t region_mapper_write_proc(struct file* filp,
                                        const char* buf,
                                        size_t count,
                                        loff_t* offset) {
    unsigned int* mapping_entry = pde_data(file_inode(filp));
    char in[3];
    unsigned int rw_flags = 0;
    unsigned int expect_type = EXPECT_RDWR_TYPE(*mapping_entry);
    unsigned int current_type = CURRENT_RDWR_TYPE(*mapping_entry);
    pr_info("region_mapper_write_proc, mapping entry: 0x%04x\n",
            *mapping_entry);

    if (expect_type != current_type) {
        pr_err(
            "chunk in sync, discard update: exp_type=0x%04x, cur_type=0x%04x\n",
            expect_type, current_type);
        return count;
    }

    if (copy_from_user(in, buf, count)) {
        pr_err("copy_from_user failed\n");
        return -EFAULT;
    }

    if (count < 2) {
        pr_err("invalid input\n");
        return -EINVAL;
    }

    if (in[0] == '0' || in[0] == '1') {
        rw_flags |= ((in[0] - '0') << 1);
    } else {
        pr_err("invalid input\n");
        return -EINVAL;
    }
    if (in[1] == '0' || in[1] == '1') {
        rw_flags |= (in[1] - '0');
    } else {
        pr_err("invalid input\n");
        return -EINVAL;
    }

    EXPECT_RDWR_CLEAR_THEN_SET(*mapping_entry, rw_flags);

    return count;
}

/* Export Symbols*/

struct list_head get_all_devices(void) {
    return all_devices;
}
EXPORT_SYMBOL(get_all_devices);

struct mapping_table* alloc_mapping_table(sector_t sectors) {
    struct mapping_table* tbl =
        kzalloc(sizeof(struct mapping_table), GFP_KERNEL);

    if (!tbl) {
        pr_err("region_mapper: failed to allocate mapping table\n");
        return NULL;
    }

    // MUST make sure that sectors aligned to CHUNK_SIZE_IN_SECTORS
    tbl->entry_count = (sectors >> CHUNK_SHIFT);

    tbl->mapping_page = vzalloc(tbl->entry_count * sizeof(unsigned int));
    if (!tbl->mapping_page) {
        pr_err("region_mapper: failed to allocate mapping page\n");
        goto bad;
    }

    tbl->bitmap = kzalloc(
        DIV_ROUND_UP(tbl->entry_count, (sizeof(unsigned int) * 8)), GFP_KERNEL);
    if (!tbl->bitmap) {
        pr_err("region_mapper: failed to allocate bitmap\n");
        goto bad;
    }

    // reserve the first target chunk for unmapped read io
    tbl->bitmap[0] = 0x1;

    return tbl;

bad:
    free_mapping_table(tbl);
    return NULL;
}
EXPORT_SYMBOL(alloc_mapping_table);

void free_mapping_table(struct mapping_table* tbl) {
    if (tbl && tbl->bitmap) {
        pr_info("tbl->bitmap: %p", tbl->bitmap);
        kfree_sensitive(tbl->bitmap);
    }

    if (tbl && tbl->mapping_page) {
        pr_info("tbl->mapping_page: %p", tbl->mapping_page);
        // vfree(tbl->mapping_page);
    }

    pr_info("tbl: %p", tbl);
    if (tbl) {
        kfree_sensitive(tbl);
    }
}
EXPORT_SYMBOL(free_mapping_table);

inline void free_physical_chunk(struct mapping_table* tbl, unsigned int pc) {
    unsigned int i = pc / (sizeof(unsigned int) * 8);
    unsigned int j = pc % (sizeof(unsigned int) * 8);
    BITMAP_CLEAR(tbl->bitmap[i], j);
}

struct dev_region_mapper* dev_create_region_mapper(const char* name,
                                                   dev_t dev,
                                                   sector_t meta_start,
                                                   sector_t meta_sectors,
                                                   sector_t data_start,
                                                   sector_t data_sectors) {
    struct dev_id* dev_id;
    struct dev_region_mapper* mapper;
    struct mapping_table* tbl;
    struct dev_sync_table* dev_sync_tbl;
    struct proc_dir_entry* entry;
    int i;
    char proc_dev[16];
    char proc_chk[16];

    dev_id = kmalloc(sizeof(struct dev_id), GFP_KERNEL);
    if (!dev_id) {
        pr_err("region_mapper: failed to allocate dev_id\n");
        goto err;
    }
    dev_id->name = name;
    dev_id->major = MAJOR(dev);
    dev_id->minor = MINOR(dev);
    INIT_LIST_HEAD(&dev_id->list);
    list_add(&dev_id->list, &all_devices);

    mapper = kmalloc(sizeof(struct dev_region_mapper), GFP_KERNEL);
    if (!mapper) {
        pr_err("region_mapper: failed to allocate region mapper\n");
        goto err;
    }
    mapper->dev = dev_id;

    tbl = alloc_mapping_table(data_sectors);
    if (!tbl) {
        pr_err("region_mapper: failed to allocate mapping table\n");
        goto err;
    }
    mapper->mapping_tbl = tbl;
    mapper->meta_start = meta_start;
    mapper->meta_sectors = meta_sectors;
    mapper->data_start = data_start;
    mapper->data_sectors = data_sectors;

    dev_sync_tbl = alloc_dev_sync_table(dev_id);
    if (!dev_sync_tbl) {
        pr_err("region_mapper: failed to allocate dev_sync_table\n");
        goto err;
    }
    dev_sync_tbl->private = mapper;
    mapper->dev_sync_tbl = dev_sync_tbl;

    sprintf(proc_dev, "%d:%d", MAJOR(dev), MINOR(dev));
    entry = proc_mkdir(proc_dev, proc_region_mapper);
    for (i = 0; i < tbl->entry_count; i++) {
        sprintf(proc_chk, "%d", i);
        proc_create_data(proc_chk, 0777, entry, &proc_fops,
                         &tbl->mapping_page[i]);
    }

    return mapper;

err:
    if (dev_sync_tbl)
        free_dev_sync_table(dev_sync_tbl);
    if (tbl)
        free_mapping_table(tbl);
    if (mapper)
        dev_destroy_region_mapper(mapper);
    if (dev_id)
        kfree(dev_id);
    return NULL;
}
EXPORT_SYMBOL(dev_create_region_mapper);

void dev_destroy_region_mapper(struct dev_region_mapper* mapper) {
    struct dev_id* dev_id = NULL;
    struct mapping_table* tbl = NULL;
    struct dev_sync_table* dev_sync_tbl = NULL;
    char proc_dev[16];

    if (!mapper)
        return;

    dev_id = mapper->dev;
    tbl = mapper->mapping_tbl;
    dev_sync_tbl = mapper->dev_sync_tbl;

    if (dev_id) {
        sprintf(proc_dev, "%d:%d", dev_id->major, dev_id->minor);
        remove_proc_subtree(proc_dev, proc_region_mapper);
        list_del(&dev_id->list);
        kfree(dev_id);
    }

    if (tbl) {
        free_mapping_table(tbl);
    }

    if (dev_sync_tbl) {
        free_dev_sync_table(dev_sync_tbl);
    }

    kfree_sensitive(mapper);
}
EXPORT_SYMBOL(dev_destroy_region_mapper);

unsigned int get_mapping_entry(struct mapping_table* tbl, sector_t sectors) {
    int logical_chunk = SECTOR_TO_CHUNK(sectors);

    pr_info("get mapping entry for: %llu", sectors);

    if (logical_chunk >= tbl->entry_count) {
        pr_err("region_mapper: logical chunk '%d' out of range\n",
               logical_chunk);
        return 0;
    }

    if (!MAPPING_ENTRY_IN_USE(tbl->mapping_page[logical_chunk])) {
        return 0;
    }
    return tbl->mapping_page[logical_chunk];
}
EXPORT_SYMBOL(get_mapping_entry);

unsigned int set_mapping_entry(struct mapping_table* tbl,
                               unsigned int lc,
                               unsigned int target_chunk) {
    if (lc >= tbl->entry_count) {
        pr_err("region_mapper: logical chunk '%d' out of range\n", lc);
        return 0;
    }
    tbl->mapping_page[lc] =
        TARGET_CHUNK_SET(tbl->mapping_page[lc], target_chunk);
    MAPPING_ENTRY_SET_IN_USE(tbl->mapping_page[lc]);
    
    return tbl->mapping_page[lc];
}
EXPORT_SYMBOL(set_mapping_entry);

unsigned int find_free_physical_chunk(struct mapping_table* tbl) {
    unsigned i, j;

    // quickly find out not fully allocated bitmap line
    for (i = 0; i < tbl->entry_count; i++) {
        if (tbl->bitmap[i] != 0xFFFFFFFF) {
            break;
        }
    }

    // find out the exact not allocated bit in the bitmap line
    for (j = 0; j < sizeof(unsigned int) * 8; j++) {
        if (!(tbl->bitmap[i] & (1 << j))) {
            BITMAP_SET(tbl->bitmap[i], j);
            return i * sizeof(unsigned int) * 8 + j;
        }
    }
    return -1;
}
EXPORT_SYMBOL(find_free_physical_chunk);

unsigned int alloc_free_physical_chunk(struct mapping_table* tbl,
                                       unsigned int lc) {
    unsigned int physical_chunk;
    unsigned int entry;

    physical_chunk = find_free_physical_chunk(tbl);
    if (physical_chunk == -1) {
        pr_err("region_mapper: no free physical chunk\n");
        return 0;
    }

    entry = set_mapping_entry(tbl, lc, physical_chunk);

    return entry;
}
EXPORT_SYMBOL(alloc_free_physical_chunk);

/* Internal definitions */

struct dev_sync_table* alloc_dev_sync_table(struct dev_id* dev) {
    struct dev_sync_table* dev_sync_tbl =
        kmalloc(sizeof(struct dev_sync_table), GFP_KERNEL);
    if (!dev_sync_tbl) {
        return NULL;
    }
    INIT_LIST_HEAD(&dev_sync_tbl->sync_table_head);

    dev_sync_tbl->dev = dev;
    INIT_LIST_HEAD(&dev_sync_tbl->list);
    list_add(&dev_sync_tbl->list, &all_dev_sync_tables);

    return dev_sync_tbl;
}

void free_dev_sync_table(struct dev_sync_table* dev_sync_tbl) {
    struct sync_table *tbl, *tmp;
    list_for_each_entry_safe(tbl, tmp, &dev_sync_tbl->sync_table_head, list) {
        list_del(&tbl->list);
        kfree_sensitive(tbl);
    }
    list_del(&dev_sync_tbl->list);
    kfree_sensitive(dev_sync_tbl);
}

struct sync_table* alloc_sync_table(unsigned int lc,
                                    unsigned int opc,
                                    unsigned int tpc) {
    struct sync_table* stbl = kmalloc(sizeof(struct sync_table), GFP_KERNEL);
    if (!stbl) {
        pr_err("error allocate sync table\n");
        goto err;
    }

    stbl->logical_chunk = lc;
    stbl->original_physical_chunk = opc;
    stbl->target_physical_chunk = tpc;
    stbl->remain = CHUNK_SIZE_IN_SECTORS;
    stbl->bitmap =
        kzalloc(CHUNK_SIZE_IN_SECTORS >> sizeof(unsigned int), GFP_KERNEL);
    if (!stbl->bitmap) {
        pr_err("error allocate sync table bitmap\n");
        goto err;
    }

    return stbl;

err:
    if (stbl->bitmap)
        kfree(stbl->bitmap);
    if (stbl)
        kfree(stbl);
    return NULL;
}

void free_sync_table(struct sync_table* stbl) {
    kfree(stbl->bitmap);
    kfree(stbl);
}

struct sync_table* get_sync_table(struct dev_sync_table* tbl, unsigned int lc) {
    struct sync_table* stbl;
    list_for_each_entry(stbl, &tbl->sync_table_head, list) {
        if (stbl->logical_chunk == lc) {
            return stbl;
        }
    }
    return NULL;
}

bool check_chunk_in_sync(struct dev_id* dev, unsigned int lc) {
    struct dev_sync_table* dev_stbl;
    struct sync_table* stbl;
    bool ret = false;
    list_for_each_entry(dev_stbl, &all_dev_sync_tables, list) {
        if (dev_stbl->dev == dev) {
            break;
        }
    }
    list_for_each_entry(stbl, &dev_stbl->sync_table_head, list) {
        if (stbl->logical_chunk == lc) {
            ret = true;
            break;
        }
    }
    return ret;
}

bool check_sectors_synced(struct sync_table* stbl,
                          sector_t start,
                          sector_t sectors) {
    unsigned int i = start / sizeof(int) * 8;
    unsigned int j = start % sizeof(int) * 8;

    if (sectors + j <= sizeof(int) * 8) {
        return ((stbl->bitmap[i] >> j) & ((1 << sectors) - 1)) ==
               ((1 << sectors) - 1);
    } else {
        if ((stbl->bitmap[i] >> j) != (1 << (sizeof(int) * 8 - j))) {
            return false;
        }
        sectors -= sizeof(int) * 8 - j;
    }

    while (sectors > 0) {
        i++;
        if (sectors >= sizeof(int) * 8) {
            if (~(stbl->bitmap[i])) {
                return false;
            }
            sectors -= sizeof(int) * 8;
        } else {
            return (stbl->bitmap[i] & ((1 << sectors) - 1)) ==
                   ((1 << sectors) - 1);
        }
    }

    return true;
}
/* BIO map functions */

struct sync_io* bio_region_map(struct dev_region_mapper* mapper,
                               struct bio* bio) {
    unsigned int expect_type;
    unsigned int current_type;
    struct mapping_table* tbl = mapper->mapping_tbl;
    sector_t start = bio->bi_iter.bi_sector;
    unsigned int entry = get_mapping_entry(tbl, start);

    pr_info("bio_region_map entry:  %u\n", entry);

    if (!entry) {
        pr_info("region_mapper: no entry found\n");
        if (bio_data_dir(bio) == WRITE) {
            pr_info("region_mapper: alloc free physical chunk for WRITE bio\n");
            entry = alloc_free_physical_chunk(tbl, SECTOR_TO_CHUNK(start));
            if (!entry) {
                pr_err("region_mapper: no free physical chunk\n");
                return NULL;
            }
            pr_info(
                "region_mapper: alloc free physical chunk for WRITE bio "
                "done\n");
        } else {
            return __bio_region_map(mapper, bio, entry);
        }
    }

    if (entry) {
        expect_type = EXPECT_RDWR_TYPE(entry);
        current_type = CURRENT_RDWR_TYPE(entry);
        pr_info("region_mapper: expect type %d, current type %d\n", expect_type,
                current_type);
        if (expect_type == current_type) {
            return __bio_region_map(mapper, bio, entry);
        }
    }

    return bio_region_map_sync(mapper, bio, entry);
}
EXPORT_SYMBOL(bio_region_map);

inline struct sync_io* __bio_region_map(struct dev_region_mapper* mapper,
                                        struct bio* bio,
                                        unsigned int entry) {
    int logical_chunk = SECTOR_TO_CHUNK(bio->bi_iter.bi_sector);
    sector_t offset =
        bio->bi_iter.bi_sector - logical_chunk * CHUNK_SIZE_IN_SECTORS;
    bio->bi_iter.bi_sector = TARGET_CHUNK(entry) * CHUNK_SIZE_IN_SECTORS +
                             offset + mapper->data_start;
    return NULL;
}

struct sync_io* bio_region_map_sync(struct dev_region_mapper* mapper,
                                    struct bio* bio,
                                    unsigned int entry) {
    int logical_chunk = SECTOR_TO_CHUNK(bio->bi_iter.bi_sector);
    struct sync_table* stbl;
    unsigned int original_physical_chunk;
    unsigned int target_physical_chunk;
    struct sync_io* sync_io = NULL;

    if (!check_chunk_in_sync(mapper->dev, logical_chunk)) {
        unsigned int new_entry =
            alloc_free_physical_chunk(mapper->mapping_tbl, logical_chunk);
        if (!new_entry) {
            pr_err("region_mapper: failed to alloc free physical chunk\n");
            return NULL;
        }
        original_physical_chunk = TARGET_CHUNK(entry);
        target_physical_chunk = TARGET_CHUNK(new_entry);
        stbl = alloc_sync_table(logical_chunk, original_physical_chunk,
                                target_physical_chunk);
        if (!stbl) {
            pr_err("error allocate sync table\n");
            return NULL;
        }
        stbl->private = mapper->dev_sync_tbl;
        INIT_LIST_HEAD(&stbl->list);
        list_add(&stbl->list, &mapper->dev_sync_tbl->sync_table_head);
    } else {
        stbl = get_sync_table(mapper->dev_sync_tbl, logical_chunk);
        original_physical_chunk = stbl->original_physical_chunk;
        target_physical_chunk = stbl->target_physical_chunk;
    }

    if (!check_sectors_synced(stbl, bio->bi_iter.bi_sector, bio_sectors(bio))) {
        unsigned int target_entry;
        sync_io = kmalloc(sizeof(struct sync_io), GFP_KERNEL);
        if (!sync_io) {
            pr_err("error allocate sync_io\n");
            return NULL;
        }
        sync_io->base_io = spawn_sync_bio(stbl, bio, GFP_NOWAIT);
        if (!sync_io->base_io) {
            pr_err("error spawn sync bio\n");
            return NULL;
        }

        target_entry = TARGET_CHUNK_SET(entry, target_physical_chunk);
        __bio_region_map(mapper, sync_io->base_io, target_entry);
    }

    __bio_region_map(mapper, bio, entry);
    return sync_io;
}

struct bio* spawn_sync_bio(struct sync_table* stbl,
                           struct bio* bio,
                           gfp_t gfp_mask) {
    struct bio* sync_bio;
    struct bvec_iter iter;
    struct bio_vec bv;
    int i;
    struct bio_vec* to;

    if (bio_data_dir(bio) == READ) {
        sync_bio = bio_alloc_bioset(GFP_NOIO, bio_segments(bio), &sync_bio_set);
    } else {
        sync_bio = bio_clone_fast(bio, gfp_mask, &sync_bio_set);
    }

    if (!sync_bio) {
        pr_err("error allocate sync bio\n");
        return NULL;
    }

    sync_bio->bi_private = stbl;
    sync_bio->bi_end_io = sync_bio_endio;
    sync_bio->bi_opf = REQ_OP_WRITE;
    sync_bio->bi_bdev = bio->bi_bdev;
    sync_bio->bi_ioprio = bio->bi_ioprio;
    sync_bio->bi_write_hint = bio->bi_write_hint;
    sync_bio->bi_iter.bi_sector = bio->bi_iter.bi_sector;
    sync_bio->bi_iter.bi_size = bio->bi_iter.bi_size;

    if (bio_data_dir(bio) == READ) {
        bio_for_each_segment(bv, bio, iter)
            sync_bio->bi_io_vec[sync_bio->bi_vcnt++] = bv;

        for (i = 0, to = sync_bio->bi_io_vec; i < bio->bi_vcnt; to++, i++) {
            struct page* sync_page;

            sync_page = mempool_alloc(&sync_page_pool, GFP_NOIO);
            memcpy_from_bvec(page_address(sync_page), to);

            to->bv_page = sync_page;
        }
    }

    return sync_bio;
}

void sync_bio_endio(struct bio* bio) {
    struct sync_table* stbl = bio->bi_private;
    sector_t start = bio->bi_iter.bi_sector;
    sector_t end = bio_end_sector(bio);
    unsigned int i, j;

    while (start < end && stbl->remain > 0) {
        i = start / sizeof(int) * 8;
        j = start % sizeof(int) * 8;
        if (!(stbl->bitmap[i] & (1 << j))) {
            BITMAP_SET(stbl->bitmap[i], j);
            stbl->remain--;
        }
    }

    if (stbl->remain == 0) {
        struct dev_sync_table* dev_sync_tbl = stbl->private;
        struct dev_region_mapper* mapper = dev_sync_tbl->private;
        set_mapping_entry(mapper->mapping_tbl, stbl->logical_chunk,
                          stbl->target_physical_chunk);
        list_del(&stbl->list);
        free_sync_table(stbl);
        free_physical_chunk(mapper->mapping_tbl, stbl->original_physical_chunk);
    }
}

struct bio* alloc_flush_mapping_table_bio(struct dev_region_mapper* mapper,
                                          gfp_t gfp_mask) {
    struct bio* bio = NULL;
    // TODO:
    return bio;
}

void flush_mapping_table_endio(struct bio* bio) {
    // struct dev_region_mapper* mapper = bio->bi_private;
    // TODO:
}
