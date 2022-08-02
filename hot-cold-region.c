#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>

#include "hot-cold-region.h"
#include "io-aware.h"

/////////////// proc seq_file ////////////

struct proc_dir_entry* proc_hot_cold_region;

static void* device_region_seq_start(struct seq_file* seq, loff_t* pos) {
    static unsigned long counter = 0;
    struct region_translation_layer* rtl = pde_data(file_inode(seq->file));
    pr_info("%s: start hot-cold-region proc\n", rtl->devname);

    /* beginning a new sequence ? */
    if (*pos == 0) {
        /* yes => return a non null value to begin the sequence */
        return &counter;
    } else {
        /* no => it's the end of the sequence, return end to stop reading */
        *pos = 0;
        return NULL;
    }
}

static void* device_region_seq_next(struct seq_file* seq,
                                    void* v,
                                    loff_t* pos) {
    struct region_translation_layer* rtl = pde_data(file_inode(seq->file));
    pr_info("%s: next start hot-cold-region proc\n", rtl->devname);
    return NULL;
}

static void device_region_seq_stop(struct seq_file* seq, void* v) {}

static int device_region_seq_show(struct seq_file* seq, void* v) {
    struct region_translation_layer* rtl = pde_data(file_inode(seq->file));
    int i;

    seq_printf(seq, "[global map]\n");
    for (i = 0; i < rtl->map->size; i++) {
        seq_printf(seq, "[%d, %d] => %ld\n", i * IO_CHUNK_SIZE,
                   (i + 1) * IO_CHUNK_SIZE - 1, rtl->map->bitmap[i]);
    }
    seq_printf(seq, "\n");

    seq_printf(seq, "[region]\n");
    seq_printf(seq, "type: READ_HOT_WRITE_HOT\n");
    seq_printf(seq, "start: %ld\n", rtl->region[READ_HOT_WRITE_HOT]->start);
    seq_printf(seq, "size: %ld\n", rtl->region[READ_HOT_WRITE_HOT]->size);
    seq_printf(seq, "in_use: %ld\n", rtl->region[READ_HOT_WRITE_HOT]->in_use);
    seq_printf(seq, "\n");

    seq_printf(seq, "[region]\n");
    seq_printf(seq, "type: READ_HOT_WRITE_COLD\n");
    seq_printf(seq, "start: %ld\n", rtl->region[READ_HOT_WRITE_COLD]->start);
    seq_printf(seq, "size: %ld\n", rtl->region[READ_HOT_WRITE_COLD]->size);
    seq_printf(seq, "in_use: %ld\n", rtl->region[READ_HOT_WRITE_COLD]->in_use);
    seq_printf(seq, "\n");

    seq_printf(seq, "[region]\n");
    seq_printf(seq, "type: READ_COLD_WRITE_HOT\n");
    seq_printf(seq, "start: %ld\n", rtl->region[READ_COLD_WRITE_HOT]->start);
    seq_printf(seq, "size: %ld\n", rtl->region[READ_COLD_WRITE_HOT]->size);
    seq_printf(seq, "in_use: %ld\n", rtl->region[READ_COLD_WRITE_HOT]->in_use);
    seq_printf(seq, "\n");

    seq_printf(seq, "[region]\n");
    seq_printf(seq, "type: READ_COLD_WRITE_COLD\n");
    seq_printf(seq, "start: %ld\n", rtl->region[READ_COLD_WRITE_COLD]->start);
    seq_printf(seq, "size: %ld\n", rtl->region[READ_COLD_WRITE_COLD]->size);
    seq_printf(seq, "in_use: %ld\n", rtl->region[READ_COLD_WRITE_COLD]->in_use);
    seq_printf(seq, "\n");

    return 0;
}

static struct seq_operations device_region_seq_ops = {
    .start = device_region_seq_start,
    .next = device_region_seq_next,
    .stop = device_region_seq_stop,
    .show = device_region_seq_show,
};

static int init_region_proc(const char* name,
                            struct region_translation_layer* rtl) {
    proc_create_seq_data(name, 0444, proc_hot_cold_region,
                         &device_region_seq_ops, rtl);
    return 0;
}

///////////////////////////////////////////////////////////////////////////////

struct global_region_map* alloc_region_map(unsigned long chunk_num) {
    struct global_region_map* map =
        kmalloc(sizeof(struct global_region_map), GFP_KERNEL);
    if (!map) {
        pr_err("alloc_region_map: failed to allocate memory\n");
        return NULL;
    }
    map->size = chunk_num;
    map->bitmap = kzalloc(sizeof(unsigned long) * chunk_num, GFP_KERNEL);

    return map;
}
EXPORT_SYMBOL(alloc_region_map);

void free_region_map(struct global_region_map* map) {
    kfree(map->bitmap);
    map->bitmap = NULL;
    kfree(map);
}
EXPORT_SYMBOL(free_region_map);

void region_map_set(struct global_region_map* map,
                    unsigned long index,
                    unsigned long value) {
    if (index < map->size)
        map->bitmap[index] = value;
}
EXPORT_SYMBOL(region_map_set);

unsigned long region_map_get(struct global_region_map* map,
                             unsigned long index) {
    if (index < map->size)
        return map->bitmap[index];
    return -1;
}
EXPORT_SYMBOL(region_map_get);

struct region_translation_layer* alloc_region_translation_layer(
    const char* devname,
    int size) {
    int chunk_num = GET_CHUNK_NUM(size);

    struct region_translation_layer* rtl =
        kmalloc(sizeof(struct region_translation_layer), GFP_KERNEL);
    if (rtl == NULL) {
        return NULL;
    }

    rtl->devname = devname;

    rtl->map = alloc_region_map(chunk_num);
    if (rtl->map == NULL) {
        pr_err(
            "alloc_region_translation_layer: failed to allocate memory for "
            "global_region_map\n");
        kfree(rtl);
        return NULL;
    }

    rtl->region[READ_HOT_WRITE_HOT] =
        alloc_device_region(0, REGION_SIZE_READ_HOT_WRITE_HOT(chunk_num));
    if (rtl->region[READ_HOT_WRITE_HOT] == NULL) {
        goto e_region;
    } else {
        pr_info(
            "alloc_region_translation_layer: READ_HOT_WRITE_HOT [%d ~ %d]\n", 0,
            REGION_SIZE_READ_HOT_WRITE_HOT(chunk_num));
    }

    rtl->region[READ_HOT_WRITE_COLD] =
        alloc_device_region(REGION_SIZE_READ_HOT_WRITE_HOT(chunk_num),
                            REGION_SIZE_READ_HOT_WRITE_COLD(chunk_num));
    if (rtl->region[READ_HOT_WRITE_COLD] == NULL) {
        goto e_region;
    } else {
        pr_info(
            "alloc_region_translation_layer: READ_HOT_WRITE_COLD [%d ~ %d]\n",
            REGION_SIZE_READ_HOT_WRITE_HOT(chunk_num),
            REGION_SIZE_READ_HOT_WRITE_HOT(chunk_num) +
                REGION_SIZE_READ_HOT_WRITE_COLD(chunk_num));
    }

    rtl->region[READ_COLD_WRITE_HOT] =
        alloc_device_region(REGION_SIZE_READ_HOT_WRITE_HOT(chunk_num) +
                                REGION_SIZE_READ_HOT_WRITE_COLD(chunk_num),
                            REGION_SIZE_READ_COLD_WRITE_HOT(chunk_num));
    if (rtl->region[READ_COLD_WRITE_HOT] == NULL) {
        goto e_region;
    } else {
        pr_info(
            "alloc_region_translation_layer: READ_COLD_WRITE_HOT [%d ~ %d]\n",
            REGION_SIZE_READ_HOT_WRITE_HOT(chunk_num) +
                REGION_SIZE_READ_HOT_WRITE_COLD(chunk_num),
            REGION_SIZE_READ_HOT_WRITE_HOT(chunk_num) +
                REGION_SIZE_READ_HOT_WRITE_COLD(chunk_num) +
                REGION_SIZE_READ_COLD_WRITE_HOT(chunk_num));
    }

    rtl->region[READ_COLD_WRITE_COLD] =
        alloc_device_region(REGION_SIZE_READ_HOT_WRITE_HOT(chunk_num) +
                                REGION_SIZE_READ_HOT_WRITE_COLD(chunk_num) +
                                REGION_SIZE_READ_COLD_WRITE_HOT(chunk_num),
                            REGION_SIZE_READ_COLD_WRITE_COLD(chunk_num));
    if (rtl->region[READ_COLD_WRITE_COLD] == NULL) {
        goto e_region;
    } else {
        pr_info(
            "alloc_region_translation_layer: READ_COLD_WRITE_COLD [%d ~ %d]\n",
            REGION_SIZE_READ_HOT_WRITE_HOT(chunk_num) +
                REGION_SIZE_READ_HOT_WRITE_COLD(chunk_num) +
                REGION_SIZE_READ_COLD_WRITE_HOT(chunk_num),
            REGION_SIZE_READ_HOT_WRITE_HOT(chunk_num) +
                REGION_SIZE_READ_HOT_WRITE_COLD(chunk_num) +
                REGION_SIZE_READ_COLD_WRITE_HOT(chunk_num) +
                REGION_SIZE_READ_COLD_WRITE_COLD(chunk_num));
    }

    if (init_region_proc(devname, rtl)) {
        pr_err("init_region_proc failed\n");
    }

    return rtl;

e_region:
    pr_err(
        "alloc_region_translation_layer: failed to allocate device region\n");
    return NULL;
}
EXPORT_SYMBOL(alloc_region_translation_layer);

void free_region_translation_layer(struct region_translation_layer* rtl) {
    kfree(rtl);
}
EXPORT_SYMBOL(free_region_translation_layer);

struct device_region* alloc_device_region(unsigned long start,
                                          unsigned long size) {
    struct device_region* region =
        kmalloc(sizeof(struct device_region), GFP_KERNEL);
    if (region == NULL) {
        return NULL;
    }
    region->start = start;
    region->size = size;
    region->in_use = 0;
    return region;
}
EXPORT_SYMBOL(alloc_device_region);

void free_device_region(struct device_region* region) {
    kfree(region);
}
EXPORT_SYMBOL(free_device_region);

static int __init hot_cold_region_init(void) {
    pr_info("hot_cold_region_init\n");
    proc_hot_cold_region = proc_mkdir("hot-cold-region", NULL);
    if (proc_hot_cold_region == NULL) {
        pr_err(
            "hot-cold-region: failed to create proc directory: "
            "hot-cold-region");
        return -ENOMEM;
    }
    return 0;
}

static void __exit hot_cold_region_exit(void) {
    pr_info("hot_cold_region_exit\n");
    remove_proc_entry("hot-cold-region", NULL);
}

module_init(hot_cold_region_init);
module_exit(hot_cold_region_exit);

MODULE_AUTHOR("Peihong Chen");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("hot cold region module");
MODULE_VERSION("0.1");