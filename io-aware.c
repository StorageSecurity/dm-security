#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/slab.h>

#include "io-aware.h"

//////////// proc seq_file ////////////

struct proc_dir_entry* proc_io_aware;

static void* io_aware_seq_start(struct seq_file* seq, loff_t* pos) {
    static unsigned long counter = 0;
    struct io_account_device* device = pde_data(file_inode(seq->file));

    pr_info("%s: start io-aware proc\n", device->name);

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

static void* io_aware_seq_next(struct seq_file* seq, void* v, loff_t* pos) {
    struct io_account_device* device = pde_data(file_inode(seq->file));
    pr_info("%s: next io-aware proc\n", device->name);
    return NULL;
}

static void io_aware_seq_stop(struct seq_file* seq, void* v) {}

static int io_aware_seq_show(struct seq_file* seq, void* v) {
    struct io_account_device* device = pde_data(file_inode(seq->file));
    struct io_account_table* table = device->table;
    int i;
    for (i = 0; i < table->size; i++) {
        seq_printf(seq, "[%d, %d] Read = %d, Write = %d\n", i * IO_CHUNK_SIZE,
                   (i + 1) * IO_CHUNK_SIZE - 1,
                   atomic_read(&table->account[i].read),
                   atomic_read(&table->account[i].write));
        pr_info("io_aware_seq_show %d\n", i);
    }
    return 0;
}

static struct seq_operations io_aware_seq_ops = {
    .start = io_aware_seq_start,
    .next = io_aware_seq_next,
    .stop = io_aware_seq_stop,
    .show = io_aware_seq_show,
};

///////////////////////////////////////////////////////////////////////////////

struct io_account_device* alloc_io_account_device(const char* name, int size) {
    struct io_account_device* device =
        kmalloc(sizeof(struct io_account_device), GFP_KERNEL);
    if (device == NULL) {
        return NULL;
    }
    strcpy(device->name, name);
    device->table = alloc_io_account_table(GET_CHUNK_NUM(size));
    if (device->table == NULL) {
        goto r_device;
    }

    INIT_LIST_HEAD(&device->list);
    list_add_tail(&device->list, &io_account_device_list);

    proc_create_seq_data(name, 0444, proc_io_aware, &io_aware_seq_ops, device);

    return device;

r_device:
    kfree(device);
    return NULL;
}
EXPORT_SYMBOL(alloc_io_account_device);

void free_io_account_device(struct io_account_device* device) {
    list_del(&device->list);
    free_io_account_table(device->table);
    kfree(device);
}
EXPORT_SYMBOL(free_io_account_device);

struct io_account_table* alloc_io_account_table(int size) {
    int i;
    struct io_account_table* table =
        kmalloc(sizeof(struct io_account_table), GFP_KERNEL);
    if (table == NULL) {
        return NULL;
    }

    table->account = kmalloc(sizeof(struct io_account) * size, GFP_KERNEL);
    if (table->account == NULL) {
        goto bad;
    }
    for (i = 0; i < size; i++) {
        atomic_set(&table->account[i].read, 0);
        atomic_set(&table->account[i].write, 0);
    }

    table->size = size;
    return table;

bad:
    free_io_account_table(table);
    return NULL;
}
EXPORT_SYMBOL(alloc_io_account_table);

void free_io_account_table(struct io_account_table* list) {
    kfree(list->account);
    kfree(list);
}
EXPORT_SYMBOL(free_io_account_table);

/**
 * @brief bio account
 *
 * @param list
 * @param bio
 */
void io_account_inc(struct io_account_table* list, struct bio* bio) {
    struct io_account* account = list->account;
    int i = GET_CHUNK_INDEX(bio->bi_iter.bi_sector);

    if (bio_data_dir(bio) == READ) {
        atomic_inc(&account[i].read);
    } else {
        atomic_inc(&account[i].write);
    }
}
EXPORT_SYMBOL(io_account_inc);

rw_mode io_read_write_mode(struct io_account_table* list, struct bio* bio) {
    struct io_account* account = list->account;
    int i = GET_CHUNK_INDEX(bio->bi_iter.bi_sector);
    int read = atomic_read(&account[i].read);
    int write = atomic_read(&account[i].write);

    if (read >= write * 10) {
        return RW_MODE_RHWC;
    }
    if (write >= read * 10) {
        return RW_MODE_RCWH;
    }
    if (read > 100 && write > 100) {
        return RW_MODE_RHWH;
    } else {
        return RW_MODE_RCWC;
    }
}
EXPORT_SYMBOL(io_read_write_mode);

static int __init io_aware_init(void) {
    proc_io_aware = proc_mkdir("io-aware", NULL);
    if (proc_io_aware == NULL) {
        pr_err("io-aware: failed to create proc directory: io-aware");
        return -ENOMEM;
    }
    return 0;
}

static void __exit io_aware_exit(void) {
    remove_proc_entry("io-aware", NULL);
}

module_init(io_aware_init);
module_exit(io_aware_exit);

MODULE_AUTHOR("Peihong Chen <chph13420146901@gmail.com>");
MODULE_DESCRIPTION("io aware module for block device security");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");