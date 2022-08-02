#ifndef __IO_AWARE_H__
#define __IO_AWARE_H__

#include <linux/atmioc.h>
#include <linux/bio.h>
#include <linux/kernel.h>
#include <linux/list.h>

#define IO_CHUNK_SIZE (1 * 1024 * 1024)
#define GET_CHUNK_NUM(sector) (DIV_ROUND_UP(sector, IO_CHUNK_SIZE))
#define GET_CHUNK_INDEX(sector) (sector / IO_CHUNK_SIZE)

struct io_account {
    atomic_t read;
    atomic_t write;
};

struct io_account_device {
    struct io_account_table* table;
    struct list_head list;
    char name[16];
};

struct io_account_table {
    struct io_account* account;
    int size;
};

LIST_HEAD(io_account_device_list);

struct io_account_device* alloc_io_account_device(const char* name, int size);
void free_io_account_device(struct io_account_device* device);

struct io_account_table* alloc_io_account_table(int size);
void free_io_account_table(struct io_account_table* table);
void io_account_inc(struct io_account_table* list, struct bio* bio);

#endif