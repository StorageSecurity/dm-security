#ifndef __HOT_COLD_REGION_H__
#define __HOT_COLD_REGION_H__

#include "io-aware.h"

#define READ_HOT_WRITE_HOT 0
#define READ_HOT_WRITE_COLD 1
#define READ_COLD_WRITE_HOT 2
#define READ_COLD_WRITE_COLD 3
#define REGION_NUM 4

#define REGION_SIZE_READ_HOT_WRITE_HOT(chknum) (chknum / 10)
#define REGION_SIZE_READ_HOT_WRITE_COLD(chknum) (chknum / 5)
#define REGION_SIZE_READ_COLD_WRITE_HOT(chknum) (chknum / 5)
#define REGION_SIZE_READ_COLD_WRITE_COLD(chknum)       \
    (chknum - REGION_SIZE_READ_HOT_WRITE_HOT(chknum) - \
     REGION_SIZE_READ_HOT_WRITE_COLD(chknum) -         \
     REGION_SIZE_READ_COLD_WRITE_HOT(chknum))

#define IO_REGION_MAPPED 0
#define IO_REGION_UNMAPPED 1
#define IO_REGION_REMAPPED 2
#define region_map_result int

struct device_region;
struct region_translation_layer;
struct global_region_map;

struct region_translation_layer {
    const char* devname;
    struct device_region* region[REGION_NUM];
    struct global_region_map* map;
};

struct device_region {
    unsigned long start;
    unsigned long size;
    unsigned long in_use;
    unsigned long* map;
};

struct global_region_map {
    unsigned long size;
    unsigned long* map;
};

struct global_region_map* alloc_region_map(unsigned long size);
void free_region_map(struct global_region_map* map);
void region_map_set(struct global_region_map* map,
                    unsigned long index,
                    unsigned long value);
unsigned long region_map_get(struct global_region_map* map,
                             unsigned long index);

struct region_translation_layer* alloc_region_translation_layer(
    const char* devname,
    int size);
void free_region_translation_layer(struct region_translation_layer* rtl);

struct device_region* alloc_device_region(unsigned long start,
                                          unsigned long size);
void free_device_region(struct device_region* region);

region_map_result io_region_map(struct region_translation_layer* rtl,
                   struct bio* bio,
                   rw_mode mode);
int io_region_alloc_chunk(struct region_translation_layer* rtl, rw_mode mode);

#endif