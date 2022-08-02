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
};

struct global_region_map {
    unsigned long size;
    unsigned long* bitmap;
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

#endif