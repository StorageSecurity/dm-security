#ifndef __REGION_MAPPER_H
#define __REGION_MAPPER_H

#include <linux/types.h>

#define CHUNK_SIZE (4 * 1024 * 1024)  // 1MB
#define CHUNK_SHIFT (22)
#define EXPECT_RDWR_SHIFT (30)
#define CURRENT_RDWR_SHIFT (28)
#define REGION_TYPE_MASK (0x3)
#define REGION_READ_BIT(mask) ((mask)&0x2)
#define REGION_WRITE_BIT(mask) ((mask)&0x1)
#define EXPECT_RDWR_CLEAR_THEN_SET(entry, type)               \
    (((~(REGION_TYPE_MASK << EXPECT_RDWR_SHIFT)) & (entry)) | \
     ((type) << EXPECT_RDWR_SHIFT))

struct dev_id;
struct mapping_table;
struct dev_region_mapper;

struct list_head get_all_devices(void);

struct dev_region_mapper* dev_create_region_mapper(char* name,
                                                   dev_t dev,
                                                   sector_t sectors);

struct mapping_table* alloc_mapping_table(sector_t sectors);
void free_mapping_table(struct mapping_table* tbl);

#endif