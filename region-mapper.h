#ifndef __REGION_MAPPER_H
#define __REGION_MAPPER_H

#include <linux/blk_types.h>

#define CHUNK_SIZE (8 * 1024 * 1024)  // 8MB
#define CHUNK_SHIFT (22)
#define SECTOR_TO_CHUNK(sector) ((sector) >> CHUNK_SHIFT)
#define SECTORS_IN_CHUNK ((1 << CHUNK_SHIFT) >> SECTOR_SHIFT)

#define REGION_TYPE_MASK (0x3)

#define EXPECT_RDWR_SHIFT (30)
#define EXPECT_RDWR_TYPE(entry) \
    (((entry) >> EXPECT_RDWR_SHIFT) & REGION_TYPE_MASK)

#define CURRENT_RDWR_SHIFT (28)
#define CURRENT_RDWR_TYPE(entry) \
    (((entry) >> CURRENT_RDWR_SHIFT) & REGION_TYPE_MASK)

#define REGION_READ_BIT(mask) ((mask)&0x2)
#define REGION_WRITE_BIT(mask) ((mask)&0x1)
#define EXPECT_RDWR_CLEAR_THEN_SET(entry, type)               \
    (((~(REGION_TYPE_MASK << EXPECT_RDWR_SHIFT)) & (entry)) | \
     ((type) << EXPECT_RDWR_SHIFT))

#define MAPPING_ENTRY_IN_USE_SHIFT (27)
#define MAPPING_ENTRY_IN_USE(entry) \
    ((entry) & (1 << MAPPING_ENTRY_IN_USE_SHIFT))

#define TARGET_CHUNK_MASK (0x7FFFFFF)
#define TARGET_CHUNK(entry) ((entry)&TARGET_CHUNK_MASK)

struct dev_id;
struct mapping_table;
struct dev_region_mapper;
struct sync_table;
struct dev_sync_table;

struct list_head get_all_devices(void);

struct dev_region_mapper* dev_create_region_mapper(const char* name,
                                                   dev_t dev,
                                                   sector_t start,
                                                   sector_t sectors);
void dev_destroy_region_mapper(struct dev_region_mapper* mapper);

struct mapping_table* alloc_mapping_table(sector_t sectors);
void free_mapping_table(struct mapping_table* tbl);
unsigned int get_mapping_entry(struct mapping_table* tbl, sector_t sectors);
int alloc_new_mapping_entry(struct mapping_table* tbl);

struct dev_sync_table* alloc_dev_sync_table(struct dev_id* dev);
void free_dev_sync_table(struct dev_sync_table* tbl);
struct sync_table* alloc_sync_table(unsigned int lc,
                                    unsigned int opc,
                                    unsigned int tpc);
void free_sync_table(struct sync_table* tbl);
bool check_chunk_in_sync(dev_t dev, unsigned int lc);

void bio_region_map(struct dev_region_mapper* mapper, struct bio* bio);
inline void __bio_region_map(struct dev_region_mapper* mapper,
                             struct bio* bio,
                             unsigned int entry);
void bio_read_region_map(struct dev_region_mapper* mapper,
                         struct bio* bio,
                         unsigned int entry);
void bio_write_region_map(struct dev_region_mapper* mapper,
                          struct bio* bio,
                          unsigned int entry);

#endif