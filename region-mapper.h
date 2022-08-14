#ifndef __REGION_MAPPER_H
#define __REGION_MAPPER_H

#include <linux/blk_types.h>
#include <linux/gfp.h>

#define REGION_READ_HOT_WRITE_HOT (0b11)
#define REGION_READ_HOT_WRITE_COLD (0b10)
#define REGION_READ_COLD_WRITE_HOT (0b01)
#define REGION_READ_COLD_WRITE_COLD (0b00)

#define CHUNK_SHIFT (14)
#define CHUNK_SIZE_IN_SECTORS \
    (1 << CHUNK_SHIFT)  // 2^14 * 512B(sector) = 2^23B = 8MB
#define SECTOR_TO_CHUNK(sectors) ((sectors) >> CHUNK_SHIFT)

#define REGION_TYPE_MASK (0x3)

#define EXPECT_RDWR_SHIFT (30)
#define EXPECT_RDWR_TYPE(entry) \
    (((entry) >> EXPECT_RDWR_SHIFT) & REGION_TYPE_MASK)

#define CURRENT_RDWR_SHIFT (28)
#define CURRENT_RDWR_TYPE(entry) \
    (((entry) >> CURRENT_RDWR_SHIFT) & REGION_TYPE_MASK)

#define REGION_READ_BIT(mask) ((mask)&0x2)
#define REGION_WRITE_BIT(mask) ((mask)&0x1)
#define EXPECT_RDWR_CLEAR_THEN_SET(entry, type)                        \
    (entry = (((~(REGION_TYPE_MASK << EXPECT_RDWR_SHIFT)) & (entry)) | \
              ((type) << EXPECT_RDWR_SHIFT)))

#define MAPPING_ENTRY_IN_USE_SHIFT (27)
#define MAPPING_ENTRY_IN_USE(entry) \
    ((entry) & (1 << MAPPING_ENTRY_IN_USE_SHIFT))
#define MAPPING_ENTRY_SET_IN_USE(entry) \
    (entry |= (1 << MAPPING_ENTRY_IN_USE_SHIFT))
#define MAPPING_ENTRY_IN_USE_STATE(entry) \
    ((entry >> (MAPPING_ENTRY_IN_USE_SHIFT - 1)) & 1)

#define TARGET_CHUNK_MASK (0x7FFFFFF)
#define TARGET_CHUNK(entry) ((entry)&TARGET_CHUNK_MASK)
#define TARGET_CHUNK_SET(entry, chunk) \
    (((entry) & ~TARGET_CHUNK_MASK) | (chunk))

#define BITMAP_SET(bitmap, bit) ((bitmap) |= (1 << (bit)))
#define BITMAP_CLEAR(bitmap, bit) ((bitmap) &= ~(1 << (bit)))

struct dev_id;
struct mapping_table;
struct dev_region_mapper;
struct sync_table;
struct dev_sync_table;
struct sync_io;

struct dev_region_mapper {
    struct dev_id* dev;
    sector_t meta_start;    // metadata start sector
    sector_t meta_sectors;  // metadata length in sector
    sector_t data_start;    // device start sector
    sector_t data_sectors;  // device length in sectors
    struct mapping_table* mapping_tbl;
    struct dev_sync_table* dev_sync_tbl;
};

struct sync_io {
    unsigned int src_retion_type;
    unsigned int dst_region_type;
    struct bio* base_io;
};

struct list_head get_all_devices(void);

struct dev_region_mapper* dev_create_region_mapper(const char* name,
                                                   dev_t dev,
                                                   sector_t meta_start,
                                                   sector_t meta_sectors,
                                                   sector_t data_start,
                                                   sector_t data_sectors);
void dev_destroy_region_mapper(struct dev_region_mapper* mapper);

struct mapping_table* alloc_mapping_table(sector_t sectors);
void free_mapping_table(struct mapping_table* tbl);
inline void use_physical_chunk(struct mapping_table* tbl, unsigned int pc);
inline void free_physical_chunk(struct mapping_table* tbl, unsigned int pc);
unsigned int get_mapping_entry(struct mapping_table* tbl, sector_t sectors);
unsigned int set_mapping_entry(struct mapping_table* tbl,
                               unsigned int lc,
                               unsigned int entry);
unsigned int find_free_physical_chunk(struct mapping_table* tbl);
unsigned int alloc_free_physical_chunk(struct mapping_table* tbl,
                                       unsigned int lc);

struct dev_sync_table* alloc_dev_sync_table(struct dev_id* dev);
void free_dev_sync_table(struct dev_sync_table* tbl);
struct sync_table* alloc_sync_table(unsigned int lc,
                                    unsigned int opc,
                                    unsigned int tpc);
void free_sync_table(struct sync_table* stbl);
struct sync_table* get_sync_table(struct dev_sync_table* tbl, unsigned int lc);
bool check_chunk_in_sync(struct dev_id* dev, unsigned int lc);
bool check_sectors_synced(struct sync_table* stbl,
                          sector_t start,
                          sector_t sectors);

struct sync_io* bio_region_map(struct dev_region_mapper* mapper,
                               struct bio* bio);
inline struct sync_io* __bio_region_map(struct dev_region_mapper* mapper,
                                        struct bio* bio,
                                        unsigned int entry);
struct sync_io* bio_region_map_sync(struct dev_region_mapper* mapper,
                                    struct bio* bio,
                                    unsigned int entry);
struct bio* spawn_sync_bio(struct sync_table* stbl,
                           struct bio* bio,
                           gfp_t gfp_mask);
void sync_bio_endio(struct bio* bio);
struct bio* alloc_flush_mapping_table_bio(struct dev_region_mapper* mapper,
                                          gfp_t gfp_mask);
void flush_mapping_table_endio(struct bio* bio);

#endif