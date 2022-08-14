/*
 * Copyright (C) 2003 Jana Saout <jana@saout.de>
 * Copyright (C) 2004 Clemens Fruhwirth <clemens@endorphin.org>
 * Copyright (C) 2006-2020 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2013-2020 Milan Broz <gmazyland@gmail.com>
 *
 * This file is released under the GPL.
 */

#include <asm/page.h>
#include <asm/unaligned.h>
#include <crypto/algapi.h>
#include <crypto/hash.h>
#include <crypto/md5.h>
#include <crypto/skcipher.h>
#include <keys/encrypted-type.h>
#include <keys/trusted-type.h>
#include <keys/user-type.h>
#include <linux/atomic.h>
#include <linux/backing-dev.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/completion.h>
#include <linux/crypto.h>
#include <linux/ctype.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/key-type.h>
#include <linux/key.h>
#include <linux/kthread.h>
#include <linux/mempool.h>
#include <linux/module.h>
#include <linux/rbtree.h>
#include <linux/rtnetlink.h> /* for struct rtattr and RTA macros only */
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#include <linux/device-mapper.h>
#include "region-mapper.h"

#define DM_MSG_PREFIX "security"

/* extern interfaces in region-mapper module */

extern struct dev_region_mapper* dev_create_region_mapper(
    const char* name,
    dev_t dev,
    sector_t meta_start,
    sector_t meta_sectors,
    sector_t data_start,
    sector_t data_sectors);

extern void dev_destroy_region_mapper(struct dev_region_mapper* mapper);

/*
 * context holding the current state of a multi-part conversion
 */
struct convert_context {
    struct completion restart;
    struct bio* bio_in;
    struct bio* bio_out;
    struct bvec_iter iter_in;
    struct bvec_iter iter_out;
    u64 cc_sector;
    atomic_t cc_pending;
    struct skcipher_request* req;
};

/*
 * per bio private data
 */
struct dm_crypt_io {
    struct crypt_config* cc;
    struct crypt_strategy* cs;
    struct bio* base_bio;
    struct work_struct work;
    struct tasklet_struct tasklet;

    struct convert_context ctx;

    atomic_t io_pending;
    blk_status_t error;
    sector_t sector;

    struct rb_node rb_node;
} CRYPTO_MINALIGN_ATTR;

struct dm_crypt_request {
    struct convert_context* ctx;
    struct scatterlist sg_in[4];
    struct scatterlist sg_out[4];
    u64 iv_sector;
};

struct crypt_config;

struct crypt_iv_operations {
    int (*ctr)(struct crypt_strategy* cs,
               struct dm_target* ti,
               const char* opts);
    void (*dtr)(struct crypt_strategy* cs);
    int (*init)(struct crypt_strategy* cs);
    int (*wipe)(struct crypt_strategy* cs);
    int (*generator)(struct crypt_strategy* cs,
                     u8* iv,
                     struct dm_crypt_request* dmreq);
    int (*post)(struct crypt_strategy* cs,
                u8* iv,
                struct dm_crypt_request* dmreq);
};

/*
 * Crypt: maps a linear range of a block device
 * and encrypts / decrypts at the same time.
 */
enum flags {
    DM_CRYPT_SUSPENDED,
    DM_CRYPT_KEY_VALID,
    DM_CRYPT_SAME_CPU,
    DM_CRYPT_NO_OFFLOAD,
    DM_CRYPT_NO_READ_WORKQUEUE,
    DM_CRYPT_NO_WRITE_WORKQUEUE,
    DM_CRYPT_WRITE_INLINE
};

enum cipher_flags {
    CRYPT_IV_LARGE_SECTORS,   /* Calculate IV from sector_size, not 512B sectors
                               */
    CRYPT_ENCRYPT_PREPROCESS, /* Must preprocess data for encryption (elephant)
                               */
};

struct crypt_strategy {
    char cipher_string[16];
    struct crypto_skcipher** cipher_tfm;
    unsigned tfms_count;

    const struct crypt_iv_operations* iv_gen_ops;
    unsigned int iv_size;

    /*
     * Layout of each crypto request:
     *
     *   struct skcipher_request
     *      context
     *      padding
     *   struct dm_crypt_request
     *      padding
     *   IV
     *
     * The padding is added so that dm_crypt_request and the IV are
     * correctly aligned.
     */
    unsigned int dmreq_start;

    unsigned per_bio_data_size;

    mempool_t req_pool;
};

struct crypt_strategies {
    struct crypt_strategy read_write_efficient;
    struct crypt_strategy read_most_efficient;
    struct crypt_strategy write_most_efficient;
    struct crypt_strategy default_strategy;
};

/*
 * The fields in here must be read only after initialization.
 */
struct crypt_config {
    struct dm_dev* dev;
    sector_t start;

    struct dev_region_mapper* rmap;

    struct percpu_counter n_allocated_pages;

    struct workqueue_struct* io_queue;
    struct workqueue_struct* crypt_queue;

    spinlock_t write_thread_lock;
    struct task_struct* write_thread;
    struct rb_root write_tree;

    struct crypt_strategies crypt_strategies;

    char* key_string;

    u64 iv_offset;
    unsigned short int sector_size;
    unsigned char sector_shift;

    unsigned long cipher_flags;

    unsigned long flags;
    unsigned int key_size;
    unsigned int key_parts; /* independent parts in key buffer */

    /*
     * pool for per bio private data, crypto requests,
     * encryption requeusts/buffer pages and integrity tags
     */
    mempool_t page_pool;

    struct bio_set bs;
    struct mutex bio_alloc_lock;

    u8 key[];
};

#define MIN_IOS 64
#define POOL_ENTRY_SIZE 512

static DEFINE_SPINLOCK(dm_crypt_clients_lock);
static unsigned dm_crypt_clients_n = 0;
static volatile unsigned long dm_crypt_pages_per_client;
#define DM_CRYPT_MEMORY_PERCENT 2
#define DM_CRYPT_MIN_PAGES_PER_CLIENT (BIO_MAX_VECS * 16)

static void clone_init(struct dm_crypt_io*, struct bio*);
static void kcryptd_queue_crypt(struct dm_crypt_io* io);

/*
 * Use this to access cipher attributes that are independent of the key.
 */
static struct crypto_skcipher* any_tfm(struct crypt_strategy* cs) {
    return cs->cipher_tfm[0];
}

static int crypt_iv_essiv_gen(struct crypt_strategy* cs,
                              u8* iv,
                              struct dm_crypt_request* dmreq) {
    /*
     * ESSIV encryption of the IV is now handled by the crypto API,
     * so just pass the plain sector number here.
     */
    memset(iv, 0, cs->iv_size);
    *(__le64*)iv = cpu_to_le64(dmreq->iv_sector);

    return 0;
}

static const struct crypt_iv_operations crypt_iv_essiv_ops = {
    .generator = crypt_iv_essiv_gen};

static void crypt_convert_init(struct crypt_config* cc,
                               struct convert_context* ctx,
                               struct bio* bio_out,
                               struct bio* bio_in,
                               sector_t sector) {
    ctx->bio_in = bio_in;
    ctx->bio_out = bio_out;
    if (bio_in)
        ctx->iter_in = bio_in->bi_iter;
    if (bio_out)
        ctx->iter_out = bio_out->bi_iter;
    ctx->cc_sector = sector + cc->iv_offset;
    init_completion(&ctx->restart);
}

static struct dm_crypt_request* dmreq_of_req(struct crypt_strategy* cs,
                                             void* req) {
    return (struct dm_crypt_request*)((char*)req + cs->dmreq_start);
}

static void* req_of_dmreq(struct crypt_strategy* cs,
                          struct dm_crypt_request* dmreq) {
    return (void*)((char*)dmreq - cs->dmreq_start);
}

static u8* iv_of_dmreq(struct crypt_strategy* cs,
                       struct dm_crypt_request* dmreq) {
    return (u8*)ALIGN((unsigned long)(dmreq + 1),
                      crypto_skcipher_alignmask(any_tfm(cs)) + 1);
}

static u8* org_iv_of_dmreq(struct crypt_strategy* cs,
                           struct dm_crypt_request* dmreq) {
    return iv_of_dmreq(cs, dmreq) + cs->iv_size;
}

static __le64* org_sector_of_dmreq(struct crypt_strategy* cs,
                                   struct dm_crypt_request* dmreq) {
    u8* ptr = iv_of_dmreq(cs, dmreq) + cs->iv_size + cs->iv_size;
    return (__le64*)ptr;
}

static int crypt_convert_block_skcipher(struct crypt_config* cc,
                                        struct crypt_strategy* cs,
                                        struct convert_context* ctx,
                                        struct skcipher_request* req) {
    struct bio_vec bv_in = bio_iter_iovec(ctx->bio_in, ctx->iter_in);
    struct bio_vec bv_out = bio_iter_iovec(ctx->bio_out, ctx->iter_out);
    struct scatterlist *sg_in, *sg_out;
    struct dm_crypt_request* dmreq;
    u8 *iv, *org_iv;
    __le64* sector;
    int r = 0;

    /* Reject unexpected unaligned bio. */
    if (unlikely(bv_in.bv_len & (cc->sector_size - 1)))
        return -EIO;

    dmreq = dmreq_of_req(cs, req);
    dmreq->iv_sector = ctx->cc_sector;
    if (test_bit(CRYPT_IV_LARGE_SECTORS, &cc->cipher_flags))
        dmreq->iv_sector >>= cc->sector_shift;
    dmreq->ctx = ctx;

    iv = iv_of_dmreq(cs, dmreq);
    org_iv = org_iv_of_dmreq(cs, dmreq);

    sector = org_sector_of_dmreq(cs, dmreq);
    *sector = cpu_to_le64(ctx->cc_sector - cc->iv_offset);

    /* For skcipher we use only the first sg item */
    sg_in = &dmreq->sg_in[0];
    sg_out = &dmreq->sg_out[0];

    sg_init_table(sg_in, 1);
    sg_set_page(sg_in, bv_in.bv_page, cc->sector_size, bv_in.bv_offset);

    sg_init_table(sg_out, 1);
    sg_set_page(sg_out, bv_out.bv_page, cc->sector_size, bv_out.bv_offset);

    if (cs->iv_gen_ops) {
        r = cs->iv_gen_ops->generator(cs, org_iv, dmreq);
        if (r < 0)
            return r;
        /* Data can be already preprocessed in generator */
        if (test_bit(CRYPT_ENCRYPT_PREPROCESS, &cc->cipher_flags))
            sg_in = sg_out;
        /* Working copy of IV, to be modified in crypto API */
        memcpy(iv, org_iv, cs->iv_size);
    }

    skcipher_request_set_crypt(req, sg_in, sg_out, cc->sector_size, iv);

    if (bio_data_dir(ctx->bio_in) == WRITE)
        r = crypto_skcipher_encrypt(req);
    else
        r = crypto_skcipher_decrypt(req);

    if (!r && cs->iv_gen_ops && cs->iv_gen_ops->post)
        r = cs->iv_gen_ops->post(cs, org_iv, dmreq);

    bio_advance_iter(ctx->bio_in, &ctx->iter_in, cc->sector_size);
    bio_advance_iter(ctx->bio_out, &ctx->iter_out, cc->sector_size);

    return r;
}

static void kcryptd_async_done(struct crypto_async_request* async_req,
                               int error);

static int crypt_alloc_req_skcipher(struct crypt_strategy* cs,
                                    struct convert_context* ctx) {
    unsigned key_index = ctx->cc_sector & (cs->tfms_count - 1);

    if (!ctx->req) {
        ctx->req = mempool_alloc(&cs->req_pool,
                                 in_interrupt() ? GFP_ATOMIC : GFP_NOIO);
        if (!ctx->req)
            return -ENOMEM;
    }

    skcipher_request_set_tfm(ctx->req, cs->cipher_tfm[key_index]);

    /*
     * Use REQ_MAY_BACKLOG so a cipher driver internally backlogs
     * requests if driver request queue is full.
     */
    skcipher_request_set_callback(ctx->req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                                  kcryptd_async_done,
                                  dmreq_of_req(cs, ctx->req));

    return 0;
}

static int crypt_alloc_req(struct crypt_strategy* cs,
                           struct convert_context* ctx) {
    return crypt_alloc_req_skcipher(cs, ctx);
}

static void crypt_free_req_skcipher(struct crypt_strategy* cs,
                                    struct skcipher_request* req,
                                    struct bio* base_bio) {
    struct dm_crypt_io* io = dm_per_bio_data(base_bio, cs->per_bio_data_size);

    if ((struct skcipher_request*)(io + 1) != req)
        mempool_free(req, &cs->req_pool);
}

static void crypt_free_req(struct crypt_strategy* cs,
                           void* req,
                           struct bio* base_bio) {
    crypt_free_req_skcipher(cs, req, base_bio);
}

/*
 * Encrypt / decrypt data from one bio to another one (can be the same one)
 */
static blk_status_t crypt_convert(struct crypt_config* cc,
                                  struct crypt_strategy* cs,
                                  struct convert_context* ctx,
                                  bool atomic,
                                  bool reset_pending) {
    unsigned int sector_step = cc->sector_size >> SECTOR_SHIFT;
    int r;

    /*
     * if reset_pending is set we are dealing with the bio for the first time,
     * else we're continuing to work on the previous bio, so don't mess with
     * the cc_pending counter
     */
    if (reset_pending)
        atomic_set(&ctx->cc_pending, 1);

    while (ctx->iter_in.bi_size && ctx->iter_out.bi_size) {
        r = crypt_alloc_req(cs, ctx);
        if (r) {
            complete(&ctx->restart);
            return BLK_STS_DEV_RESOURCE;
        }

        atomic_inc(&ctx->cc_pending);

        r = crypt_convert_block_skcipher(cc, cs, ctx, ctx->req);

        switch (r) {
            /*
             * The request was queued by a crypto driver
             * but the driver request queue is full, let's wait.
             */
            case -EBUSY:
                if (in_interrupt()) {
                    if (try_wait_for_completion(&ctx->restart)) {
                        /*
                         * we don't have to block to wait for completion,
                         * so proceed
                         */
                    } else {
                        /*
                         * we can't wait for completion without blocking
                         * exit and continue processing in a workqueue
                         */
                        ctx->req = NULL;
                        ctx->cc_sector += sector_step;
                        return BLK_STS_DEV_RESOURCE;
                    }
                } else {
                    wait_for_completion(&ctx->restart);
                }
                reinit_completion(&ctx->restart);
                fallthrough;
            /*
             * The request is queued and processed asynchronously,
             * completion function kcryptd_async_done() will be called.
             */
            case -EINPROGRESS:
                ctx->req = NULL;
                ctx->cc_sector += sector_step;
                continue;
            /*
             * The request was already processed (synchronously).
             */
            case 0:
                atomic_dec(&ctx->cc_pending);
                ctx->cc_sector += sector_step;
                if (!atomic)
                    cond_resched();
                continue;
            /*
             * There was a data integrity error.
             */
            case -EBADMSG:
                atomic_dec(&ctx->cc_pending);
                return BLK_STS_PROTECTION;
            /*
             * There was an error while processing the request.
             */
            default:
                atomic_dec(&ctx->cc_pending);
                return BLK_STS_IOERR;
        }
    }

    return 0;
}

static void crypt_free_buffer_pages(struct crypt_config* cc, struct bio* clone);

/*
 * Generate a new unfragmented bio with the given size
 * This should never violate the device limitations (but only because
 * max_segment_size is being constrained to PAGE_SIZE).
 *
 * This function may be called concurrently. If we allocate from the mempool
 * concurrently, there is a possibility of deadlock. For example, if we have
 * mempool of 256 pages, two processes, each wanting 256, pages allocate from
 * the mempool concurrently, it may deadlock in a situation where both processes
 * have allocated 128 pages and the mempool is exhausted.
 *
 * In order to avoid this scenario we allocate the pages under a mutex.
 *
 * In order to not degrade performance with excessive locking, we try
 * non-blocking allocations without a mutex first but on failure we fallback
 * to blocking allocations with a mutex.
 */
static struct bio* crypt_alloc_buffer(struct dm_crypt_io* io, unsigned size) {
    struct crypt_config* cc = io->cc;
    struct bio* clone;
    unsigned int nr_iovecs = (size + PAGE_SIZE - 1) >> PAGE_SHIFT;
    gfp_t gfp_mask = GFP_NOWAIT | __GFP_HIGHMEM;
    unsigned i, len, remaining_size;
    struct page* page;

retry:
    if (unlikely(gfp_mask & __GFP_DIRECT_RECLAIM))
        mutex_lock(&cc->bio_alloc_lock);

    clone = bio_alloc_bioset(GFP_NOIO, nr_iovecs, &cc->bs);
    if (!clone)
        goto out;

    clone_init(io, clone);

    remaining_size = size;

    for (i = 0; i < nr_iovecs; i++) {
        page = mempool_alloc(&cc->page_pool, gfp_mask);
        if (!page) {
            crypt_free_buffer_pages(cc, clone);
            bio_put(clone);
            gfp_mask |= __GFP_DIRECT_RECLAIM;
            goto retry;
        }

        len = (remaining_size > PAGE_SIZE) ? PAGE_SIZE : remaining_size;

        bio_add_page(clone, page, len, 0);

        remaining_size -= len;
    }

out:
    if (unlikely(gfp_mask & __GFP_DIRECT_RECLAIM))
        mutex_unlock(&cc->bio_alloc_lock);

    return clone;
}

static void crypt_free_buffer_pages(struct crypt_config* cc,
                                    struct bio* clone) {
    struct bio_vec* bv;
    struct bvec_iter_all iter_all;

    bio_for_each_segment_all(bv, clone, iter_all) {
        BUG_ON(!bv->bv_page);
        mempool_free(bv->bv_page, &cc->page_pool);
    }
}

static void crypt_io_init(struct dm_crypt_io* io,
                          struct crypt_config* cc,
                          struct crypt_strategy* cs,
                          struct bio* bio,
                          sector_t sector) {
    io->cc = cc;
    io->cs = cs;
    io->base_bio = bio;
    io->sector = sector;
    io->error = 0;
    io->ctx.req = NULL;
    atomic_set(&io->io_pending, 0);
}

static void crypt_inc_pending(struct dm_crypt_io* io) {
    atomic_inc(&io->io_pending);
}

static void kcryptd_io_bio_endio(struct work_struct* work) {
    struct dm_crypt_io* io = container_of(work, struct dm_crypt_io, work);
    bio_endio(io->base_bio);
}

/*
 * One of the bios was finished. Check for completion of
 * the whole request and correctly clean up the buffer.
 */
static void crypt_dec_pending(struct dm_crypt_io* io) {
    struct crypt_config* cc = io->cc;
    struct crypt_strategy* cs = io->cs;
    struct bio* base_bio = io->base_bio;
    blk_status_t error = io->error;

    if (!atomic_dec_and_test(&io->io_pending))
        return;

    if (io->ctx.req)
        crypt_free_req(cs, io->ctx.req, base_bio);

    base_bio->bi_status = error;

    /*
     * If we are running this function from our tasklet,
     * we can't call bio_endio() here, because it will call
     * clone_endio() from dm.c, which in turn will
     * free the current struct dm_crypt_io structure with
     * our tasklet. In this case we need to delay bio_endio()
     * execution to after the tasklet is done and dequeued.
     */
    if (tasklet_trylock(&io->tasklet)) {
        tasklet_unlock(&io->tasklet);
        bio_endio(base_bio);
        return;
    }

    INIT_WORK(&io->work, kcryptd_io_bio_endio);
    queue_work(cc->io_queue, &io->work);
}

/*
 * kcryptd/kcryptd_io:
 *
 * Needed because it would be very unwise to do decryption in an
 * interrupt context.
 *
 * kcryptd performs the actual encryption or decryption.
 *
 * kcryptd_io performs the IO submission.
 *
 * They must be separated as otherwise the final stages could be
 * starved by new requests which can block in the first stages due
 * to memory allocation.
 *
 * The work is done per CPU global for all dm-crypt instances.
 * They should not depend on each other and do not block.
 */
static void crypt_endio(struct bio* clone) {
    struct dm_crypt_io* io = clone->bi_private;
    struct crypt_config* cc = io->cc;
    unsigned rw = bio_data_dir(clone);
    blk_status_t error;

    /*
     * free the processed pages
     */
    if (rw == WRITE)
        crypt_free_buffer_pages(cc, clone);

    error = clone->bi_status;
    bio_put(clone);

    if (rw == READ && !error) {
        kcryptd_queue_crypt(io);
        return;
    }

    if (unlikely(error))
        io->error = error;

    crypt_dec_pending(io);
}

static void clone_init(struct dm_crypt_io* io, struct bio* clone) {
    struct crypt_config* cc = io->cc;

    clone->bi_private = io;
    clone->bi_end_io = crypt_endio;
    bio_set_dev(clone, cc->dev->bdev);
    clone->bi_opf = io->base_bio->bi_opf;
}

static int kcryptd_io_read(struct dm_crypt_io* io, gfp_t gfp) {
    struct crypt_config* cc = io->cc;
    struct crypt_strategy* cs = io->cs;
    struct bio* clone;
    struct sync_io* sync_io;

    /*
     * We need the original biovec array in order to decrypt
     * the whole bio data *afterwards* -- thanks to immutable
     * biovecs we don't need to worry about the block layer
     * modifying the biovec array; so leverage bio_clone_fast().
     */
    clone = bio_clone_fast(io->base_bio, gfp, &cc->bs);
    if (!clone)
        return 1;

    crypt_inc_pending(io);

    clone_init(io, clone);
    clone->bi_iter.bi_sector = cc->start + io->sector;

    // map bio using regrion mapper
    sync_io = bio_region_map(cc->rmap, clone);
    if (sync_io != NULL) {
        // encrypt with new strategy then submit
        int ret;
        struct convert_context ctx;

        crypt_convert_init(cc, &ctx, sync_io->base_io, sync_io->base_io,
                           io->sector);
        ret = crypt_convert(cc, cs, &ctx,
                            test_bit(DM_CRYPT_NO_WRITE_WORKQUEUE, &cc->flags),
                            true);
        if (ret) {
            bio_put(clone);
            return 1;
        }
        submit_bio_noacct(sync_io->base_io);
    }

    submit_bio_noacct(clone);
    return 0;
}

static void kcryptd_io_read_work(struct work_struct* work) {
    struct dm_crypt_io* io = container_of(work, struct dm_crypt_io, work);

    crypt_inc_pending(io);
    if (kcryptd_io_read(io, GFP_NOIO))
        io->error = BLK_STS_RESOURCE;
    crypt_dec_pending(io);
}

static void kcryptd_queue_read(struct dm_crypt_io* io) {
    struct crypt_config* cc = io->cc;

    INIT_WORK(&io->work, kcryptd_io_read_work);
    queue_work(cc->io_queue, &io->work);
}

static void kcryptd_io_write(struct dm_crypt_io* io) {
    struct crypt_config* cc = io->cc;
    struct sync_io* sync_io;
    struct bio* clone = io->ctx.bio_out;

    // map bio using regrion mapper
    sync_io = bio_region_map(cc->rmap, clone);
    if (sync_io != NULL) {
        // submit directly
        submit_bio_noacct(sync_io->base_io);
    }

    submit_bio_noacct(clone);
}

#define crypt_io_from_node(node) rb_entry((node), struct dm_crypt_io, rb_node)

static int dmcrypt_write(void* data) {
    struct crypt_config* cc = data;
    struct dm_crypt_io* io;

    while (1) {
        struct rb_root write_tree;
        struct blk_plug plug;

        spin_lock_irq(&cc->write_thread_lock);
    continue_locked:

        if (!RB_EMPTY_ROOT(&cc->write_tree))
            goto pop_from_list;

        set_current_state(TASK_INTERRUPTIBLE);

        spin_unlock_irq(&cc->write_thread_lock);

        if (unlikely(kthread_should_stop())) {
            set_current_state(TASK_RUNNING);
            break;
        }

        schedule();

        set_current_state(TASK_RUNNING);
        spin_lock_irq(&cc->write_thread_lock);
        goto continue_locked;

    pop_from_list:
        write_tree = cc->write_tree;
        cc->write_tree = RB_ROOT;
        spin_unlock_irq(&cc->write_thread_lock);

        BUG_ON(rb_parent(write_tree.rb_node));

        /*
         * Note: we cannot walk the tree here with rb_next because
         * the structures may be freed when kcryptd_io_write is called.
         */
        blk_start_plug(&plug);
        do {
            io = crypt_io_from_node(rb_first(&write_tree));
            rb_erase(&io->rb_node, &write_tree);
            kcryptd_io_write(io);
        } while (!RB_EMPTY_ROOT(&write_tree));
        blk_finish_plug(&plug);
    }
    return 0;
}

static void kcryptd_crypt_write_io_submit(struct dm_crypt_io* io, int async) {
    struct bio* clone = io->ctx.bio_out;
    struct crypt_config* cc = io->cc;
    unsigned long flags;
    sector_t sector;
    struct rb_node **rbp, *parent;

    if (unlikely(io->error)) {
        crypt_free_buffer_pages(cc, clone);
        bio_put(clone);
        crypt_dec_pending(io);
        return;
    }

    /* crypt_convert should have filled the clone bio */
    BUG_ON(io->ctx.iter_out.bi_size);

    clone->bi_iter.bi_sector = cc->start + io->sector;

    if ((likely(!async) && test_bit(DM_CRYPT_NO_OFFLOAD, &cc->flags)) ||
        test_bit(DM_CRYPT_NO_WRITE_WORKQUEUE, &cc->flags)) {
        submit_bio_noacct(clone);
        return;
    }

    spin_lock_irqsave(&cc->write_thread_lock, flags);
    if (RB_EMPTY_ROOT(&cc->write_tree))
        wake_up_process(cc->write_thread);
    rbp = &cc->write_tree.rb_node;
    parent = NULL;
    sector = io->sector;
    while (*rbp) {
        parent = *rbp;
        if (sector < crypt_io_from_node(parent)->sector)
            rbp = &(*rbp)->rb_left;
        else
            rbp = &(*rbp)->rb_right;
    }
    rb_link_node(&io->rb_node, parent, rbp);
    rb_insert_color(&io->rb_node, &cc->write_tree);
    spin_unlock_irqrestore(&cc->write_thread_lock, flags);
}

static bool kcryptd_crypt_write_inline(struct crypt_config* cc,
                                       struct convert_context* ctx)

{
    if (!test_bit(DM_CRYPT_WRITE_INLINE, &cc->flags))
        return false;

    /*
     * Note: zone append writes (REQ_OP_ZONE_APPEND) do not have ordering
     * constraints so they do not need to be issued inline by
     * kcryptd_crypt_write_convert().
     */
    switch (bio_op(ctx->bio_in)) {
        case REQ_OP_WRITE:
        case REQ_OP_WRITE_SAME:
        case REQ_OP_WRITE_ZEROES:
            return true;
        default:
            return false;
    }
}

static void kcryptd_crypt_write_continue(struct work_struct* work) {
    struct dm_crypt_io* io = container_of(work, struct dm_crypt_io, work);
    struct crypt_config* cc = io->cc;
    struct crypt_strategy* cs = io->cs;
    struct convert_context* ctx = &io->ctx;
    int crypt_finished;
    sector_t sector = io->sector;
    blk_status_t r;

    wait_for_completion(&ctx->restart);
    reinit_completion(&ctx->restart);

    r = crypt_convert(cc, cs, &io->ctx, true, false);
    if (r)
        io->error = r;
    crypt_finished = atomic_dec_and_test(&ctx->cc_pending);
    if (!crypt_finished && kcryptd_crypt_write_inline(cc, ctx)) {
        /* Wait for completion signaled by kcryptd_async_done() */
        wait_for_completion(&ctx->restart);
        crypt_finished = 1;
    }

    /* Encryption was already finished, submit io now */
    if (crypt_finished) {
        kcryptd_crypt_write_io_submit(io, 0);
        io->sector = sector;
    }

    crypt_dec_pending(io);
}

static void kcryptd_crypt_write_convert(struct dm_crypt_io* io) {
    struct crypt_config* cc = io->cc;
    struct crypt_strategy* cs = io->cs;
    struct convert_context* ctx = &io->ctx;
    struct bio* clone;
    int crypt_finished;
    sector_t sector = io->sector;
    blk_status_t r;

    /*
     * Prevent io from disappearing until this function completes.
     */
    crypt_inc_pending(io);
    crypt_convert_init(cc, ctx, NULL, io->base_bio, sector);

    clone = crypt_alloc_buffer(io, io->base_bio->bi_iter.bi_size);
    if (unlikely(!clone)) {
        io->error = BLK_STS_IOERR;
        goto dec;
    }

    io->ctx.bio_out = clone;
    io->ctx.iter_out = clone->bi_iter;

    sector += bio_sectors(clone);

    crypt_inc_pending(io);
    r = crypt_convert(cc, cs, ctx,
                      test_bit(DM_CRYPT_NO_WRITE_WORKQUEUE, &cc->flags), true);
    /*
     * Crypto API backlogged the request, because its queue was full
     * and we're in softirq context, so continue from a workqueue
     * (TODO: is it actually possible to be in softirq in the write path?)
     */
    if (r == BLK_STS_DEV_RESOURCE) {
        INIT_WORK(&io->work, kcryptd_crypt_write_continue);
        queue_work(cc->crypt_queue, &io->work);
        return;
    }
    if (r)
        io->error = r;
    crypt_finished = atomic_dec_and_test(&ctx->cc_pending);
    if (!crypt_finished && kcryptd_crypt_write_inline(cc, ctx)) {
        /* Wait for completion signaled by kcryptd_async_done() */
        wait_for_completion(&ctx->restart);
        crypt_finished = 1;
    }

    /* Encryption was already finished, submit io now */
    if (crypt_finished) {
        kcryptd_crypt_write_io_submit(io, 0);
        io->sector = sector;
    }

dec:
    crypt_dec_pending(io);
}

static void kcryptd_crypt_read_done(struct dm_crypt_io* io) {
    crypt_dec_pending(io);
}

static void kcryptd_crypt_read_continue(struct work_struct* work) {
    struct dm_crypt_io* io = container_of(work, struct dm_crypt_io, work);
    struct crypt_config* cc = io->cc;
    struct crypt_strategy* cs = io->cs;
    blk_status_t r;

    wait_for_completion(&io->ctx.restart);
    reinit_completion(&io->ctx.restart);

    r = crypt_convert(cc, cs, &io->ctx, true, false);
    if (r)
        io->error = r;

    if (atomic_dec_and_test(&io->ctx.cc_pending))
        kcryptd_crypt_read_done(io);

    crypt_dec_pending(io);
}

static void kcryptd_crypt_read_convert(struct dm_crypt_io* io) {
    struct crypt_config* cc = io->cc;
    struct crypt_strategy* cs = io->cs;
    blk_status_t r;

    crypt_inc_pending(io);

    crypt_convert_init(cc, &io->ctx, io->base_bio, io->base_bio, io->sector);

    r = crypt_convert(cc, cs, &io->ctx,
                      test_bit(DM_CRYPT_NO_READ_WORKQUEUE, &cc->flags), true);
    /*
     * Crypto API backlogged the request, because its queue was full
     * and we're in softirq context, so continue from a workqueue
     */
    if (r == BLK_STS_DEV_RESOURCE) {
        INIT_WORK(&io->work, kcryptd_crypt_read_continue);
        queue_work(cc->crypt_queue, &io->work);
        return;
    }
    if (r)
        io->error = r;

    if (atomic_dec_and_test(&io->ctx.cc_pending))
        kcryptd_crypt_read_done(io);

    crypt_dec_pending(io);
}

static void kcryptd_async_done(struct crypto_async_request* async_req,
                               int error) {
    struct dm_crypt_request* dmreq = async_req->data;
    struct convert_context* ctx = dmreq->ctx;
    struct dm_crypt_io* io = container_of(ctx, struct dm_crypt_io, ctx);
    struct crypt_config* cc = io->cc;
    struct crypt_strategy* cs = io->cs;

    /*
     * A request from crypto driver backlog is going to be processed now,
     * finish the completion and continue in crypt_convert().
     * (Callback will be called for the second time for this request.)
     */
    if (error == -EINPROGRESS) {
        complete(&ctx->restart);
        return;
    }

    if (!error && cs->iv_gen_ops && cs->iv_gen_ops->post)
        error = cs->iv_gen_ops->post(cs, org_iv_of_dmreq(cs, dmreq), dmreq);

    if (error == -EBADMSG) {
        io->error = BLK_STS_PROTECTION;
    } else if (error < 0)
        io->error = BLK_STS_IOERR;

    crypt_free_req(cs, req_of_dmreq(cs, dmreq), io->base_bio);

    if (!atomic_dec_and_test(&ctx->cc_pending))
        return;

    /*
     * The request is fully completed: for inline writes, let
     * kcryptd_crypt_write_convert() do the IO submission.
     */
    if (bio_data_dir(io->base_bio) == READ) {
        kcryptd_crypt_read_done(io);
        return;
    }

    if (kcryptd_crypt_write_inline(cc, ctx)) {
        complete(&ctx->restart);
        return;
    }

    kcryptd_crypt_write_io_submit(io, 1);
}

static void kcryptd_crypt(struct work_struct* work) {
    struct dm_crypt_io* io = container_of(work, struct dm_crypt_io, work);

    if (bio_data_dir(io->base_bio) == READ)
        kcryptd_crypt_read_convert(io);
    else
        kcryptd_crypt_write_convert(io);
}

static void kcryptd_crypt_tasklet(unsigned long work) {
    kcryptd_crypt((struct work_struct*)work);
}

static void kcryptd_queue_crypt(struct dm_crypt_io* io) {
    struct crypt_config* cc = io->cc;

    if ((bio_data_dir(io->base_bio) == READ &&
         test_bit(DM_CRYPT_NO_READ_WORKQUEUE, &cc->flags)) ||
        (bio_data_dir(io->base_bio) == WRITE &&
         test_bit(DM_CRYPT_NO_WRITE_WORKQUEUE, &cc->flags))) {
        /*
         * in_hardirq(): Crypto API's skcipher_walk_first() refuses to work in
         * hard IRQ context. irqs_disabled(): the kernel may run some IO
         * completion from the idle thread, but it is being executed with irqs
         * disabled.
         */
        if (in_hardirq() || irqs_disabled()) {
            tasklet_init(&io->tasklet, kcryptd_crypt_tasklet,
                         (unsigned long)&io->work);
            tasklet_schedule(&io->tasklet);
            return;
        }

        kcryptd_crypt(&io->work);
        return;
    }

    INIT_WORK(&io->work, kcryptd_crypt);
    queue_work(cc->crypt_queue, &io->work);
}

static void crypt_free_tfms_skcipher(struct crypt_strategy* cs) {
    unsigned i;

    if (!cs->cipher_tfm)
        return;

    for (i = 0; i < cs->tfms_count; i++)
        if (cs->cipher_tfm[i] && !IS_ERR(cs->cipher_tfm[i])) {
            crypto_free_skcipher(cs->cipher_tfm[i]);
            cs->cipher_tfm[i] = NULL;
        }

    kfree(cs->cipher_tfm);
    cs->cipher_tfm = NULL;
}

static void crypt_free_tfms(struct crypt_strategies* cs) {
    crypt_free_tfms_skcipher(&cs->read_write_efficient);
    crypt_free_tfms_skcipher(&cs->write_most_efficient);
    crypt_free_tfms_skcipher(&cs->read_most_efficient);
    crypt_free_tfms_skcipher(&cs->default_strategy);
}

static int crypt_alloc_tfms_skcipher(struct crypt_strategy* cs,
                                     char* ciphermode) {
    unsigned i;
    int err;

    cs->cipher_tfm =
        kcalloc(cs->tfms_count, sizeof(struct crypto_skcipher*), GFP_KERNEL);
    if (!cs->cipher_tfm)
        return -ENOMEM;

    for (i = 0; i < cs->tfms_count; i++) {
        cs->cipher_tfm[i] =
            crypto_alloc_skcipher(ciphermode, 0, CRYPTO_ALG_ALLOCATES_MEMORY);
        if (IS_ERR(cs->cipher_tfm[i])) {
            err = PTR_ERR(cs->cipher_tfm[i]);
            crypt_free_tfms_skcipher(cs);
            return err;
        }
    }

    /*
     * dm-crypt performance can vary greatly depending on which crypto
     * algorithm implementation is used.  Help people debug performance
     * problems by logging the ->cra_driver_name.
     */
    DMDEBUG_LIMIT("%s using implementation \"%s\"", ciphermode,
                  crypto_skcipher_alg(cs->cipher_tfm[0])->base.cra_driver_name);
    return 0;
}

static unsigned crypt_subkey_size(struct crypt_config* cc,
                                  struct crypt_strategy* cs) {
    return (cc->key_size) >> ilog2(cs->tfms_count);
}

static int crypt_setkey(struct crypt_config* cc, struct crypt_strategy* cs) {
    unsigned subkey_size;
    int err = 0, i, r;

    /* Ignore extra keys (which are used for IV etc) */
    subkey_size = crypt_subkey_size(cc, cs);
    for (i = 0; i < cs->tfms_count; i++) {
        r = crypto_skcipher_setkey(cs->cipher_tfm[i],
                                   cc->key + (i * subkey_size), subkey_size);
        if (r)
            err = r;
    }

    return err;
}

static int get_key_size(char** key_string) {
    return strlen(*key_string) >> 1;
}

static int crypt_set_key(struct crypt_config* cc, char* key) {
    int r = -EINVAL;
    int key_string_len = strlen(key);

    /* Hyphen (which gives a key_size of zero) means there is no key. */
    if (!cc->key_size && strcmp(key, "-"))
        goto out;

    /* clear the flag since following operations may invalidate previously valid
     * key */
    clear_bit(DM_CRYPT_KEY_VALID, &cc->flags);

    /* wipe references to any kernel keyring key */
    kfree_sensitive(cc->key_string);
    cc->key_string = NULL;

    /* Decode key from its hex representation. */
    if (cc->key_size && hex2bin(cc->key, key, cc->key_size) < 0)
        goto out;

    r = crypt_setkey(cc, &cc->crypt_strategies.read_write_efficient);
    r |= crypt_setkey(cc, &cc->crypt_strategies.read_most_efficient);
    r |= crypt_setkey(cc, &cc->crypt_strategies.write_most_efficient);
    r |= crypt_setkey(cc, &cc->crypt_strategies.default_strategy);
    if (!r)
        set_bit(DM_CRYPT_KEY_VALID, &cc->flags);

out:
    /* Hex key string not needed after here, so wipe it. */
    memset(key, '0', key_string_len);

    return r;
}

static int crypt_wipe_key(struct crypt_config* cc) {
    struct crypt_strategies* cs = &cc->crypt_strategies;
    struct crypt_strategy* strategy;
    int r;

    clear_bit(DM_CRYPT_KEY_VALID, &cc->flags);
    get_random_bytes(&cc->key, cc->key_size);

    /* Wipe IV private keys */

    strategy = &cs->read_write_efficient;
    if (strategy->iv_gen_ops && strategy->iv_gen_ops->wipe) {
        r = strategy->iv_gen_ops->wipe(strategy);
        if (r)
            return r;
    }

    strategy = &cs->read_most_efficient;
    if (strategy->iv_gen_ops && strategy->iv_gen_ops->wipe) {
        r = strategy->iv_gen_ops->wipe(strategy);
        if (r)
            return r;
    }

    strategy = &cs->write_most_efficient;
    if (strategy->iv_gen_ops && strategy->iv_gen_ops->wipe) {
        r = strategy->iv_gen_ops->wipe(strategy);
        if (r)
            return r;
    }

    strategy = &cs->default_strategy;
    if (strategy->iv_gen_ops && strategy->iv_gen_ops->wipe) {
        r = strategy->iv_gen_ops->wipe(strategy);
        if (r)
            return r;
    }

    kfree_sensitive(cc->key_string);
    cc->key_string = NULL;
    r = crypt_setkey(cc, &cs->read_write_efficient) |
        crypt_setkey(cc, &cs->read_most_efficient) |
        crypt_setkey(cc, &cs->write_most_efficient) |
        crypt_setkey(cc, &cs->default_strategy);
    memset(&cc->key, 0, cc->key_size * sizeof(u8));

    return r;
}

static void crypt_calculate_pages_per_client(void) {
    unsigned long pages =
        (totalram_pages() - totalhigh_pages()) * DM_CRYPT_MEMORY_PERCENT / 100;

    if (!dm_crypt_clients_n)
        return;

    pages /= dm_crypt_clients_n;
    if (pages < DM_CRYPT_MIN_PAGES_PER_CLIENT)
        pages = DM_CRYPT_MIN_PAGES_PER_CLIENT;
    dm_crypt_pages_per_client = pages;
}

static void* crypt_page_alloc(gfp_t gfp_mask, void* pool_data) {
    struct crypt_config* cc = pool_data;
    struct page* page;

    /*
     * Note, percpu_counter_read_positive() may over (and under) estimate
     * the current usage by at most (batch - 1) * num_online_cpus() pages,
     * but avoids potential spinlock contention of an exact result.
     */
    if (unlikely(percpu_counter_read_positive(&cc->n_allocated_pages) >=
                 dm_crypt_pages_per_client) &&
        likely(gfp_mask & __GFP_NORETRY))
        return NULL;

    page = alloc_page(gfp_mask);
    if (likely(page != NULL))
        percpu_counter_add(&cc->n_allocated_pages, 1);

    return page;
}

static void crypt_page_free(void* page, void* pool_data) {
    struct crypt_config* cc = pool_data;

    __free_page(page);
    percpu_counter_sub(&cc->n_allocated_pages, 1);
}

static void crypt_dtr(struct dm_target* ti) {
    struct crypt_config* cc = ti->private;
    struct crypt_strategies* cs = &cc->crypt_strategies;
    struct crypt_strategy* strategy;

    ti->private = NULL;

    if (!cc)
        return;

    if (cc->write_thread)
        kthread_stop(cc->write_thread);

    if (cc->io_queue)
        destroy_workqueue(cc->io_queue);
    if (cc->crypt_queue)
        destroy_workqueue(cc->crypt_queue);

    crypt_free_tfms(cs);

    bioset_exit(&cc->bs);

    mempool_exit(&cc->page_pool);
    mempool_exit(&cs->read_write_efficient.req_pool);
    mempool_exit(&cs->write_most_efficient.req_pool);
    mempool_exit(&cs->read_most_efficient.req_pool);
    mempool_exit(&cs->default_strategy.req_pool);

    WARN_ON(percpu_counter_sum(&cc->n_allocated_pages) != 0);
    percpu_counter_destroy(&cc->n_allocated_pages);

    strategy = &cs->read_write_efficient;
    if (strategy->iv_gen_ops && strategy->iv_gen_ops->dtr)
        strategy->iv_gen_ops->dtr(strategy);
    strategy = &cs->read_most_efficient;
    if (strategy->iv_gen_ops && strategy->iv_gen_ops->dtr)
        strategy->iv_gen_ops->dtr(strategy);
    strategy = &cs->write_most_efficient;
    if (strategy->iv_gen_ops && strategy->iv_gen_ops->dtr)
        strategy->iv_gen_ops->dtr(strategy);
    strategy = &cs->default_strategy;
    if (strategy->iv_gen_ops && strategy->iv_gen_ops->dtr)
        strategy->iv_gen_ops->dtr(strategy);

    if (cc->dev)
        dm_put_device(ti, cc->dev);

    kfree_sensitive(cs->read_write_efficient.cipher_string);
    kfree_sensitive(cs->write_most_efficient.cipher_string);
    kfree_sensitive(cs->read_most_efficient.cipher_string);
    kfree_sensitive(cs->default_strategy.cipher_string);

    kfree_sensitive(cc->key_string);

    mutex_destroy(&cc->bio_alloc_lock);

    dev_destroy_region_mapper(cc->rmap);

    /* Must zero key material before freeing */

    // FIXME: memory leaks, but code below will cause kernel panic, how to fix?
    // kfree_sensitive(cc)；
    kfree(cc);

    spin_lock(&dm_crypt_clients_lock);
    WARN_ON(!dm_crypt_clients_n);
    dm_crypt_clients_n--;
    crypt_calculate_pages_per_client();
    spin_unlock(&dm_crypt_clients_lock);
}

static int crypt_ctr_ivmode(struct dm_target* ti) {
    struct crypt_config* cc = ti->private;
    struct crypt_strategies* cs = &cc->crypt_strategies;

    /* 1. read write efficient crypt strategy for read-cold-write-hot region
     * chunks */

    // no iv mode

    /* 2. write most efficient crypt strategy for read-cold-write-hot region
     * chunks */

    cs->write_most_efficient.iv_size =
        crypto_skcipher_ivsize(cs->write_most_efficient.cipher_tfm[0]);
    if (cs->write_most_efficient.iv_size) {
        /* at least a 64 bit sector number should fit in our buffer */
        cs->write_most_efficient.iv_size =
            max(cs->write_most_efficient.iv_size,
                (unsigned int)(sizeof(u64) / sizeof(u8)));
    }
    cs->write_most_efficient.iv_gen_ops = &crypt_iv_essiv_ops;

    /* 3. read most efficient crypt strategy for read-hot-write-cold region
     * chunks */

    cs->read_most_efficient.iv_size =
        crypto_skcipher_ivsize(cs->read_most_efficient.cipher_tfm[0]);
    if (cs->read_most_efficient.iv_size) {
        /* at least a 64 bit sector number should fit in our buffer */
        cs->read_most_efficient.iv_size =
            max(cs->read_most_efficient.iv_size,
                (unsigned int)(sizeof(u64) / sizeof(u8)));
    }
    cs->read_most_efficient.iv_gen_ops = &crypt_iv_essiv_ops;

    /* 4. default crypt strategy for read-cold-write-cold region chunks */

    // no iv mode

    return 0;
}

static int crypt_ctr_dmreq_each(struct dm_target* ti,
                                struct crypt_strategy* cs) {
    unsigned int align_mask;
    size_t iv_size_padding, additional_req_size;
    int ret;

    cs->dmreq_start = sizeof(struct skcipher_request);
    cs->dmreq_start += crypto_skcipher_reqsize(cs->cipher_tfm[0]);
    align_mask = crypto_skcipher_alignmask(cs->cipher_tfm[0]);
    cs->dmreq_start =
        ALIGN(cs->dmreq_start, __alignof__(struct dm_crypt_request));

    if (align_mask < CRYPTO_MINALIGN) {
        /* Allocate the padding exactly */
        iv_size_padding =
            -(cs->dmreq_start + sizeof(struct dm_crypt_request)) & align_mask;
    } else {
        /*
         * If the cipher requires greater alignment than kmalloc
         * alignment, we don't know the exact position of the
         * initialization vector. We must assume worst case.
         */
        iv_size_padding = align_mask;
    }

    /*  ...| IV + padding | original IV | original sec. number | bio tag offset
     * | */
    additional_req_size = sizeof(struct dm_crypt_request) + iv_size_padding +
                          cs->iv_size + cs->iv_size + sizeof(uint64_t) +
                          sizeof(unsigned int);

    ret = mempool_init_kmalloc_pool(&cs->req_pool, MIN_IOS,
                                    cs->dmreq_start + additional_req_size);
    if (ret) {
        ti->error = "Cannot allocate crypt request mempool";
    }

    cs->per_bio_data_size = ti->per_io_data_size = ALIGN(
        sizeof(struct dm_crypt_io) + cs->dmreq_start + additional_req_size,
        ARCH_KMALLOC_MINALIGN);

    return ret;
}

static int crypt_ctr_dmreq(struct dm_target* ti) {
    struct crypt_config* cc = ti->private;
    struct crypt_strategies* cs = &cc->crypt_strategies;
    int ret;

    /* 1. read write efficient crypt strategy for read-cold-write-hot region
     * chunks */
    ret = crypt_ctr_dmreq_each(ti, &cs->read_write_efficient);
    if (ret < 0)
        return ret;

    /* 2. write most efficient crypt strategy for read-cold-write-hot region
     * chunks */
    ret = crypt_ctr_dmreq_each(ti, &cs->write_most_efficient);
    if (ret < 0)
        return ret;

    /* 3. read most efficient crypt strategy for read-hot-write-cold region
     * chunks */
    ret = crypt_ctr_dmreq_each(ti, &cs->read_most_efficient);
    if (ret < 0)
        return ret;

    /* 4. default crypt strategy for read-cold-write-cold region chunks */
    ret = crypt_ctr_dmreq_each(ti, &cs->default_strategy);
    if (ret < 0)
        return ret;

    return ret;
}

static int crypt_ctr_crypt_strategies(struct dm_target* ti, char* key) {
    struct crypt_config* cc = ti->private;
    struct crypt_strategies* cs = &cc->crypt_strategies;
    int ret = -EINVAL;

    cc->key_parts = 1;

    /* 1. read write efficient crypt strategy for read-cold-write-hot region
     * chunks */

    cs->read_write_efficient.tfms_count = 1;
    /* Allocate cipher */
    ret = crypt_alloc_tfms_skcipher(&cs->read_write_efficient, "xts(aes)");
    if (ret < 0) {
        ti->error = "Error allocating crypto tfm";
        return ret;
    }
    cs->read_write_efficient.iv_size =
        crypto_skcipher_ivsize(any_tfm(&cs->read_write_efficient));

    /* 2. write most efficient crypt strategy for read-cold-write-hot region
     * chunks */

    cs->write_most_efficient.tfms_count = 1;
    /* Allocate cipher */
    ret = crypt_alloc_tfms_skcipher(&cs->write_most_efficient,
                                    "essiv(cbc(aes),sha256)");
    if (ret < 0) {
        ti->error = "Error allocating crypto tfm";
        return ret;
    }
    cs->write_most_efficient.iv_size =
        crypto_skcipher_ivsize(any_tfm(&cs->write_most_efficient));

    /* 3. read most efficient crypt strategy for read-hot-write-cold region
     * chunks */

    cs->read_most_efficient.tfms_count = 1;
    /* Allocate cipher */
    ret = crypt_alloc_tfms_skcipher(&cs->read_most_efficient,
                                    "essiv(cbc(aes),sha256)");
    if (ret < 0) {
        ti->error = "Error allocating crypto tfm";
        return ret;
    }
    cs->read_most_efficient.iv_size =
        crypto_skcipher_ivsize(any_tfm(&cs->read_most_efficient));

    /* 4. default crypt strategy for read-cold-write-cold region chunks */
    cs->default_strategy.tfms_count = 1;
    /* Allocate cipher */
    ret = crypt_alloc_tfms_skcipher(&cs->default_strategy, "ecb(aes)");
    if (ret < 0) {
        ti->error = "Error allocating crypto tfm";
        return ret;
    }
    cs->default_strategy.iv_size =
        crypto_skcipher_ivsize(any_tfm(&cs->default_strategy));

    return 0;
}

static int crypt_ctr_cipher(struct dm_target* ti, char* key) {
    struct crypt_config* cc = ti->private;
    int ret;

    ret = crypt_ctr_crypt_strategies(ti, key);
    if (ret < 0)
        return ret;

    /* Initialize and set key */
    ret = crypt_set_key(cc, key);
    if (ret < 0) {
        ti->error = "Error decoding and setting key";
        return ret;
    }

    /* Initialize IV */
    ret = crypt_ctr_ivmode(ti);
    if (ret < 0)
        return ret;

    /* wipe the kernel key payload copy */
    if (cc->key_string)
        memset(cc->key, 0, cc->key_size * sizeof(u8));

    ret = crypt_ctr_dmreq(ti);
    if (ret < 0) {
        ti->error = "Error allocating dmreq";
        return ret;
    }

    return ret;
}

#ifdef CONFIG_BLK_DEV_ZONED
static int crypt_report_zones(struct dm_target* ti,
                              struct dm_report_zones_args* args,
                              unsigned int nr_zones) {
    struct crypt_config* cc = ti->private;

    return dm_report_zones(cc->dev->bdev, cc->start,
                           cc->start + dm_target_offset(ti, args->next_sector),
                           args, nr_zones);
}
#else
#define crypt_report_zones NULL
#endif

/*
 * Construct an encryption mapping:
 * `dmsetup create <new device name> --tables <start sector> <end sector>
 * <target name> <target parameters>`,
 * which, parameters: <key> <iv_offset> <dev_path> <meta_start> <data_start>
 *
 * Each line of the table specifies a single target and is of the form:
 * > logical_start_sector num_sectors target_type target_args
 * refer to: https://man7.org/linux/man-pages/man8/dmsetup.8.html
 */
static int crypt_ctr(struct dm_target* ti, unsigned int argc, char** argv) {
    struct crypt_config* cc;
    const char* devname = dm_table_device_name(ti->table);
    int key_size;
    unsigned long long tmpll;
    int ret;
    char dummy;

    if (argc < 5) {
        ti->error = "Not enough arguments";
        return -EINVAL;
    }

    key_size = get_key_size(&argv[0]);
    if (key_size < 0) {
        ti->error = "Cannot parse key size";
        return -EINVAL;
    }

    cc = kzalloc(struct_size(cc, key, key_size), GFP_KERNEL);
    if (!cc) {
        ti->error = "Cannot allocate encryption context";
        return -ENOMEM;
    }
    cc->key_size = key_size;
    cc->sector_size = (1 << SECTOR_SHIFT);
    cc->sector_shift = 0;

    ti->private = cc;

    spin_lock(&dm_crypt_clients_lock);
    dm_crypt_clients_n++;
    crypt_calculate_pages_per_client();
    spin_unlock(&dm_crypt_clients_lock);

    ret = percpu_counter_init(&cc->n_allocated_pages, 0, GFP_KERNEL);
    if (ret < 0)
        goto bad;

    /* WARN: we remove optional args in dm-security */

    /* Set up built-in cipher strategies */
    ret = crypt_ctr_cipher(ti, argv[0]);
    if (ret < 0)
        goto bad;

    ret = mempool_init(&cc->page_pool, BIO_MAX_VECS, crypt_page_alloc,
                       crypt_page_free, cc);
    if (ret) {
        ti->error = "Cannot allocate page mempool";
        goto bad;
    }

    ret = bioset_init(&cc->bs, MIN_IOS, 0, BIOSET_NEED_BVECS);
    if (ret) {
        ti->error = "Cannot allocate crypt bioset";
        goto bad;
    }

    mutex_init(&cc->bio_alloc_lock);

    ret = -EINVAL;
    if ((sscanf(argv[1], "%llu%c", &tmpll, &dummy) != 1) ||
        (tmpll & ((cc->sector_size >> SECTOR_SHIFT) - 1))) {
        ti->error = "Invalid iv_offset sector";
        goto bad;
    }
    cc->iv_offset = tmpll;

    ret = dm_get_device(ti, argv[2], dm_table_get_mode(ti->table), &cc->dev);
    if (ret) {
        ti->error = "Device lookup failed";
        goto bad;
    }

    ret = -EINVAL;
    if (sscanf(argv[4], "%llu%c", &tmpll, &dummy) != 1 ||
        tmpll != (sector_t)tmpll) {
        ti->error = "Invalid device sector";
        goto bad;
    }
    cc->start = tmpll;

    /* create dev_region_mapper */
    ret = -EINVAL;
    if (sscanf(argv[3], "%llu%c", &tmpll, &dummy) != 1 ||
        tmpll != (sector_t)tmpll) {
        ti->error = "Invalid device sector";
        goto bad;
    }

    cc->rmap = dev_create_region_mapper(devname, cc->dev->bdev->bd_dev, tmpll,
                                        cc->start - tmpll, cc->start, ti->len);
    if (!cc->rmap) {
        ti->error = "Cannot create region mapper";
        goto bad;
    }

    /* WARN: we remove zone and integrity here (which used in dm-crypt) */

    ret = -ENOMEM;
    cc->io_queue = alloc_workqueue("kcryptd_io/%s", WQ_MEM_RECLAIM, 1, devname);
    if (!cc->io_queue) {
        ti->error = "Couldn't create kcryptd io queue";
        goto bad;
    }

    if (test_bit(DM_CRYPT_SAME_CPU, &cc->flags))
        cc->crypt_queue = alloc_workqueue(
            "kcryptd/%s", WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM, 1, devname);
    else
        cc->crypt_queue = alloc_workqueue(
            "kcryptd/%s", WQ_CPU_INTENSIVE | WQ_MEM_RECLAIM | WQ_UNBOUND,
            num_online_cpus(), devname);
    if (!cc->crypt_queue) {
        ti->error = "Couldn't create kcryptd queue";
        goto bad;
    }

    spin_lock_init(&cc->write_thread_lock);
    cc->write_tree = RB_ROOT;

    cc->write_thread =
        kthread_create(dmcrypt_write, cc, "dmcrypt_write/%s", devname);
    if (IS_ERR(cc->write_thread)) {
        ret = PTR_ERR(cc->write_thread);
        cc->write_thread = NULL;
        ti->error = "Couldn't spawn write thread";
        goto bad;
    }
    wake_up_process(cc->write_thread);

    ti->num_flush_bios = 1;
    ti->limit_swap_bios = true;

    return 0;

bad:
    crypt_dtr(ti);
    return ret;
}

static struct crypt_strategy* crypt_select_strategy(struct crypt_config* cc,
                                                    unsigned int region_type) {
    switch (region_type) {
        case REGION_READ_HOT_WRITE_HOT:
            return &cc->crypt_strategies.read_write_efficient;
        case REGION_READ_HOT_WRITE_COLD:
            return &cc->crypt_strategies.read_most_efficient;
        case REGION_READ_COLD_WRITE_HOT:
            return &cc->crypt_strategies.write_most_efficient;
        case REGION_READ_COLD_WRITE_COLD:
            return &cc->crypt_strategies.default_strategy;
    }
    return NULL;
}

static int crypt_map(struct dm_target* ti, struct bio* bio) {
    struct dm_crypt_io* io;
    struct crypt_config* cc = ti->private;
    struct crypt_strategy* cs;
    unsigned int entry;

    /*
     * If bio is REQ_PREFLUSH or REQ_OP_DISCARD, just bypass crypt queues.
     * - for REQ_PREFLUSH device-mapper core ensures that no IO is in-flight
     * - for REQ_OP_DISCARD caller must use flush if IO ordering matters
     */
    if (unlikely(bio->bi_opf & REQ_PREFLUSH || bio_op(bio) == REQ_OP_DISCARD)) {
        bio_set_dev(bio, cc->dev->bdev);
        if (bio_sectors(bio))
            bio->bi_iter.bi_sector =
                cc->start + dm_target_offset(ti, bio->bi_iter.bi_sector);
        return DM_MAPIO_REMAPPED;
    }

    /**
     * Check if bio is accross multiple region chunks, split as needed.
     */
    // TODO

    /*
     * Check if bio is too large, split as needed.
     */
    if (unlikely(bio->bi_iter.bi_size > (BIO_MAX_VECS << PAGE_SHIFT)) &&
        (bio_data_dir(bio) == WRITE))
        dm_accept_partial_bio(bio,
                              ((BIO_MAX_VECS << PAGE_SHIFT) >> SECTOR_SHIFT));

    /*
     * Ensure that bio is a multiple of internal sector encryption size
     * and is aligned to this size as defined in IO hints.
     */
    if (unlikely((bio->bi_iter.bi_sector &
                  ((cc->sector_size >> SECTOR_SHIFT) - 1)) != 0))
        return DM_MAPIO_KILL;

    if (unlikely(bio->bi_iter.bi_size & (cc->sector_size - 1)))
        return DM_MAPIO_KILL;

    /* Choose crypt strategy from Region Mapper by bio start sector */
    entry = get_mapping_entry(cc->rmap->mapping_tbl, bio->bi_iter.bi_sector);
    cs = crypt_select_strategy(cc, CURRENT_RDWR_TYPE(entry));

    io = dm_per_bio_data(bio, cs->per_bio_data_size);
    crypt_io_init(io, cc, cs, bio,
                  dm_target_offset(ti, bio->bi_iter.bi_sector));

    io->ctx.req = (struct skcipher_request*)(io + 1);

    if (bio_data_dir(io->base_bio) == READ) {
        if (kcryptd_io_read(io, GFP_NOWAIT))
            kcryptd_queue_read(io);
    } else
        kcryptd_queue_crypt(io);

    return DM_MAPIO_SUBMITTED;
}

static void crypt_status(struct dm_target* ti,
                         status_type_t type,
                         unsigned status_flags,
                         char* result,
                         unsigned maxlen) {
    struct crypt_config* cc = ti->private;
    unsigned i, sz = 0;
    int num_feature_args = 0;

    switch (type) {
        case STATUSTYPE_INFO:
            result[0] = '\0';
            break;

        case STATUSTYPE_TABLE:
            DMEMIT("%s ", "[minxed]");

            if (cc->key_size > 0) {
                if (cc->key_string)
                    DMEMIT(":%u:%s", cc->key_size, cc->key_string);
                else
                    for (i = 0; i < cc->key_size; i++)
                        DMEMIT("%02x", cc->key[i]);
            } else
                DMEMIT("-");

            DMEMIT(" %llu %s %llu", (unsigned long long)cc->iv_offset,
                   cc->dev->name, (unsigned long long)cc->start);

            num_feature_args += !!ti->num_discard_bios;
            num_feature_args += test_bit(DM_CRYPT_SAME_CPU, &cc->flags);
            num_feature_args += test_bit(DM_CRYPT_NO_OFFLOAD, &cc->flags);
            num_feature_args +=
                test_bit(DM_CRYPT_NO_READ_WORKQUEUE, &cc->flags);
            num_feature_args +=
                test_bit(DM_CRYPT_NO_WRITE_WORKQUEUE, &cc->flags);
            num_feature_args += cc->sector_size != (1 << SECTOR_SHIFT);
            num_feature_args +=
                test_bit(CRYPT_IV_LARGE_SECTORS, &cc->cipher_flags);
            if (num_feature_args) {
                DMEMIT(" %d", num_feature_args);
                if (ti->num_discard_bios)
                    DMEMIT(" allow_discards");
                if (test_bit(DM_CRYPT_SAME_CPU, &cc->flags))
                    DMEMIT(" same_cpu_crypt");
                if (test_bit(DM_CRYPT_NO_OFFLOAD, &cc->flags))
                    DMEMIT(" submit_from_crypt_cpus");
                if (test_bit(DM_CRYPT_NO_READ_WORKQUEUE, &cc->flags))
                    DMEMIT(" no_read_workqueue");
                if (test_bit(DM_CRYPT_NO_WRITE_WORKQUEUE, &cc->flags))
                    DMEMIT(" no_write_workqueue");
                if (cc->sector_size != (1 << SECTOR_SHIFT))
                    DMEMIT(" sector_size:%d", cc->sector_size);
                if (test_bit(CRYPT_IV_LARGE_SECTORS, &cc->cipher_flags))
                    DMEMIT(" iv_large_sectors");
            }
            break;

        case STATUSTYPE_IMA:
            DMEMIT_TARGET_NAME_VERSION(ti->type);
            DMEMIT(",allow_discards=%c", ti->num_discard_bios ? 'y' : 'n');
            DMEMIT(",same_cpu_crypt=%c",
                   test_bit(DM_CRYPT_SAME_CPU, &cc->flags) ? 'y' : 'n');
            DMEMIT(",submit_from_crypt_cpus=%c",
                   test_bit(DM_CRYPT_NO_OFFLOAD, &cc->flags) ? 'y' : 'n');
            DMEMIT(
                ",no_read_workqueue=%c",
                test_bit(DM_CRYPT_NO_READ_WORKQUEUE, &cc->flags) ? 'y' : 'n');
            DMEMIT(
                ",no_write_workqueue=%c",
                test_bit(DM_CRYPT_NO_WRITE_WORKQUEUE, &cc->flags) ? 'y' : 'n');
            DMEMIT(",iv_large_sectors=%c",
                   test_bit(CRYPT_IV_LARGE_SECTORS, &cc->cipher_flags) ? 'y'
                                                                       : 'n');

            if (cc->sector_size != (1 << SECTOR_SHIFT))
                DMEMIT(",sector_size=%d", cc->sector_size);

            DMEMIT(",key_size=%u", cc->key_size);
            DMEMIT(",key_parts=%u", cc->key_parts);
            DMEMIT(";");
            break;
    }
}

static void crypt_postsuspend(struct dm_target* ti) {
    struct crypt_config* cc = ti->private;

    set_bit(DM_CRYPT_SUSPENDED, &cc->flags);
}

static int crypt_preresume(struct dm_target* ti) {
    struct crypt_config* cc = ti->private;

    if (!test_bit(DM_CRYPT_KEY_VALID, &cc->flags)) {
        DMERR("aborting resume - crypt key is not set.");
        return -EAGAIN;
    }

    return 0;
}

static void crypt_resume(struct dm_target* ti) {
    struct crypt_config* cc = ti->private;

    clear_bit(DM_CRYPT_SUSPENDED, &cc->flags);
}

/* Message interface
 *	key set <key>
 *	key wipe
 */
static int crypt_message(struct dm_target* ti,
                         unsigned argc,
                         char** argv,
                         char* result,
                         unsigned maxlen) {
    struct crypt_config* cc = ti->private;
    struct crypt_strategies* cs = &cc->crypt_strategies;
    struct crypt_strategy* strategy;
    int key_size, ret = -EINVAL;

    if (argc < 2)
        goto error;

    if (!strcasecmp(argv[0], "key")) {
        if (!test_bit(DM_CRYPT_SUSPENDED, &cc->flags)) {
            DMWARN("not suspended during key manipulation.");
            return -EINVAL;
        }
        if (argc == 3 && !strcasecmp(argv[1], "set")) {
            /* The key size may not be changed. */
            key_size = get_key_size(&argv[2]);
            if (key_size < 0 || cc->key_size != key_size) {
                memset(argv[2], '0', strlen(argv[2]));
                return -EINVAL;
            }

            ret = crypt_set_key(cc, argv[2]);
            if (ret)
                return ret;

            strategy = &cs->read_write_efficient;
            if (strategy->iv_gen_ops && strategy->iv_gen_ops->init)
                strategy->iv_gen_ops->init(strategy);

            strategy = &cs->read_most_efficient;
            if (strategy->iv_gen_ops && strategy->iv_gen_ops->init)
                strategy->iv_gen_ops->init(strategy);

            strategy = &cs->write_most_efficient;
            if (strategy->iv_gen_ops && strategy->iv_gen_ops->init)
                strategy->iv_gen_ops->init(strategy);

            strategy = &cs->default_strategy;
            if (strategy->iv_gen_ops && strategy->iv_gen_ops->init)
                strategy->iv_gen_ops->init(strategy);

            /* wipe the kernel key payload copy */
            if (cc->key_string)
                memset(cc->key, 0, cc->key_size * sizeof(u8));
            return ret;
        }
        if (argc == 2 && !strcasecmp(argv[1], "wipe"))
            return crypt_wipe_key(cc);
    }

error:
    DMWARN("unrecognised message received.");
    return -EINVAL;
}

static int crypt_iterate_devices(struct dm_target* ti,
                                 iterate_devices_callout_fn fn,
                                 void* data) {
    struct crypt_config* cc = ti->private;

    return fn(ti, cc->dev, cc->start, ti->len, data);
}

static void crypt_io_hints(struct dm_target* ti, struct queue_limits* limits) {
    struct crypt_config* cc = ti->private;

    /*
     * Unfortunate constraint that is required to avoid the potential
     * for exceeding underlying device's max_segments limits -- due to
     * crypt_alloc_buffer() possibly allocating pages for the encryption
     * bio that are not as physically contiguous as the original bio.
     */
    limits->max_segment_size = PAGE_SIZE;

    limits->logical_block_size =
        max_t(unsigned, limits->logical_block_size, cc->sector_size);
    limits->physical_block_size =
        max_t(unsigned, limits->physical_block_size, cc->sector_size);
    limits->io_min = max_t(unsigned, limits->io_min, cc->sector_size);
}

static struct target_type crypt_target = {
    .name = "security",
    .version = {1, 23, 0},
    .module = THIS_MODULE,
    .ctr = crypt_ctr,
    .dtr = crypt_dtr,
    .features = DM_TARGET_ZONED_HM,
    .report_zones = crypt_report_zones,
    .map = crypt_map,
    .status = crypt_status,
    .postsuspend = crypt_postsuspend,
    .preresume = crypt_preresume,
    .resume = crypt_resume,
    .message = crypt_message,
    .iterate_devices = crypt_iterate_devices,
    .io_hints = crypt_io_hints,
};

static int __init dm_security_init(void) {
    int r;

    r = dm_register_target(&crypt_target);
    if (r < 0)
        DMERR("register failed %d", r);

    return r;
}

static void __exit dm_security_exit(void) {
    dm_unregister_target(&crypt_target);
}

module_init(dm_security_init);
module_exit(dm_security_exit);

MODULE_AUTHOR("Jana Saout <jana@saout.de>");
MODULE_DESCRIPTION(DM_NAME " target for transparent encryption / decryption");
MODULE_LICENSE("GPL");
