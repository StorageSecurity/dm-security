/*
 * Copyright (C) 2022 Peihong Chen <peihing.chen@transwarp.io>
 *
 * This file is released under the GPL.
 */

#include <asm/page.h>
#include <asm/unaligned.h>
#include <crypto/aead.h>
#include <crypto/algapi.h>
#include <crypto/authenc.h>
#include <crypto/hash.h>
#include <crypto/md5.h>
#include <crypto/skcipher.h>
#include <keys/encrypted-type.h>
#include <keys/trusted-type.h>
#include <keys/user-type.h>
#include <linux/atomic.h>
#include <linux/backing-dev.h>
#include <linux/bio.h>
#include <linux/blk-integrity.h>
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

#define DM_MSG_PREFIX "security"

static void security_dtr(struct dm_target* ti) {}

#ifdef CONFIG_BLK_DEV_ZONED
static int security_report_zones(struct dm_target* ti,
                                 struct dm_report_zones_args* args,
                                 unsigned int nr_zones) {
    return 0;
}
#else
#define security_report_zones NULL
#endif

/*
 * Construct an encryption mapping:
 * <cipher> [<key>|:<key_size>:<user|logon>:<key_description>] <iv_offset>
 * <dev_path> <start>
 */
static int security_ctr(struct dm_target* ti, unsigned int argc, char** argv) {
    return 0;
}

static int security_map(struct dm_target* ti, struct bio* bio) {
    return DM_MAPIO_SUBMITTED;
}

static void security_status(struct dm_target* ti,
                            status_type_t type,
                            unsigned status_flags,
                            char* result,
                            unsigned maxlen) {}

static void security_postsuspend(struct dm_target* ti) {}

static int security_preresume(struct dm_target* ti) {
    return 0;
}

static void security_resume(struct dm_target* ti) {}

/* Message interface
 *	key set <key>
 *	key wipe
 */
static int security_message(struct dm_target* ti,
                            unsigned argc,
                            char** argv,
                            char* result,
                            unsigned maxlen) {
    return 0;
}

static int security_iterate_devices(struct dm_target* ti,
                                    iterate_devices_callout_fn fn,
                                    void* data) {
    return 0;
}

static void crypt_io_hints(struct dm_target* ti, struct queue_limits* limits) {}

static struct target_type crypt_target = {
    .name = "security",
    .version = {0, 0, 1},
    .module = THIS_MODULE,
    .ctr = security_ctr,
    .dtr = security_dtr,
    .features = DM_TARGET_ZONED_HM,
    .report_zones = security_report_zones,
    .map = security_map,
    .status = security_status,
    .postsuspend = security_postsuspend,
    .preresume = security_preresume,
    .resume = security_resume,
    .message = security_message,
    .iterate_devices = security_iterate_devices,
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

MODULE_AUTHOR("Peihong Chen <peihong.chen@transwarp.io>");
MODULE_DESCRIPTION(DM_NAME " target for block device security");
MODULE_LICENSE("GPL");
