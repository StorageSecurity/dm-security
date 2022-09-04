#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <linux/gfp.h>
#include <linux/err.h>
#include <linux/jiffies.h>
#include <linux/timex.h>
#include <linux/random.h>
#include <linux/timekeeping.h>

#include <crypto/skcipher.h>
#include <crypto/hash.h>
#include <crypto/if_alg.h>
#include <crypto/drbg.h>

#define MAX_LEN (4 * 1024 * 1024) // 4MB
#define STEP (256 *1024) // 128KB
#define MAX_KEY_SIZE (64) // 最大密钥长度，64bit

struct test_context {
    struct skcipher_def *sk;
    char *cipher;
    unsigned int keylen;
    long long encrypt_cost[MAX_LEN / STEP];
    long long decrypt_cost[MAX_LEN / STEP];
};

static struct test_context tests[] = {
        {
                .cipher = "ecb(aes)",
                .keylen = 32,
        },
        {
                .cipher = "cbc(aes)",
                .keylen = 32,
        },
        // {
        //         .cipher = "pcbc(aes)",
        //         .keylen = 32,
        // },
        // {
        //         .cipher = "ofb(aes)",
        //         .keylen = 32,
        // },
        // {
        //         .cipher = "cfb(aes)",
        //         .keylen = 32,
        // },
        // {
        //         .cipher = "ctr(aes)",
        //         .keylen = 32,
        // },
        {
                .cipher = "xts(aes)",
                .keylen = 64,
        },
};

/* tie all data structures together */
struct skcipher_def {
    struct scatterlist sg;
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct crypto_wait wait;
};

/* Perform cipher operation */
static unsigned int test_skcipher_encdec(struct test_context *test_ctx,
                                         int enc, int iter) {
    int rc;
    ktime_t start_time, finish_time;

    if (enc) {
        start_time = ktime_get();
        rc = crypto_wait_req(crypto_skcipher_encrypt(test_ctx->sk->req), &test_ctx->sk->wait);
        finish_time = ktime_get();
        test_ctx->encrypt_cost[iter] = ktime_to_us(ktime_sub(finish_time, start_time));
    } else {
        start_time = ktime_get();
        rc = crypto_wait_req(crypto_skcipher_decrypt(test_ctx->sk->req), &test_ctx->sk->wait);
        finish_time = ktime_get();
        test_ctx->decrypt_cost[iter] = ktime_to_us(ktime_sub(finish_time, start_time));
    }

    if (rc) {
        pr_err("skcipher encrypt returned with result %d\n", rc);
    }
    return rc;
}

/* Initialize and trigger cipher operation */
static int test_skcipher(struct test_context *test_ctx, char *scratchpad, unsigned int len) {
    int ret = -EFAULT;
    struct skcipher_def sk;
    struct crypto_skcipher *skcipher = NULL;
    struct skcipher_request *req = NULL;
    unsigned char key[MAX_KEY_SIZE];
    char *ivdata = NULL;

    skcipher = crypto_alloc_skcipher(test_ctx->cipher, 0, 0);
    if (IS_ERR(skcipher)) {
        pr_err("could not allocate skcipher handle\n");
        return PTR_ERR(skcipher);
    }

    req = skcipher_request_alloc(skcipher, GFP_KERNEL);
    if (!req) {
        pr_err("could not allocate skcipher request\n");
        ret = -ENOMEM;
        goto out;
    }

    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
                                  crypto_req_done,
                                  &sk.wait);

    /* AES 256 with random key */
    get_random_bytes(&key, test_ctx->keylen);
    if (crypto_skcipher_setkey(skcipher, key, test_ctx->keylen)) {
        pr_info("key could not be set\n");
        ret = -EAGAIN;
        goto out;
    }

    /* IV will be random */
    ivdata = kmalloc(16, GFP_KERNEL);
    if (!ivdata) {
        pr_info("could not allocate ivdata\n");
        goto out;
    }
    get_random_bytes(ivdata, 16);

    sk.tfm = skcipher;
    sk.req = req;

    sg_init_one(&sk.sg, scratchpad, len);
    /**
     * @req: request handle
     * @src: source scatter / gather list
     * @dst: destination scatter / gather list
     * @cryptlen: number of bytes to process from @src
     * @iv: IV for the cipher operation which must comply with the IV size defined
     *      by crypto_skcipher_ivsize
     */
    skcipher_request_set_crypt(req, &sk.sg, &sk.sg, len, ivdata);
    crypto_init_wait(&sk.wait);

    test_ctx->sk = &sk;

    ret = test_skcipher_encdec(test_ctx, 0, len / STEP);
    if (ret)
        goto out;

    pr_info("Decryption triggered successfully\n");

    ret = test_skcipher_encdec(test_ctx, 1, len / STEP);
    if (ret)
        goto out;

    pr_info("Encryption triggered successfully\n");

    out:
    if (skcipher)
        crypto_free_skcipher(skcipher);
    if (req)
        skcipher_request_free(req);
    if (ivdata)
        kfree(ivdata);
    return ret;
}

static int __init

cipher_bench_init(void) {
    char *scratchpad = NULL;
    int i, j;

    pr_info("linux crypto block chain mode loaded");

    for (i = STEP; i <= MAX_LEN; i += STEP) {
        /* Input data will be random */
        scratchpad = kmalloc(i, GFP_KERNEL);
        if (!scratchpad) {
            pr_info("could not allocate scratchpad\n");
            goto out;
        }
        get_random_bytes(scratchpad, i);

        for (j = 0; j < ARRAY_SIZE(tests); ++j) {
            test_skcipher(&tests[j], scratchpad, i);
        }
        out:
        if (scratchpad) {
            kfree(scratchpad);
        }
    }

    // 打印结果
    // 1. 加密操作
    pr_cont("input");
    for (i = 0; i < ARRAY_SIZE(tests); i++) {
        pr_cont(",%s-%d", tests[i].cipher, tests[i].keylen);
    }
    pr_info();
    for (i = 0; i < MAX_LEN / STEP; i++) {
        pr_cont("%d", (i + 1) * STEP);
        for (j = 0; j < ARRAY_SIZE(tests); j++) {
            pr_cont(",%lld", tests[j].encrypt_cost[i]);
        }
        pr_info();
    }

    // 2. 解密操作
    pr_cont("input");
    for (i = 0; i < ARRAY_SIZE(tests); i++) {
        pr_cont(",%s-%d", tests[i].cipher, tests[i].keylen);
    }
    pr_info();
    for (i = 0; i < MAX_LEN / STEP; i++) {
        pr_cont("%d", (i + 1) * STEP);
        for (j = 0; j < ARRAY_SIZE(tests); j++) {
            pr_cont(",%lld", tests[j].decrypt_cost[i]);
        }
        pr_info();
    }

    // 3. 加密+解密操作
    pr_cont("input");
    for (i = 0; i < ARRAY_SIZE(tests); i++) {
        pr_cont(",%s-%d", tests[i].cipher, tests[i].keylen);
    }
    pr_info();
    for (i = 0; i < MAX_LEN / STEP; i++) {
        pr_cont("%d", (i + 1) * STEP);
        for (j = 0; j < ARRAY_SIZE(tests); j++) {
            pr_cont(",%lld", tests[j].encrypt_cost[i] + tests[j].decrypt_cost[i]);
        }
        pr_info();
    }

    return 0;
}

static void __exit

cipher_bench_exit(void) {
    printk("linux crypto block chain mode benchmark unloaded\n");
}

module_init(cipher_bench_init);
module_exit(cipher_bench_exit);

MODULE_DESCRIPTION("Linux Crypto Block Chain Mode Benchmark");
MODULE_LICENSE("GPL");
