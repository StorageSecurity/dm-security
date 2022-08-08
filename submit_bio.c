#include <linux/blk_types.h>
#include <linux/genhd.h>
#include <linux/bio.h>
#include <uapi/linux/ptrace.h>

struct bio_account_t {
  unsigned long ts;
  int major;
  int minor;
  unsigned int rw_mode;
  unsigned int start;
  unsigned int length;
};

BPF_RINGBUF_OUTPUT(bio_account_ring, 1 << 4);

int bio_account_fn(struct pt_regs *ctx, struct bio *bio) {
  struct block_device* bdev = bio->bi_bdev;
  struct gendisk* disk = bdev->bd_disk;
  dev_t dev;

  bpf_probe_read_kernel(&dev, sizeof(dev), &bdev->bd_dev);
  if (MAJOR(dev) != DEV_MAJOR || MINOR(dev) != DEV_MINOR) {
    return 0;
  }

  struct bio_account_t *account = bio_account_ring.ringbuf_reserve(sizeof(struct bio_account_t));
  if (!account) { // failed to reserve space in ring buffer
    return 1;
  }

  account->ts = bpf_ktime_get_ns();
  account->major = MAJOR(dev);
  account->minor = MINOR(dev);
  // bpf_probe_read_kernel_str(account->name, sizeof(account->name), disk->disk_name);
  // error: doesn't work for some reason
  // account->rw_mode = bio_data_dir(bio);
  account->rw_mode = (bio->bi_opf & REQ_OP_MASK) & 1;
  account->start = bio->bi_iter.bi_sector;
  account->length = bio->bi_iter.bi_size >> 9;

  bio_account_ring.ringbuf_submit(account, 0);

  return 0;
}