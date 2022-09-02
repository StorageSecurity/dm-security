from collections import OrderedDict
from enum import Enum
from io_trace_set import *
from multiprocessing.dummy import Pool as ThreadPool
import random


class OpType(Enum):
    READ = 0
    WRITE = 1


class ReadWriteType(Enum):
    READ_HOT_WRITE_HOT = 0
    READ_HOT_WRITE_COLD = 1
    READ_COLD_WRITE_HOT = 2
    READ_COLD_WRITE_COLD = 3


class Freq:

    def __init__(self, read: int, write: int):
        self.read = read
        self.write = write


class LeastRecentlyUsed(OrderedDict):

    def __init__(self, capacity):
        self.capacity = capacity
        self.cache = OrderedDict()

    def get(self, key) -> Freq:
        if key in self.cache:
            value = self.cache.get(key)
        else:
            value = Freq(0, 0)
        return value

    def set(self, key, type: OpType, size: int) -> None:
        if key in self.cache:
            value = self.cache.pop(key)
            if type == OpType.READ:
                value.read += size
            else:
                value.write += size
            self.cache[key] = value
        else:
            read = size if OpType == OpType.READ else 0
            write = size if OpType == OpType.WRITE else 0
            value = Freq(read, write)
            if len(self.cache) == self.capacity:
                zero_freq_found = False
                for k, v in self.cache.items():
                    if v.read == 0 and v.write == 0:
                        zero_freq_found = True
                        self.cache.pop(k)
                        self.cache[key] = value
                        break
                if not zero_freq_found and random.randint(0, 1) == 0:
                    # probability of 0.5 to evict the first item
                    # if there is no zero freq
                    self.cache.popitem(last=False)  # pop出第一个item
                    self.cache[key] = value
            else:
                self.cache[key] = value

    def decay(self) -> None:
        for _, v in self.cache.items():
            if v.read == 1:
                v.read = 0
            else:
                v.read /= 2
            if v.write == 1:
                v.write = 0
            else:
                v.write /= 2


class GroupLeastRecentyUsed:

    def __init__(self, k, capacity, period):
        self.k = k
        self.lru_group = [LeastRecentlyUsed(capacity) for _ in range(k)]
        self.period = period  # 每个周期的请求次数，其中每个周期结束时对lru_group执行一次decay
        self.count = 0  # 记录当前周期是第几次请求
        self.ratio = 7  # 读写频率比例
        self.penalty_ratio = 2  # 预测出错时的在线训练惩罚比率
        self.bonus_ratio = 1  # 预测正确时的在线训练奖励比率

    def fit(self, trace: IOTrace):
        LPN = trace.offset
        idx = LPN % self.k
        self.lru_group[idx].set(LPN, trace.type, trace.size)

        self.count = (self.count + 1) % self.period
        if self.count == 0:
            pool = ThreadPool()  # 用于并行执行decay操作的线程池
            pool.map(lambda x: x.decay(), self.lru_group)
            pool.close()
            pool.join()

    def predict(self, trace: IOTrace) -> ReadWriteType:
        LPN = trace.offset
        idx = LPN % self.k
        lru = self.lru_group[idx]

        freq = lru.get(LPN)
        read, write = freq.read, freq.write

        if read == 0 and write == 0:
            return ReadWriteType.READ_COLD_WRITE_COLD
        if (read + 1) / (write + 1) >= self.ratio:
            return ReadWriteType.READ_HOT_WRITE_COLD
        elif (write + 1) / (read + 1) >= self.ratio:
            return ReadWriteType.READ_COLD_WRITE_HOT
        else:
            return ReadWriteType.READ_HOT_WRITE_HOT


class GroupLeastRecentlyUsedModel:

    def __init__(self):
        self.glru = GroupLeastRecentyUsed(
            k=100, capacity=100000, period=10000000)

    def trace_one(self, trace: IOTrace) -> list:
        rwType = self.glru.predict(trace)
        if rwType == ReadWriteType.READ_HOT_WRITE_HOT:
            cost = 2
        elif rwType == ReadWriteType.READ_COLD_WRITE_COLD:
            cost = 3
        else:
            if rwType == ReadWriteType.READ_HOT_WRITE_COLD:
                cost = 1 if trace.type == 0 else 3
            else:
                cost = 1 if trace.type == 1 else 3

        # false prediction, add penalty
        if cost == 3:
            trace.size *= self.glru.penalty_ratio
        elif cost == 1:
            trace.size *= self.glru.bonus_ratio
        # train online
        self.glru.fit(trace)

        return cost, 3


if __name__ == '__main__':
    trace_set = IOTraceSet('datasets/proj_processed.csv')
    # trace_set = IOTraceSet('Financial_processed.csv')
    glru_model = GroupLeastRecentlyUsedModel()
    trace_set.replay(glru_model.trace_one)
    trace_set.show_result()
