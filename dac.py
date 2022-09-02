from io_trace_set import *


class Region:

    def __init__(self, capacity: int) -> None:
        self.items = []
        self.capacity = capacity

    # add LPN to the region,
    # and return the promoted and evicted LPNs if necessary
    def __access__(self, LPN: int, promote: bool) -> list:
        promoted, evicted = None, None
        if LPN in self.items:
            if promote and self.items[-1] == LPN:
                promoted = LPN
                self.items.remove(LPN)
            else:
                self.items.remove(LPN)
                self.items.append(LPN)
        else:
            if len(self.items) == self.capacity:
                evicted = self.items[0]
                self.items.pop(0)
                self.items.append(LPN)
            else:
                self.items.append(LPN)
        return promoted, evicted

    def promote(self, LPN: int) -> list:
        return self.__access__(LPN, True)

    def cache(self, LPN: int) -> None:
        self.__access__(LPN, False)


class DynamicDataClustering:

    def __init__(self, region_arr: list):
        self.regions = [Region(region) for region in region_arr]
        self.index = dict()

    def fit(self, LPN: int) -> None:
        if LPN in self.index:
            idx = self.index[LPN]
        else:
            idx = 0

        region = self.regions[idx]
        if idx == len(self.regions) - 1:
            region.cache(LPN)
            return

        promoted, evicted = region.promote(LPN)
        self.index[LPN] = idx
        while True:
            if promoted is not None:
                idx += 1
                self.index[promoted] = idx
                region = self.regions[idx]
                promoted, evicted = region.promote(promoted)
            elif evicted is not None:
                idx -= 1
                if idx >= 0:
                    self.index[evicted] = idx
                    region = self.regions[idx]
                    promoted, evicted = region.promote(evicted)
                else:
                    self.index.pop(evicted)
                    break
            else:
                break

    def predict(self, LPN: int) -> int:
        return self.index[LPN] if LPN in self.index else -1


class DynamicDataClusteringModel:

    def __init__(self, read_regions, write_regions) -> None:
        self.read_dac = DynamicDataClustering(read_regions)
        self.write_dac = DynamicDataClustering(write_regions)

    def trace_one(self, trace: IOTrace) -> list:
        cost = self.op_cost(trace)
        total_cost = 3
        if trace.type == 0:
            for _ in range(trace.size):
                self.read_dac.fit(trace.offset)
        else:
            for _ in range(trace.size):
                self.write_dac.fit(trace.offset)
        return cost, total_cost

    def op_cost(self, trace: IOTrace) -> int:
        read_hot = self.read_dac.predict(
            trace.offset) == len(self.read_dac.regions) - 1
        write_hot = self.write_dac.predict(
            trace.offset) == len(self.write_dac.regions) - 1

        if trace.type == 0:
            if read_hot and not write_hot:
                return 1
            if read_hot and write_hot:
                return 2
            if not read_hot:
                return 3
        else:
            if write_hot and not read_hot:
                return 1
            if write_hot and read_hot:
                return 2
            if not write_hot:
                return 3
        return 0


if __name__ == '__main__':
    trace_set = IOTraceSet('proj_1_processed.csv')
    dac_model = DynamicDataClusteringModel([100000, 100000, 100000, 100000],
                                           [100000, 100000, 100000, 100000])
    trace_set.replay(dac_model.trace_one)
    trace_set.show_result()
