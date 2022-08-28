import csv
from rich.progress import Progress


class IOTrace:

    def __init__(self, row):
        self.type = int(row[0])
        self.offset = int(row[1])
        self.size = int(row[2])


class IOTraceSet:

    def __init__(self, trace_file: str) -> None:
        with open(trace_file, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            self.trace_set = [IOTrace(row) for row in reader]
        print("trace num: %d" % len(self.trace_set))
        self.cost = 0
        self.total_cost = 0

    def replay(self, trace_one):
        with Progress() as progress:
            task = progress.add_task('tracing...', total=len(self.trace_set))
            for trace in self.trace_set:
                self.cost, self.total_cost = trace_one(
                    trace, self.cost, self.total_cost)
                progress.update(task, advance=1)

    def show_result(self):
        print("total cost: %d" % self.total_cost)
        print("actual cost: %d" % self.total_cost)
        print("saved ratio: %.2f" % (1 - self.cost / self.total_cost))


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

    def trace_one(self, trace: IOTrace, cost: int, total_cost: int) -> list:
        cost += self.op_cost(trace)
        total_cost += 3
        if trace.type == 0:
            for i in range(trace.size):
                self.read_dac.fit(trace.offset)
        else:
            for i in range(trace.size):
                self.write_dac.fit(trace.offset)

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
    dac_model = DynamicDataClusteringModel([100000, 100000, 100000, 100000], [
                                           100000, 100000, 100000, 100000])
    trace_set.replay(dac_model.trace_one)
    trace_set.show_result()
