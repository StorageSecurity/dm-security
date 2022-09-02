import csv
from rich.progress import Progress


class IOTrace:

    def __init__(self, row):
        self.type = int(row[0])
        self.offset = int(row[1])
        self.size = int(row[2])
        

class OriginalCost: 
    
    def __init__(self, read_cost, write_cost):
        self.cost_table = [read_cost, write_cost]
        
    def get(self, trace: IOTrace):
        return self.cost_table[trace.type]
    

original_cost_opt_for_read = OriginalCost(1, 3)
original_cost_opt_for_write = OriginalCost(3, 1)
original_cost_balanced = OriginalCost(2, 2)


class IOTraceSet:

    def __init__(self, trace_file: str, original_cost: OriginalCost) -> None:
        with open(trace_file, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            self.trace_set = [IOTrace(row) for row in reader]
        print("trace num: %d" % len(self.trace_set))
        self.cost = 0
        self.total_cost = 0
        self.trace_file = trace_file
        self.original_cost = original_cost
        

    def replay(self, trace_one):
        with Progress() as progress:
            task = progress.add_task('tracing %s...' %
                                     self.trace_file, total=len(self.trace_set))
            for trace in self.trace_set:
                cost = trace_one(trace)
                self.cost += cost
                self.total_cost += self.original_cost.get(trace)
                progress.update(task, advance=1)

    def show_result(self):
        print("total cost: %d" % self.total_cost)
        print("actual cost: %d" % self.cost)
        print("saved ratio: %.6f" % (1 - self.cost / self.total_cost))
    
    def get_result(self):
        return [self.total_cost, self.cost, 1 - self.cost / self.total_cost]

    # 展示 trace set 的数据分布情况
    def show_statistics(self):
        statistics = dict()
        for trace in self.trace_set:
            if trace.offset in statistics:
                statistics[trace.offset] += 1
            else:
                statistics[trace.offset] = 1
        counter = dict()
        for _, v in statistics.items():
            if v in counter:
                counter[v] += 1
            else:
                counter[v] = 1
        for k, v in counter.items():
            print("%d: %d" % (k, v))
