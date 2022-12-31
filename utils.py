from collections import deque
import queue

def topological_sort(keys, hg):
    sorted = []
    visited_count = 0
    adj_list = {keys[i] : () for i in range(len(keys))}
    in_degree = {keys[i] : 0 for i in range(len(keys))}
    for k in keys:
        for p in hg[k].parents:
            if p in keys:
                in_degree[p] += 1
                adj_list[k] += (p,)
    q = queue.Queue()
    for h in in_degree.keys():
        if in_degree[h] == 0:
            q.put(h)
    while not q.empty():
        node = q.get()
        sorted.insert(0, node)
        for p in adj_list[node]:
            in_degree[p] -= 1
            if in_degree[p] == 0:
                q.put(p)
        visited_count += 1
    if visited_count != len(keys):
        print("Cycle detected!")
    return sorted
