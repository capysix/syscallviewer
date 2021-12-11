import angr
import argparse
import IPython
import networkx
import os
import subprocess
from subprocess import Popen, PIPE

IDA_PATH="/home/htay/ida/idat"
IDA64_PATH="/home/htay/ida/idat64"

SYSCALL_TAGS = ["print", "write", "bind", "open", "stat", "strcmp", "nvram", "error", "log", "system", "execve"]

class Node():
    def __init__(self, function, name, addr, syscalls, children):
        self.f = function
        self.name = name
        self.addr = addr
        self.syscalls = syscalls
        self.children = children


class Graph():
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.project = angr.Project(binary_path, load_options={'auto_load_libs': False})
        self.cfg = self.project.analyses.CFGFast(detect_tail_calls=True,
                                                      normalize=True,
                                                      data_references=True)
        self.graph_nodes = {}
        self.node_content_map = {}
        self.graph = networkx.DiGraph()
        self.syscalls = set()
        self.main = None
        self.ida_path = self.get_ida_arch()

        self.build_nodes()


    def get_ida_arch(self):
        sp = subprocess.run(["file", self.binary_path], stdout=PIPE, stderr=PIPE)
        stdout = sp.stdout
        if b"64-bit" in stdout:
            print("binary is 64 bit, using ida64")
            return IDA64_PATH
        print("binary is 32 bit, using ida")
        return IDA_PATH

    def build_nodes(self):
        done = []
        mains = []
        for f in self.cfg.functions.values():
            if f.addr in done:
                # print("Skipping ", f.addr)
                continue
            for tag in SYSCALL_TAGS:
                if tag in f.name:
                    # print("Skipping ", f.name)
                    self.syscalls.add(f.addr)
                    continue
            callees = f.functions_called()
            syscalls = []
            children = []
            for c in callees:
                found = False
                for tag in SYSCALL_TAGS:
                    if tag in c.name and c.name not in syscalls:
                        syscalls.append(c.name)
                        break
                if not found:
                    children.append(c.addr)
            n = Node(f, f.name, f.addr, syscalls, children)
            self.graph_nodes[n.addr] = n
            if n.name.endswith("main"):
                mains.append(n)
            done.append(f.addr)

        def sortby_node_name(n):
            return n.name

        for m in sorted(mains, key=sortby_node_name, reverse=True): # priotize shorter labels
            print("setting main: ", m.name, m.addr)
            self.main = m
            break

    def build_graph_from_nodes(self):
        if self.main == None:
            print("No main found, end")
            return

        next_addrs = [self.main.addr]
        done = set()

        while True:
            if len(next_addrs) <= 0:
                break
            current_addr = next_addrs.pop()
            if current_addr in done or current_addr in self.syscalls:
                # print("  - Skip!", current_addr)
                continue

            current_node = self.graph_nodes[current_addr]
            if len(current_node.children) > 0:
                self.add_node_to_graph(current_node)
                for c in current_node.children:
                    if c not in self.syscalls and c not in next_addrs:
                        self.graph.add_edge(current_node.addr, c)
                        next_addrs.append(c)
            done.add(current_addr)
        self.update_graph_with_labels()


    def add_node_to_graph(self, node):
        outname = node.name+"_decomp"
        func_name = node.name
        ida_command = [self.ida_path, "-Ohexrays:-nosave:"+outname+":"+func_name, "-A", self.binary_path]
        # print("Running: ", " ".join(ida_command))
        subprocess.run(ida_command)

        decompPath = outname+".c"
        functionLines = ""
        if os.path.exists(decompPath):
            with open(decompPath, "r+") as decompFile:
                functionLines = decompFile.read()
            decompFile.close()
            os.remove(decompPath)

        node_contents = "[%x] " % (node.addr)
        node_contents += "%s" % node.name
        done = set()
        for line in functionLines.splitlines():
            if line.startswith("/"):
                continue # skip comments
            for s in node.syscalls:
                s = s+"("
                if s in line.strip():
                    sysdetails = self.extract_syscall(line, s)
                    if sysdetails not in done:
                        node_contents += "\n%s" % sysdetails
                        done.add(sysdetails)

        self.graph.add_node(node.addr)
        self.node_content_map[node.addr] = node_contents
        # if len(node.syscalls) > 0:
        #     self.graph.add_node(node_contents)
        #     self.graph.add_edge(titlenode, node_contents)

    def extract_syscall(self, line, s):
        if s not in line:
            print("Error %s not in %s" % (s, line))
            return ""
        index = line.index(s)
        line = line[index:]
        brace = 0
        index = 0
        latch = False
        for c in line:
            if c == "(":
                brace += 1
                if not latch:
                    latch = True
            if c == ")":
                brace -= 1

            index += 1
            if latch and brace == 0:
                break
        line = line[:index]

        line = line.replace("\n", "")
        line = line.replace("\t", "")
        line = line.replace("\r", "")
        line = line.replace(";", "")
        line = line.replace(":", " ")
        line = line.replace("\\", "")
        return line

    def update_graph_with_labels(self):
        networkx.relabel_nodes(self.graph, self.node_content_map, copy=False)
        count = 1
        while True:
            print("Filter cycle %d" % count)
            prevNumNodes = len(self.graph.nodes)
            outdeg = self.graph.out_degree()
            to_remove = [n for (n, deg) in outdeg if deg <= 0 and (isinstance(n, int) or "\n" in str(n))]
            self.graph.remove_nodes_from(to_remove)
            currNumNodes = len(self.graph.nodes)

            if prevNumNodes == currNumNodes:
                break
            print(" - prevNumNodes", prevNumNodes)
            print(" - currNumNodes", currNumNodes)
            count += 1


    def dump_graph(self):
        dot_graph = networkx.nx_pydot.to_pydot(self.graph)
        binary_name = os.path.basename(self.binary_path)

        graph_name = '%s.dot' % (binary_name)
        dot_graph.write(graph_name)


def main():
    parser = argparse.ArgumentParser(description='generates cfg tree of key syscalls')
    parser.add_argument('binary_path',
                help='path to the target binary')
    args, unknownargs = parser.parse_known_args()
    g = Graph(args.binary_path)
    g.build_graph_from_nodes()
    g.dump_graph()

main()