SyscallViewer

Simple python-based CFG visualization tool to help with RE of binaries. Requires angr, networkx and ida installed.

Concept:
- I've generally found that when REing looking at the control flow + syscalls and debug statements helped me form a useful initial picture of the binary. I thought it might be useful to have a tool that just extracts a subset of the decompiled syscalls per function and mapped it into a basic function-level CFG. Decided to try writing a tool using angr/ida to have a look at how effective it might be.

The result is less useful than I thought but still pretty cute. Could probably be improved by implementing some sort of subgraph and including if/else/loops/gotos, but at some point we end up just reinventing IDA. One of the reasons I used IDAs' decompiler instead of angr's is that angrs does not display hardcoded strings as part of the decompilation dump, while IDA does, and it seemed easier to just map a subprocess dump than try to fingle the decompiler's addr-string mappings inside angrs backend.

It might be better to write an IDA/angr plugin that does the same except backwards - i.e. strip basic blocks in the decompiler GUI of any statements that aren't a syscall or logging/debug statement.

Overall I had fun writing this little tool, and it does seem potentially useful to my own work REing weird firmware binaries, which tend to be just convoluted masses of logging messages and syscalls.

Usage:
python3 sysviewer.py <binary_path>

You will also need to set the global IDA_PATH to both `idat` and `idat64` so we can invoke the ida decompiler.

SYSCALL_LIST is a global list that can be modified to target specific groups of syscalls. It just looks for keywords, so something like "printf" matches "sprintf" and "fprintf".

These should probably be a config or argument but eh it works.
