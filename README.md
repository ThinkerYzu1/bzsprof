## bzsprof

This is simple profiler that collect stack traces of all processes and kernel.
It collects samples with perf events triggered with a fixed interval.
Once a perf event takes place, it walks tacks of kernel and
the running process, not a specific process, to collect IPs of frames on the stack.
It shows users a system wide profile.

## Dependencies

 - BlazeSym (https://github.com/ThinkerYzu1/blazesym)
