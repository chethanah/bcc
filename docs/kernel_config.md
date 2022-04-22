# Linux Kernel Configration for BPF Features

Functionalities | Kernel Configuration | Describtion
-----------------|----------------------|------------
| basic | CONFIG_BPF_SYSCALL | Enable the bpf() system call
|  | CONFIG_BPF_JIT |
|  | CONFIG_HAVE_BPF_JIT |
|  | CONFIG_HAVE_EBPF_JIT |
|  | CONFIG_HAVE_CBPF_JIT |
|  | CONFIG_MODULES |
|  | CONFIG_BPF |
|  | CONFIG_BPF_EVENTS |
|  | CONFIG_PERF_EVENTS |
|  | CONFIG_HAVE_PERF_EVENTS |
|  | CONFIG_PROFILING |
| BTF | CONFIG_DEBUG_INFO_BTF | Generate deduplicated BTF type information from DWARF debug info
| | CONFIG_PAHOLE_HAS_SPLIT_BTF | Generate BTF for each selected kernel module
| | CONFIG_DEBUG_INFO_BTF_MODULES | Generate compact split BTF type information for kernel modules
| security | CONFIG_BPF_JIT_ALWAYS_ON | Enable BPF JIT and removes BPF interpreter to avoid speculative execution
| | CONFIG_BPF_UNPRIV_DEFAULT_OFF | Disable unprivileged BPF by default by setting
| cgroup | CONFIG_CGROUP_BPF |
| network | CONFIG_BPFILTER |
| | CONFIG_BPFILTER_UMH |
| | CONFIG_NET_CLS_BPF |
| | CONFIG_NET_ACT_BPF |
| | CONFIG_BPF_STREAM_PARSER |
| | CONFIG_LWTUNNEL_BPF |
| | CONFIG_NETFILTER_XT_MATCH_BPF |
| | CONFIG_IPV6_SEG6_BPF |
| | CONFIG_LWTUNNEL_BPF |
| kprobes | CONFIG_KPROBE_EVENTS |
|  | CONFIG_KPROBES |
|  | CONFIG_HAVE_KPROBES |
|  | CONFIG_HAVE_REGS_AND_STACK_ACCESS_API |
| kprobe override | CONFIG_BPF_KPROBE_OVERRIDE | Enable BPF programs to override a kprobed function
| uprobes | CONFIG_UPROBE_EVENTS |
|  | CONFIG_ARCH_SUPPORTS_UPROBES |
|  | CONFIG_UPROBES |
|  | CONFIG_MMU |
| tracepoints | CONFIG_TRACEPOINTS |
|  | CONFIG_HAVE_SYSCALL_TRACEPOINTS |
| Raw Tracepoints | Same as Tracepoints |
| LSM | CONFIG_BPF_LSM | Enable BPF LSM Instrumentation
| LIRC | CONFIG_BPF_LIRC_MODE2 | Allow attaching eBPF programs to a lirc device
