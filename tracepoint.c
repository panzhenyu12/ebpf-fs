// +build ignore

#include "common.h"
#include "bpf_helpers.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") counting_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 1,
};

// This struct is defined according to the following format file:
// /sys/kernel/debug/tracing/events/kmem/mm_page_alloc/format
struct alloc_info {
	unsigned short common_type;	
	unsigned char common_flags;	
	unsigned char common_preempt_count;	
	int common_pid;	

	int __syscall_nr;	
	const char * pathname;	
	unsigned short mode;	
};

// This tracepoint is defined in mm/page_alloc.c:__alloc_pages_nodemask()
// Userspace pathname: /sys/kernel/debug/tracing/events/kmem/mm_page_alloc
SEC("tracepoint/syscalls/sys_enter_mkdir")
int trace_mkdir(struct alloc_info *info) {
	u32 key     = 0;
	u64 initval = 1, *valp;
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    bpf_printk("pid:%d,filename:%s \n",pid,info->pathname);

	valp = bpf_map_lookup_elem(&counting_map, &key);
	if (!valp) {
		bpf_map_update_elem(&counting_map, &key, &initval, BPF_ANY);
		return 0;
	}
	__sync_fetch_and_add(valp, 1);
	return 0;
}
