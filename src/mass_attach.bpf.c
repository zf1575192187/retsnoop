// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2021 Facebook */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#ifdef BPF_NO_GLOBAL_DATA
#include "retsnoop.h"
#endif

/* these two are defined by custom BPF code outside of mass_attacher */
#ifndef BPF_NO_GLOBAL_DATA
extern int handle_func_entry(void *ctx, u32 func_id, u64 func_ip);
extern int handle_func_exit(void *ctx, u32 func_id, u64 func_ip, u64 ret);
#else
static __always_inline int handle_func_entry(void *ctx, u32 func_id, u64 func_ip);
static __always_inline int handle_func_exit(void *ctx, u32 func_id, u64 func_ip, u64 ret);
#endif

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);
	__type(value, unsigned);
} ip_to_id SEC(".maps");

#define MAX_CPU_CNT 256
#define MAX_CPU_MASK (MAX_CPU_CNT - 1)
#define MAX_LBR_ENTRIES 32

#ifndef BPF_NO_GLOBAL_DATA
bool ready = false;

/* feature detection/calibration inputs */
const volatile int kret_ip_off = 0;
const volatile bool has_bpf_get_func_ip = false;
const volatile bool has_bpf_cookie = false;

/* Kernel protects from the same BPF program from refiring on the same CPU.
 * Unfortunately, it's not very useful for us right now, because each attached
 * fentry/fexit is a separate BPF, so we need to still protected ourselves.
 */
const volatile bool has_fentry_protection = false;

extern const volatile bool use_lbr;

static __u64 lbr_szs[MAX_CPU_CNT];
static struct perf_branch_entry lbrs[MAX_CPU_CNT][MAX_LBR_ENTRIES];

#else

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, __u64);
	__uint(max_entries, retsnoop_ID_CNT); /* could be overriden from user-space */
} global_var SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, __u64);
	__uint(max_entries, MAX_CPU_CNT); /* could be overriden from user-space */
} lbr_szs SEC(".maps");

struct perf_branch_entry_array {
	struct perf_branch_entry entry[MAX_LBR_ENTRIES];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct perf_branch_entry_array);
	__uint(max_entries, MAX_CPU_CNT); /* could be overriden from user-space */
} lbrs SEC(".maps");
#endif

/* has to be called from entry-point BPF program if not using
 * bpf_get_func_ip()
 */
#ifndef BPF_NO_GLOBAL_DATA
static __always_inline u64 get_kret_func_ip(void *ctx)
{
	if (!has_bpf_get_func_ip) {
		struct trace_kprobe *tk;
		u64 fp, ip;

		/* get frame pointer */
		asm volatile ("%[fp] = r10" : [fp] "+r"(fp) :);

		bpf_probe_read(&tk, sizeof(tk), (void *)(fp + kret_ip_off * sizeof(__u64)));
		ip = (__u64)BPF_CORE_READ(tk, rp.kp.addr);
		return ip;
	}

	return bpf_get_func_ip(ctx);
}
#else
static __always_inline u64 get_kret_func_ip(void *ctx)
{
	__u64 *has_bpf_get_func_ip, *kret_ip_off;
	__u64 len;
	int key;

	key = retsnoop_has_bpf_get_func_ip;
	has_bpf_get_func_ip = bpf_map_lookup_elem(&global_var, &key);
	if (!has_bpf_get_func_ip)
		return 0;

	key = retsnoop_kret_ip_off;
	kret_ip_off = bpf_map_lookup_elem(&global_var, &key);
	if (!kret_ip_off)
		return 0;

	if (!*has_bpf_get_func_ip) {
		struct trace_kprobe *tk;
		u64 fp, ip, ip_tmp;

		/* get frame pointer */
		asm volatile ("%[fp] = r10" : [fp] "+r"(fp) :);

		len = *kret_ip_off * sizeof(__u64);
		len = len & 511;
		bpf_probe_read(&tk, sizeof(tk), (void *)(fp + len));
		ip = (__u64)BPF_CORE_READ(tk, rp.kp.addr);
		return ip;
	}

	if (bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_get_func_ip))
		return bpf_get_func_ip(ctx);
	else
		return 0;
}
#endif

#ifndef BPF_NO_GLOBAL_DATA
static __always_inline void capture_lbrs(int cpu)
{
	long lbr_sz;

	if (!use_lbr)
		return;

	lbr_sz = bpf_get_branch_snapshot(&lbrs[cpu & MAX_CPU_MASK], sizeof(lbrs[0]), 0);
	lbr_szs[cpu & MAX_CPU_MASK] = lbr_sz;
}
#else
static __always_inline void capture_lbrs(int cpu)
{
	long lbr_sz;
	__u64 *use_lbr, *val;
	int key;
	struct perf_branch_entry_array *lbrs_ptr;

	key = retsnoop_use_lbr;
	use_lbr = bpf_map_lookup_elem(&global_var, &key);
	if (!use_lbr)
		return;

	if (!*use_lbr)
		return;

	if (!bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_get_branch_snapshot))
		return;

	key = cpu & MAX_CPU_MASK;
	lbrs_ptr = bpf_map_lookup_elem(&lbrs, &key);
	if (!lbrs_ptr)
		return;
	lbr_sz = bpf_get_branch_snapshot(lbrs_ptr, sizeof(struct perf_branch_entry_array), 0);
	key = cpu & MAX_CPU_MASK;
	val = bpf_map_lookup_elem(&lbr_szs, &key);
	if (!val)
		return;
	*val = lbr_sz;
}
#endif

#ifndef BPF_NO_GLOBAL_DATA
__hidden int copy_lbrs(void *dst, size_t dst_sz)
{
	int cpu;

	if (!use_lbr)
		return 0;

	cpu = bpf_get_smp_processor_id();
	bpf_probe_read_kernel(dst, dst_sz, &lbrs[cpu & MAX_CPU_MASK]);
	return lbr_szs[cpu & MAX_CPU_MASK];
}
#else
static __always_inline int copy_lbrs(void *dst, size_t dst_sz)
{
	int cpu;
	__u64 *use_lbr, *val;
	int key;
	struct perf_branch_entry_array *lbrs_ptr;

	key = retsnoop_use_lbr;
	use_lbr = bpf_map_lookup_elem(&global_var, &key);
	if (!use_lbr)
		return 0;

	if (!*use_lbr)
		return 0;

	cpu = bpf_get_smp_processor_id();
	key = cpu & MAX_CPU_MASK;
	lbrs_ptr = bpf_map_lookup_elem(&lbrs, &key);
	if (!lbrs_ptr)
		return 0;
	bpf_probe_read_kernel(dst, dst_sz, lbrs_ptr);

	key = cpu & MAX_CPU_MASK;
	val = bpf_map_lookup_elem(&lbr_szs, &key);
	if (!val)
		return 0;
	return *val;
}
#endif

SEC("kprobe")
#ifndef BPF_NO_GLOBAL_DATA
int kentry(struct pt_regs *ctx)
{
	const char *name;
	long ip;
	u32 id;

	if (!ready)
		return 0;

	if (has_bpf_get_func_ip) {
		ip = bpf_get_func_ip(ctx);
	} else {
#ifdef bpf_target_x86
		/* for x86 the IP is off by one at hardware level,
		 * see https://github.com/anakryiko/retsnoop/issues/32
		 */
		ip = PT_REGS_IP(ctx) - 1;
#else
		ip = PT_REGS_IP(ctx);
#endif
	}

	if (has_bpf_cookie) {
		id = bpf_get_attach_cookie(ctx);
	} else {
		u32 *id_ptr;

		id_ptr = bpf_map_lookup_elem(&ip_to_id, &ip);
		if (!id_ptr) {
			bpf_printk("KENTRY UNRECOGNIZED IP %lx", ip);
			return 0;
		}

		id = *id_ptr;
	}

	handle_func_entry(ctx, id, ip);
	return 0;
}
#else
int kentry(struct pt_regs *ctx)
{
	const char *name;
	long ip;
	u32 id;
	__u64 *ready, *has_bpf_get_func_ip, *has_bpf_cookie;
	int key;

	key = retsnoop_ready;
	ready = bpf_map_lookup_elem(&global_var, &key);
	if (!ready)
		return 0;

	if (!*ready)
		return 0;

	key = retsnoop_has_bpf_get_func_ip;
	has_bpf_get_func_ip = bpf_map_lookup_elem(&global_var, &key);
	if (!has_bpf_get_func_ip)
		return 0;

	if (*has_bpf_get_func_ip) {
		if (bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_get_func_ip)) {
			ip = bpf_get_func_ip(ctx);
		} else {
#ifdef bpf_target_x86
			/* for x86 the IP is off by one at hardware level,
			* see https://github.com/anakryiko/retsnoop/issues/32
			*/
			ip = PT_REGS_IP(ctx) - 1;
#else
			ip = PT_REGS_IP(ctx);
#endif
		}
	} else {
#ifdef bpf_target_x86
		/* for x86 the IP is off by one at hardware level,
		 * see https://github.com/anakryiko/retsnoop/issues/32
		 */
		ip = PT_REGS_IP(ctx) - 1;
#else
		ip = PT_REGS_IP(ctx);
#endif
	}

	key = retsnoop_has_bpf_cookie;
	has_bpf_cookie = bpf_map_lookup_elem(&global_var, &key);
	if (!has_bpf_cookie)
		return 0;

	if (*has_bpf_cookie) {
		if (bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_get_attach_cookie)) {
			id = bpf_get_attach_cookie(ctx);
		} else {
			u32 *id_ptr;

			id_ptr = bpf_map_lookup_elem(&ip_to_id, &ip);
			if (!id_ptr) {
				bpf_printk("KENTRY UNRECOGNIZED IP %lx", ip);
				return 0;
			}

			id = *id_ptr;
		}
	} else {
		u32 *id_ptr;

		id_ptr = bpf_map_lookup_elem(&ip_to_id, &ip);
		if (!id_ptr) {
			bpf_printk("KENTRY UNRECOGNIZED IP %lx", ip);
			return 0;
		}

		id = *id_ptr;
	}

	handle_func_entry(ctx, id, ip);
	return 0;
}
#endif

SEC("kretprobe")
#ifndef BPF_NO_GLOBAL_DATA
int kexit(struct pt_regs *ctx)
{
	const char *name;
	u32 id, cpu;
	long ip;

	if (!ready)
		return 0;

	cpu = bpf_get_smp_processor_id();
	capture_lbrs(cpu);

	ip = get_kret_func_ip(ctx);

	if (has_bpf_cookie) {
		id = bpf_get_attach_cookie(ctx);
	} else {
		u32 *id_ptr;

		id_ptr = bpf_map_lookup_elem(&ip_to_id, &ip);
		if (!id_ptr) {
			bpf_printk("KEXIT UNRECOGNIZED IP %lx", ip);
			return 0;
		}

		id = *id_ptr;
	}

	handle_func_exit(ctx, id, ip, PT_REGS_RC(ctx));

	return 0;
}
#else
SEC("kretprobe")
int kexit(struct pt_regs *ctx)
{
	const char *name;
	u32 id, cpu;
	long ip;
	__u64 *ready, *has_bpf_cookie;
	int key;

	key = retsnoop_ready;
	ready = bpf_map_lookup_elem(&global_var, &key);
	if (!ready)
		return 0;

	if (!*ready)
		return 0;

	ip = get_kret_func_ip(ctx);

	cpu = bpf_get_smp_processor_id();
	capture_lbrs(cpu);

	key = retsnoop_has_bpf_cookie;
	has_bpf_cookie = bpf_map_lookup_elem(&global_var, &key);
	if (!has_bpf_cookie)
		return 0;
	if (*has_bpf_cookie) {
		if (bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_get_attach_cookie)) {
			id = bpf_get_attach_cookie(ctx);
		} else {
			u32 *id_ptr;

			id_ptr = bpf_map_lookup_elem(&ip_to_id, &ip);
			if (!id_ptr) {
				bpf_printk("KEXIT UNRECOGNIZED IP %lx", ip);
				return 0;
			}

			id = *id_ptr;
		}
	} else {
		u32 *id_ptr;

		id_ptr = bpf_map_lookup_elem(&ip_to_id, &ip);
		if (!id_ptr) {
			bpf_printk("KEXIT UNRECOGNIZED IP %lx", ip);
			return 0;
		}

		id = *id_ptr;
	}

	handle_func_exit(ctx, id, ip, PT_REGS_RC(ctx));

	return 0;
}
#endif

#ifndef BPF_NO_GLOBAL_DATA
int running[MAX_CPU_CNT] = {};

static __always_inline bool recur_enter(u32 cpu)
{
	if (running[cpu & MAX_CPU_MASK])
		return false;

	running[cpu & MAX_CPU_MASK] += 1;

	return true;
}

static __always_inline void recur_exit(u32 cpu)
{
	running[cpu & MAX_CPU_MASK] -= 1;
}
#else
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, __u64);
	__uint(max_entries, MAX_CPU_CNT); /* could be overriden from user-space */
} running SEC(".maps");

static __always_inline bool recur_enter(u32 cpu)
{
	int key;
	__u64 *val;

	key = cpu & MAX_CPU_MASK;
	val = bpf_map_lookup_elem(&running, &key);
	if (!val)
		return false;
	if (*val)
		return false;

	*val += 1;

	return true;
}

static __always_inline void recur_exit(u32 cpu)
{
	int key;
	__u64 *val;

	key = cpu & MAX_CPU_MASK;
	val = bpf_map_lookup_elem(&running, &key);
	if (!val)
		return;

	*val -= 1;
}
#endif

#ifndef BPF_NO_GLOBAL_DATA
static __always_inline u64 get_ftrace_func_ip(void *ctx, int arg_cnt)
{
	if (!has_bpf_get_func_ip) {
		u64 off = 1 /* skip orig rbp */
			+ 1 /* skip reserved space for ret value */;
		u64 ip;

		if (arg_cnt <= 6)
			off += arg_cnt;
		else
			off += 6;
		off = (u64)ctx + off * 8;

		if (bpf_probe_read_kernel(&ip, sizeof(ip), (void *)off))
			return 0;

		ip -= 5; /* compensate for 5-byte fentry stub */
		return ip;
	}

	return bpf_get_func_ip(ctx);
}
#else
static __always_inline u64 get_ftrace_func_ip(void *ctx, int arg_cnt)
{
	__u64 *has_bpf_get_func_ip;
	int key;

	key = retsnoop_has_bpf_get_func_ip;
	has_bpf_get_func_ip = bpf_map_lookup_elem(&global_var, &key);
	if (!has_bpf_get_func_ip)
		return 0;
	if (!*has_bpf_get_func_ip) {
		u64 off = 1 /* skip orig rbp */
			+ 1 /* skip reserved space for ret value */;
		u64 ip;

		if (arg_cnt <= 6)
			off += arg_cnt;
		else
			off += 6;
		off = (u64)ctx + off * 8;

		if (bpf_probe_read_kernel(&ip, sizeof(ip), (void *)off))
			return 0;

		ip -= 5; /* compensate for 5-byte fentry stub */
		return ip;
	}

	if (bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_get_func_ip))
		return bpf_get_func_ip(ctx);
	else
		return 0;
}
#endif

/* we need arg_cnt * sizeof(__u64) to be a constant, so need to inline */
#ifndef BPF_NO_GLOBAL_DATA
static __always_inline int handle_fentry(void *ctx, int arg_cnt)
{
	u32 *id_ptr, cpu;
	const char *name;
	long ip;

	if (!ready)
		return 0;

	cpu = bpf_get_smp_processor_id();
	if (!recur_enter(cpu))
		return 0;

	ip = get_ftrace_func_ip(ctx, arg_cnt);
	id_ptr = bpf_map_lookup_elem(&ip_to_id, &ip);
	if (!id_ptr) {
		bpf_printk("UNRECOGNIZED FENTRY IP %lx ARG_CNT %d", ip, arg_cnt);
		goto out;
	}

	handle_func_entry(ctx, *id_ptr, ip);

out:
	recur_exit(cpu);
	return 0;
}
#else
static __always_inline int handle_fentry(void *ctx, int arg_cnt)
{
	u32 *id_ptr, cpu;
	const char *name;
	long ip;
	__u64 *ready;
	int key;

	key = retsnoop_ready;
	ready = bpf_map_lookup_elem(&global_var, &key);
	if (!ready)
		return 0;

	if (!*ready)
		return 0;

	cpu = bpf_get_smp_processor_id();
	if (!recur_enter(cpu))
		return 0;

	ip = get_ftrace_func_ip(ctx, arg_cnt);
	id_ptr = bpf_map_lookup_elem(&ip_to_id, &ip);
	if (!id_ptr) {
		bpf_printk("UNRECOGNIZED FENTRY IP %lx ARG_CNT %d", ip, arg_cnt);
		goto out;
	}

	handle_func_entry(ctx, *id_ptr, ip);

out:
	recur_exit(cpu);
	return 0;
}
#endif

/* we need arg_cnt * sizeof(__u64) to be a constant, so need to inline */
#ifndef BPF_NO_GLOBAL_DATA
static __always_inline int handle_fexit(void *ctx, int arg_cnt, bool is_void_ret)
{
	u32 *id_ptr, cpu;
	const char *name;
	long ip;
	u64 res;

	if (!ready)
		return 0;

	cpu = bpf_get_smp_processor_id();
	if (!recur_enter(cpu))
		return 0;

	capture_lbrs(cpu);

	ip = get_ftrace_func_ip(ctx, arg_cnt);
	id_ptr = bpf_map_lookup_elem(&ip_to_id, &ip);
	if (!id_ptr) {
		bpf_printk("UNRECOGNIZED FEXIT IP %lx ARG_CNT %d", ip, arg_cnt);
		goto out;
	}

	res = is_void_ret ? 0 : *(u64 *)(ctx + sizeof(u64) * arg_cnt);
	handle_func_exit(ctx, *id_ptr, ip, res);

out:
	recur_exit(cpu);
	return 0;
}
#else
static __always_inline int handle_fexit(void *ctx, int arg_cnt, bool is_void_ret)
{
	u32 *id_ptr, cpu;
	const char *name;
	long ip;
	u64 res;
	__u64 *ready;
	int key;

	key = retsnoop_ready;
	ready = bpf_map_lookup_elem(&global_var, &key);
	if (!ready)
		return 0;

	if (!*ready)
		return 0;

	cpu = bpf_get_smp_processor_id();
	if (!recur_enter(cpu))
		return 0;

	capture_lbrs(cpu);

	ip = get_ftrace_func_ip(ctx, arg_cnt);
	id_ptr = bpf_map_lookup_elem(&ip_to_id, &ip);
	if (!id_ptr) {
		bpf_printk("UNRECOGNIZED FEXIT IP %lx ARG_CNT %d", ip, arg_cnt);
		goto out;
	}

	res = is_void_ret ? 0 : *(u64 *)(ctx + sizeof(u64) * arg_cnt);
	handle_func_exit(ctx, *id_ptr, ip, res);

out:
	recur_exit(cpu);
	return 0;
}
#endif

#define DEF_PROGS(arg_cnt) \
SEC("fentry") \
int fentry ## arg_cnt(void *ctx) \
{ \
	return handle_fentry(ctx, arg_cnt); \
} \
SEC("fexit") \
int fexit ## arg_cnt(void *ctx) \
{ \
	return handle_fexit(ctx, arg_cnt, false /*is_void_ret*/); \
} \
SEC("fexit") \
int fexit_void ## arg_cnt(void *ctx) \
{ \
	return handle_fexit(ctx, arg_cnt, true /*is_void_ret*/); \
}

DEF_PROGS(0)
DEF_PROGS(1)
DEF_PROGS(2)
DEF_PROGS(3)
DEF_PROGS(4)
DEF_PROGS(5)
DEF_PROGS(6)
