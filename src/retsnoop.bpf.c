// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2021 Facebook */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "retsnoop.h"
#ifdef BPF_NO_GLOBAL_DATA
#include "mass_attach.bpf.c"
#endif

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define printk_is_sane (bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_snprintf))

#define printk_needs_endline (!bpf_core_type_exists(struct trace_event_raw_bpf_trace_printk))

#define APPEND_ENDLINE(fmt) fmt[sizeof(fmt) - 2] = '\n'

#ifdef BPF_NO_GLOBAL_DATA
#define BPF_PRINTK_FMT_MOD_1
#else
#define BPF_PRINTK_FMT_MOD_1 static
#endif

#undef bpf_printk
#define bpf_printk(fmt, ...)						\
({									\
	BPF_PRINTK_FMT_MOD_1 char ___fmt[] = fmt " ";					\
	if (printk_needs_endline)					\
		APPEND_ENDLINE(___fmt);					\
	bpf_trace_printk(___fmt, sizeof(___fmt), ##__VA_ARGS__);	\
})

#define barrier_var(var) asm volatile("" : "=r"(var) : "0"(var))

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, struct call_stack);
} stacks SEC(".maps");

#ifndef BPF_NO_GLOBAL_DATA
const volatile bool verbose = false;
const volatile bool extra_verbose = false;
const volatile bool use_ringbuf = false;
const volatile bool use_lbr = false;
const volatile int targ_tgid = 0;
const volatile bool emit_success_stacks = false;
const volatile bool emit_intermediate_stacks = false;
const volatile bool emit_func_trace = false;
#endif

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, bool);
	__uint(max_entries, 1); /* could be overriden from user-space */
} tgids_filter SEC(".maps");

#ifndef BPF_NO_GLOBAL_DATA
const volatile __u32 tgid_allow_cnt = 0;
const volatile __u32 tgid_deny_cnt = 0;
#endif

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, char[TASK_COMM_LEN]);
	__uint(max_entries, 1); /* could be overriden from user-space */
} comms_filter SEC(".maps");

#ifndef BPF_NO_GLOBAL_DATA
const volatile __u32 comm_allow_cnt = 0;
const volatile __u32 comm_deny_cnt = 0;

const volatile __u64 duration_ns = 0;
#endif

#ifndef BPF_NO_GLOBAL_DATA
char func_names[MAX_FUNC_CNT][MAX_FUNC_NAME_LEN] = {};
#else
struct func_names_type {
	char f_name[MAX_FUNC_NAME_LEN];
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct func_names_type);
	__uint(max_entries, MAX_FUNC_CNT); /* could be overriden from user-space */
} func_names SEC(".maps");
#endif

#ifndef BPF_NO_GLOBAL_DATA
__u64 func_ips[MAX_FUNC_CNT] = {};
#else
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, __u64);
	__uint(max_entries, MAX_FUNC_CNT); /* could be overriden from user-space */
} func_ips SEC(".maps");
#endif

#ifndef BPF_NO_GLOBAL_DATA
int func_flags[MAX_FUNC_CNT] = {};
#else
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, __u64);
	__uint(max_entries, MAX_FUNC_CNT); /* could be overriden from user-space */
} func_flags SEC(".maps");
#endif

#ifndef BPF_NO_GLOBAL_DATA
const volatile char spaces[512] = {};
#else
struct space_type {
	char space[512];
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct space_type);
	__uint(max_entries, 1); /* could be overriden from user-space */
} spaces SEC(".maps");
#endif

/* provided by mass_attach.bpf.c */
#ifndef BPF_NO_GLOBAL_DATA
int copy_lbrs(void *dst, size_t dst_sz);
#else
static __always_inline int copy_lbrs(void *dst, size_t dst_sz);
#endif

#ifndef BPF_NO_GLOBAL_DATA
static __always_inline int output_stack(void *ctx, void *map, struct call_stack *stack)
{
	stack->emit_ts = bpf_ktime_get_ns();

	if (duration_ns && stack->emit_ts - stack->func_lat[0] < duration_ns)
		return 0;

	if (!stack->is_err) {
		stack->kstack_sz = bpf_get_stack(ctx, &stack->kstack, sizeof(stack->kstack), 0);
		stack->lbrs_sz = copy_lbrs(&stack->lbrs, sizeof(stack->lbrs));
	}

	/* use_ringbuf is read-only variable, so verifier will detect which of
	 * the branch is dead code and will eliminate it, so on old kernels
	 * bpf_ringbuf_output() won't be present in the resulting code
	 */
	if (use_ringbuf)
		return bpf_ringbuf_output(map, stack, sizeof(*stack), 0);
	else
		return bpf_perf_event_output(ctx, map, BPF_F_CURRENT_CPU, stack, sizeof(*stack));
}
#else
static __always_inline int output_stack(void *ctx, void *map, struct call_stack *stack)
{
	__u64 *duration_ns, *use_ringbuf;
	int key;

	stack->emit_ts = bpf_ktime_get_ns();

	key = retsnoop_duration_ns;
	duration_ns = bpf_map_lookup_elem(&global_var, &key);
	if (!duration_ns)
		return 0;

	if (*duration_ns && stack->emit_ts - stack->func_lat[0] < *duration_ns)
		return 0;

	if (!stack->is_err) {
		stack->kstack_sz = bpf_get_stack(ctx, &stack->kstack, sizeof(stack->kstack), 0);
		stack->lbrs_sz = copy_lbrs(&stack->lbrs, sizeof(stack->lbrs));
	}

	/* use_ringbuf is read-only variable, so verifier will detect which of
	 * the branch is dead code and will eliminate it, so on old kernels
	 * bpf_ringbuf_output() won't be present in the resulting code
	 */
	key = retsnoop_use_ringbuf;
	use_ringbuf = bpf_map_lookup_elem(&global_var, &key);
	if (!use_ringbuf)
		return 0;
	if (*use_ringbuf && bpf_core_enum_value_exists(enum bpf_map_type, BPF_MAP_TYPE_RINGBUF))
		return bpf_ringbuf_output(map, stack, sizeof(*stack), 0);
	if (!bpf_core_enum_value_exists(enum bpf_map_type, BPF_MAP_TYPE_RINGBUF))
		return bpf_perf_event_output(ctx, map, BPF_F_CURRENT_CPU, stack, sizeof(*stack));

	return 0;
}
#endif

#ifndef BPF_NO_GLOBAL_DATA
static __noinline void save_stitch_stack(void *ctx, struct call_stack *stack)
{
	u64 d = stack->depth;
	u64 len = stack->max_depth - d;

	if (d >= MAX_FSTACK_DEPTH || len >= MAX_FSTACK_DEPTH) {
		bpf_printk("SHOULDN'T HAPPEN DEPTH %ld LEN %ld\n", d, len);
		return;
	}

	if (extra_verbose) {
		bpf_printk("CURRENT DEPTH %d..%d", stack->depth + 1, stack->max_depth);
		bpf_printk("SAVED DEPTH %d..%d", stack->saved_depth, stack->saved_max_depth);
	}

	/* we can stitch together stack subsections */
	if (stack->saved_depth && stack->max_depth + 1 == stack->saved_depth) {
		bpf_probe_read(stack->saved_ids + d, len * sizeof(stack->saved_ids[0]), stack->func_ids + d);
		bpf_probe_read(stack->saved_res + d, len * sizeof(stack->saved_res[0]), stack->func_res + d);
		bpf_probe_read(stack->saved_lat + d, len * sizeof(stack->saved_lat[0]), stack->func_lat + d);
		stack->saved_depth = stack->depth + 1;
		if (extra_verbose)
			bpf_printk("STITCHED STACK %d..%d to ..%d\n",
				   stack->depth + 1, stack->max_depth, stack->saved_max_depth);
		return;
	}

	if (emit_intermediate_stacks) {
		/* we are partially overriding previous stack, so emit error stack, if present */
		if (extra_verbose)
			bpf_printk("EMIT PARTIAL STACK DEPTH %d..%d\n", stack->depth + 1, stack->max_depth);
		output_stack(ctx, &rb, stack);
	} else if (extra_verbose) {
		bpf_printk("RESETTING SAVED ERR STACK %d..%d to %d..\n",
			   stack->saved_depth, stack->saved_max_depth, stack->depth + 1);
	}

	bpf_probe_read(stack->saved_ids + d, len * sizeof(stack->saved_ids[0]), stack->func_ids + d);
	bpf_probe_read(stack->saved_res + d, len * sizeof(stack->saved_res[0]), stack->func_res + d);
	bpf_probe_read(stack->saved_lat + d, len * sizeof(stack->saved_lat[0]), stack->func_lat + d);

	stack->saved_depth = stack->depth + 1;
	stack->saved_max_depth = stack->max_depth;
}
#else
static __always_inline void save_stitch_stack(void *ctx, struct call_stack *stack)
{
	u64 d = stack->depth;
	u64 len = stack->max_depth - d;
	u64 cnt;
	__u64 *val;
	__u64 extra_verbose, emit_intermediate_stacks;
	int key;

	if (d >= MAX_FSTACK_DEPTH || len >= MAX_FSTACK_DEPTH) {
		bpf_printk("SHOULDN'T HAPPEN DEPTH %ld LEN %ld\n", d, len);
		return;
	}

	key = retsnoop_extra_verbose;
	val = bpf_map_lookup_elem(&global_var, &key);
	if (!val)
		return;
	extra_verbose = *val;

	key = retsnoop_emit_intermediate_stacks;
	val = bpf_map_lookup_elem(&global_var, &key);
	if (!val)
		return;
	emit_intermediate_stacks = *val;

	if (extra_verbose) {
		bpf_printk("CURRENT DEPTH %d..%d", stack->depth + 1, stack->max_depth);
		bpf_printk("SAVED DEPTH %d..%d", stack->saved_depth, stack->saved_max_depth);
	}

	/* we can stitch together stack subsections */
	if (stack->saved_depth && stack->max_depth + 1 == stack->saved_depth) {
		d = d & (MAX_FSTACK_DEPTH-1);
		cnt = len * 2;
		cnt = cnt & (MAX_FSTACK_DEPTH-1);
		bpf_probe_read(stack->saved_ids + d, cnt, stack->func_ids + d);
		barrier_var(d);
		barrier_var(cnt);
		d = d & (MAX_FSTACK_DEPTH-1);
		cnt = cnt & (MAX_FSTACK_DEPTH-1);
		bpf_probe_read(stack->saved_res + d, cnt, stack->func_res + d);
		barrier_var(d);
		barrier_var(cnt);
		d = d & (MAX_FSTACK_DEPTH-1);
		cnt = cnt & (MAX_FSTACK_DEPTH-1);
		bpf_probe_read(stack->saved_lat + d, cnt, stack->func_lat + d);
		stack->saved_depth = stack->depth + 1;
		if (extra_verbose)
			bpf_printk("STITCHED STACK %d..%d to ..%d\n",
				   stack->depth + 1, stack->max_depth, stack->saved_max_depth);
		return;
	}

	if (emit_intermediate_stacks) {
		/* we are partially overriding previous stack, so emit error stack, if present */
		if (extra_verbose)
			bpf_printk("EMIT PARTIAL STACK DEPTH %d..%d\n", stack->depth + 1, stack->max_depth);
		output_stack(ctx, &rb, stack);
	} else if (extra_verbose) {
		bpf_printk("RESETTING SAVED ERR STACK %d..%d to %d..\n",
			   stack->saved_depth, stack->saved_max_depth, stack->depth + 1);
	}

	d = d & (MAX_FSTACK_DEPTH-1);
	cnt = len * 2;
	cnt = cnt & (MAX_FSTACK_DEPTH-1);
	bpf_probe_read(stack->saved_ids + d, cnt, stack->func_ids + d);
	barrier_var(d);
	barrier_var(cnt);
	d = d & (MAX_FSTACK_DEPTH-1);
	cnt = cnt & (MAX_FSTACK_DEPTH-1);
	bpf_probe_read(stack->saved_res + d, cnt, stack->func_res + d);
	barrier_var(d);
	barrier_var(cnt);
	d = d & (MAX_FSTACK_DEPTH-1);
	cnt = cnt & (MAX_FSTACK_DEPTH-1);
	bpf_probe_read(stack->saved_lat + d, cnt, stack->func_lat + d);

	stack->saved_depth = stack->depth + 1;
	stack->saved_max_depth = stack->max_depth;
}
#endif


#ifndef BPF_NO_GLOBAL_DATA
static const struct call_stack empty_stack;
#else
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct call_stack);
	__uint(max_entries, 1); /* could be overriden from user-space */
} empty_stack SEC(".maps");
#endif

#ifndef BPF_NO_GLOBAL_DATA
static __noinline bool push_call_stack(void *ctx, u32 id, u64 ip)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = (u32)pid_tgid;
	struct call_stack *stack;
	u64 d;

	stack = bpf_map_lookup_elem(&stacks, &pid);
	if (!stack) {
		struct task_struct *tsk;

		if (!(func_flags[id & MAX_FUNC_MASK] & FUNC_IS_ENTRY))
			return false;

		bpf_map_update_elem(&stacks, &pid, &empty_stack, BPF_ANY);
		stack = bpf_map_lookup_elem(&stacks, &pid);
		if (!stack)
			return false;

		stack->type = REC_CALL_STACK;
		stack->start_ts = bpf_ktime_get_ns();
		stack->pid = pid;
		stack->tgid = (u32)(pid_tgid >> 32);
		bpf_get_current_comm(&stack->task_comm, sizeof(stack->task_comm));
		tsk = (void *)bpf_get_current_task();
		BPF_CORE_READ_INTO(&stack->proc_comm, tsk, group_leader, comm);

		if (emit_func_trace) {
			struct func_trace_start *r;

			r = bpf_ringbuf_reserve(&rb, sizeof(*r), 0);
			if (r) {
				r->type = REC_FUNC_TRACE_START;
				r->pid = stack->pid;

				bpf_ringbuf_submit(r, 0);
			}
		}
	}

	d = stack->depth;
	barrier_var(d);
	if (d >= MAX_FSTACK_DEPTH)
		return false;

	if (stack->depth != stack->max_depth && stack->is_err)
		save_stitch_stack(ctx, stack);

	stack->func_ids[d] = id;
	stack->is_err = false;
	stack->depth = d + 1;
	stack->max_depth = d + 1;
	stack->func_lat[d] = bpf_ktime_get_ns();
	stack->next_seq_id++;

	if (emit_func_trace) {
		struct func_trace_entry *fe;

		fe = bpf_ringbuf_reserve(&rb, sizeof(*fe), 0);
		if (!fe)
			goto skip_ft_entry;

		fe->type = REC_FUNC_TRACE_ENTRY;
		fe->ts = bpf_ktime_get_ns();
		fe->pid = pid;
		fe->seq_id = stack->next_seq_id - 1;
		fe->depth = d + 1;
		fe->func_id = id;
		fe->func_lat = 0;
		fe->func_res = 0;

		bpf_ringbuf_submit(fe, 0);
skip_ft_entry:;
	}

	if (verbose) {
		const char *func_name = func_names[id & MAX_FUNC_MASK];

		if (printk_is_sane) {
			if (d == 0)
				bpf_printk("=== STARTING TRACING %s [COMM %s PID %d] ===",
					   func_name, stack->task_comm, pid);
			bpf_printk("    ENTER %s%s [...]", spaces + 2 * ((255 - d) & 0xFF), func_name);
		} else {
			if (d == 0) {
				bpf_printk("=== STARTING TRACING %s [PID %d] ===", func_name, pid);
				bpf_printk("=== ...      TRACING [PID %d COMM %s] ===", pid, stack->task_comm);
			}
			bpf_printk("    ENTER [%d] %s [...]", d + 1, func_name);
		}
		//bpf_printk("PUSH(2) ID %d ADDR %lx NAME %s", id, ip, func_name);
	}

	return true;
}
#else
static __always_inline bool push_call_stack(void *ctx, u32 id, u64 ip)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = (u32)pid_tgid;
	struct call_stack *stack;
	u64 d;
	__u64 *func_flags_ptr, *empty_stack_ptr, *val;
	int key;
	__u64 verbose, emit_func_trace;
	struct space_type *spaces_ptr;

	key = retsnoop_verbose;
	val = bpf_map_lookup_elem(&global_var, &key);
	if (!val)
		return 0;
	verbose = *val;

	key = retsnoop_emit_func_trace;
	val = bpf_map_lookup_elem(&global_var, &key);
	if (!val)
		return 0;
	emit_func_trace = *val;

	stack = bpf_map_lookup_elem(&stacks, &pid);
	if (!stack) {
		struct task_struct *tsk;

		key = id & MAX_FUNC_MASK;
		func_flags_ptr = bpf_map_lookup_elem(&func_flags, &key);
		if (!func_flags_ptr || !(*func_flags_ptr & FUNC_IS_ENTRY))
			return false;

		key = 0;
		empty_stack_ptr = bpf_map_lookup_elem(&empty_stack, &key);
		if (!empty_stack_ptr)
			return false;

		bpf_map_update_elem(&stacks, &pid, empty_stack_ptr, BPF_ANY);
		stack = bpf_map_lookup_elem(&stacks, &pid);
		if (!stack)
			return false;

		stack->type = REC_CALL_STACK;
		stack->start_ts = bpf_ktime_get_ns();
		stack->pid = pid;
		stack->tgid = (u32)(pid_tgid >> 32);
		bpf_get_current_comm(&stack->task_comm, sizeof(stack->task_comm));
		tsk = (void *)bpf_get_current_task();
		BPF_CORE_READ_INTO(&stack->proc_comm, tsk, group_leader, comm);

		if (bpf_core_enum_value_exists(enum bpf_map_type, BPF_MAP_TYPE_RINGBUF)) {
			struct func_trace_start *r;

			r = bpf_ringbuf_reserve(&rb, sizeof(*r), 0);
			if (r) {
				r->type = REC_FUNC_TRACE_START;
				r->pid = stack->pid;

				bpf_ringbuf_submit(r, 0);
			}
		}
	}

	d = stack->depth;
	barrier_var(d);
	if (d >= MAX_FSTACK_DEPTH)
		return false;

	if (stack->depth != stack->max_depth && stack->is_err)
		save_stitch_stack(ctx, stack);

	d = d & (MAX_FSTACK_DEPTH-1);
	barrier_var(d);

	stack->func_ids[d & (MAX_FSTACK_DEPTH-1)] = id;
	stack->is_err = false;
	stack->depth = d + 1;
	stack->max_depth = d + 1;
	stack->func_lat[d & (MAX_FSTACK_DEPTH-1)] = bpf_ktime_get_ns();
	stack->next_seq_id++;

	if (emit_func_trace) {
		if (bpf_core_enum_value_exists(enum bpf_map_type, BPF_MAP_TYPE_RINGBUF)) {
			struct func_trace_entry *fe;

			fe = bpf_ringbuf_reserve(&rb, sizeof(*fe), 0);
			if (!fe)
				goto skip_ft_entry;

			fe->type = REC_FUNC_TRACE_ENTRY;
			fe->ts = bpf_ktime_get_ns();
			fe->pid = pid;
			fe->seq_id = stack->next_seq_id - 1;
			fe->depth = d + 1;
			fe->func_id = id;
			fe->func_lat = 0;
			fe->func_res = 0;

			bpf_ringbuf_submit(fe, 0);
		}
skip_ft_entry:;
	}

	if (verbose) {
		//const char *func_name = func_names[id & MAX_FUNC_MASK];
		const char *func_name_ptr;
		key = id & MAX_FUNC_MASK;
		func_name_ptr = bpf_map_lookup_elem(&func_names, &key);
		if (!func_name_ptr)
			return false;

		struct space_type *spaces_ptr;
		key = 0;
		spaces_ptr = bpf_map_lookup_elem(&spaces, &key);
		if (!spaces_ptr)
			return false;

		if (printk_is_sane) {
			if (d == 0)
				bpf_printk("=== STARTING TRACING %s [COMM %s PID %d] ===",
					   func_name_ptr, stack->task_comm, pid);
			bpf_printk("    ENTER %s%s [...]", spaces_ptr->space + 2 * ((255 - d) & 0xFF), func_name_ptr);
		} else {
			if (d == 0) {
				bpf_printk("=== STARTING TRACING %s [PID %d] ===", func_name_ptr, pid);
				bpf_printk("=== ...      TRACING [PID %d COMM %s] ===", pid, stack->task_comm);
			}
			bpf_printk("    ENTER [%d] %s [...]", d + 1, func_name_ptr);
		}
		//bpf_printk("PUSH(2) ID %d ADDR %lx NAME %s", id, ip, func_name_ptr);
	}

	return true;
}
#endif

#define MAX_ERRNO 4095

static __always_inline bool IS_ERR_VALUE(long x)
{
	return (unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO;
}

static __always_inline bool IS_ERR_VALUE32(u64 x)
{
	/* Due to BPF verifier limitations, it's really hard to do int to long
	 * sign extension generically, because some return types might be
	 * pointers and BPF verifier really hates us for treating pointer as
	 * integer and doing arbitrary (bit shifts) arithmetics on it.  So
	 * instead we just assume we have a 32-bit signed integer and check
	 * manually that it's value unsigned value lies in [-4095, 1] range.
	 * -1 is 0xffffffff, -4095 is 0xfffff001. Easy.
	 */
	if (x < 0xfffff001)
		return false;
	/* prevent clever Clang optimizaations involving math */
	barrier_var(x);
	if (x > 0xffffffff)
		return false;
	return true;
}

#ifndef BPF_NO_GLOBAL_DATA
/* all length should be the same */
char FMT_SUCC_VOID[]         = "    EXIT  %s%s [VOID]     ";
char FMT_SUCC_TRUE[]         = "    EXIT  %s%s [true]     ";
char FMT_SUCC_FALSE[]        = "    EXIT  %s%s [false]    ";
char FMT_FAIL_NULL[]         = "[!] EXIT  %s%s [NULL]     ";
char FMT_FAIL_PTR[]          = "[!] EXIT  %s%s [%d]       ";
char FMT_SUCC_PTR[]          = "    EXIT  %s%s [0x%lx]    ";
char FMT_FAIL_LONG[]         = "[!] EXIT  %s%s [%ld]      ";
char FMT_SUCC_LONG[]         = "    EXIT  %s%s [%ld]      ";
char FMT_FAIL_INT[]          = "[!] EXIT  %s%s [%d]       ";
char FMT_SUCC_INT[]          = "    EXIT  %s%s [%d]       ";

char FMT_SUCC_VOID_COMPAT[]  = "    EXIT  [%d] %s [VOID]  ";
char FMT_SUCC_TRUE_COMPAT[]  = "    EXIT  [%d] %s [true]  ";
char FMT_SUCC_FALSE_COMPAT[] = "    EXIT  [%d] %s [false] ";
char FMT_FAIL_NULL_COMPAT[]  = "[!] EXIT  [%d] %s [NULL]  ";
char FMT_FAIL_PTR_COMPAT[]   = "[!] EXIT  [%d] %s [%d]    ";
char FMT_SUCC_PTR_COMPAT[]   = "    EXIT  [%d] %s [0x%lx] ";
char FMT_FAIL_LONG_COMPAT[]  = "[!] EXIT  [%d] %s [%ld]   ";
char FMT_SUCC_LONG_COMPAT[]  = "    EXIT  [%d] %s [%ld]   ";
char FMT_FAIL_INT_COMPAT[]   = "[!] EXIT  [%d] %s [%d]    ";
char FMT_SUCC_INT_COMPAT[]   = "    EXIT  [%d] %s [%d]    ";
#else
struct fmt_type {
	char fmt[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct fmt_type);
	__uint(max_entries, FMT_CNT); /* could be overriden from user-space */
} insn_fmt SEC(".maps");
#endif

#ifndef BPF_NO_GLOBAL_DATA
static __noinline void print_exit(void *ctx, __u32 d, __u32 id, long res)
{
	const char *func_name = func_names[id & MAX_FUNC_MASK];
	const size_t FMT_MAX_SZ = sizeof(FMT_SUCC_PTR_COMPAT); /* UPDATE IF NECESSARY */
	u32 flags, fmt_sz;
	const char *fmt;
	bool failed;

	if (printk_needs_endline) {
		/* before bpf_trace_printk() started using underlying
		 * tracepoint mechanism for logging to trace_pipe it didn't
		 * automatically append endline, so we need to adjust our
		 * format strings to have \n, otherwise we'll have a dump of
		 * unseparate log lines
		 */
		APPEND_ENDLINE(FMT_SUCC_VOID);
		APPEND_ENDLINE(FMT_SUCC_TRUE);
		APPEND_ENDLINE(FMT_SUCC_FALSE);
		APPEND_ENDLINE(FMT_FAIL_NULL);
		APPEND_ENDLINE(FMT_FAIL_PTR);
		APPEND_ENDLINE(FMT_SUCC_PTR);
		APPEND_ENDLINE(FMT_FAIL_LONG);
		APPEND_ENDLINE(FMT_SUCC_LONG);
		APPEND_ENDLINE(FMT_FAIL_INT);
		APPEND_ENDLINE(FMT_SUCC_INT);

		APPEND_ENDLINE(FMT_SUCC_VOID_COMPAT);
		APPEND_ENDLINE(FMT_SUCC_TRUE_COMPAT);
		APPEND_ENDLINE(FMT_SUCC_FALSE_COMPAT);
		APPEND_ENDLINE(FMT_FAIL_NULL_COMPAT);
		APPEND_ENDLINE(FMT_FAIL_PTR_COMPAT);
		APPEND_ENDLINE(FMT_SUCC_PTR_COMPAT);
		APPEND_ENDLINE(FMT_FAIL_LONG_COMPAT);
		APPEND_ENDLINE(FMT_SUCC_LONG_COMPAT);
		APPEND_ENDLINE(FMT_FAIL_INT_COMPAT);
		APPEND_ENDLINE(FMT_SUCC_INT_COMPAT);
	}

	flags = func_flags[id & MAX_FUNC_MASK];
	if (flags & FUNC_RET_VOID) {
		fmt = printk_is_sane ? FMT_SUCC_VOID : FMT_SUCC_VOID_COMPAT;
		failed = false;
	} else if (flags & FUNC_RET_PTR) {
		/* consider NULL pointer an error */
		failed = (res == 0) || IS_ERR_VALUE(res);
		if (printk_is_sane)
			fmt = failed ? (res ? FMT_FAIL_PTR : FMT_FAIL_NULL) : FMT_SUCC_PTR;
		else
			fmt = failed ? (res ? FMT_FAIL_PTR_COMPAT : FMT_FAIL_NULL_COMPAT) : FMT_SUCC_PTR_COMPAT;
	} else if (flags & FUNC_RET_BOOL) {
		if (printk_is_sane)
			fmt = res ? FMT_SUCC_TRUE : FMT_SUCC_FALSE;
		else
			fmt = res ? FMT_SUCC_TRUE_COMPAT : FMT_SUCC_FALSE_COMPAT;
		failed = false;
	} else if (flags & FUNC_NEEDS_SIGN_EXT) {
		failed = IS_ERR_VALUE32(res);
		if (failed)
			fmt = printk_is_sane ? FMT_FAIL_INT : FMT_FAIL_INT_COMPAT;
		else
			fmt = printk_is_sane ? FMT_SUCC_INT : FMT_SUCC_INT_COMPAT;
	} else {
		failed = IS_ERR_VALUE(res);
		if (failed)
			fmt = printk_is_sane ? FMT_FAIL_LONG : FMT_FAIL_LONG_COMPAT;
		else
			fmt = printk_is_sane ? FMT_SUCC_LONG : FMT_SUCC_LONG_COMPAT;
	}

	if (printk_is_sane) {
		bpf_trace_printk(fmt, FMT_MAX_SZ, spaces + 2 * ((255 - d) & 0xff), func_name, res);
	} else {
		bpf_trace_printk(fmt, FMT_MAX_SZ, d + 1, func_name, res);
	}
	//bpf_printk("POP(1) ID %d ADDR %lx NAME %s", id, ip, func_name);
}
#else
static __always_inline void print_exit(void *ctx, __u32 d, __u32 id, long res)
{
	char *func_name;
	const size_t FMT_MAX_SZ = 16; /* UPDATE IF NECESSARY */
	u32 flags, fmt_sz;
	const char *fmt;
	bool failed;
	int key;
	char *FMT_SUCC_VOID;
	char *FMT_SUCC_TRUE;
	char *FMT_SUCC_FALSE;
	char *FMT_FAIL_NULL;
	char *FMT_FAIL_PTR;
	char *FMT_SUCC_PTR;
	char *FMT_FAIL_LONG;
	char *FMT_SUCC_LONG;
	char *FMT_FAIL_INT;
	char *FMT_SUCC_INT;
	char *FMT_SUCC_VOID_COMPAT;
	char *FMT_SUCC_TRUE_COMPAT;
	char *FMT_SUCC_FALSE_COMPAT;
	char *FMT_FAIL_NULL_COMPAT;
	char *FMT_FAIL_PTR_COMPAT;
	char *FMT_SUCC_PTR_COMPAT;
	char *FMT_FAIL_LONG_COMPAT;
	char *FMT_SUCC_LONG_COMPAT;
	char *FMT_FAIL_INT_COMPAT;
	char *FMT_SUCC_INT_COMPAT;
	__u64 *func_flags_ptr;
	struct space_type *spaces_ptr;

	key = id & MAX_FUNC_MASK;
	func_name = bpf_map_lookup_elem(&func_names, &key);
	if (!func_name)
		return;

	key = FMT_SUCC_VOID_id;
	FMT_SUCC_VOID = bpf_map_lookup_elem(&insn_fmt, &key);
	if (!FMT_SUCC_VOID)
		return;

	key = FMT_SUCC_TRUE_id;
	FMT_SUCC_TRUE = bpf_map_lookup_elem(&insn_fmt, &key);
	if (!FMT_SUCC_TRUE)
		return;

	key = FMT_SUCC_FALSE_id;
	FMT_SUCC_FALSE = bpf_map_lookup_elem(&insn_fmt, &key);
	if (!FMT_SUCC_FALSE)
		return;

	key = FMT_FAIL_NULL_id;
	FMT_FAIL_NULL = bpf_map_lookup_elem(&insn_fmt, &key);
	if (!FMT_FAIL_NULL)
		return;

	key = FMT_FAIL_PTR_id;
	FMT_FAIL_PTR = bpf_map_lookup_elem(&insn_fmt, &key);
	if (!FMT_FAIL_PTR)
		return;

	key = FMT_SUCC_PTR_id;
	FMT_SUCC_PTR = bpf_map_lookup_elem(&insn_fmt, &key);
	if (!FMT_SUCC_PTR)
		return;

	key = FMT_FAIL_LONG_id;
	FMT_FAIL_LONG = bpf_map_lookup_elem(&insn_fmt, &key);
	if (!FMT_FAIL_LONG)
		return;

	key = FMT_SUCC_LONG_id;
	FMT_SUCC_LONG = bpf_map_lookup_elem(&insn_fmt, &key);
	if (!FMT_SUCC_LONG)
		return;

	key = FMT_FAIL_INT_id;
	FMT_FAIL_INT = bpf_map_lookup_elem(&insn_fmt, &key);
	if (!FMT_FAIL_INT)
		return;

	key = FMT_SUCC_INT_id;
	FMT_SUCC_INT = bpf_map_lookup_elem(&insn_fmt, &key);
	if (!FMT_SUCC_INT)
		return;

	key = FMT_SUCC_VOID_COMPAT_id;
	FMT_SUCC_VOID_COMPAT = bpf_map_lookup_elem(&insn_fmt, &key);
	if (!FMT_SUCC_VOID_COMPAT)
		return;

	key = FMT_SUCC_TRUE_COMPAT_id;
	FMT_SUCC_TRUE_COMPAT = bpf_map_lookup_elem(&insn_fmt, &key);
	if (!FMT_SUCC_TRUE_COMPAT)
		return;

	key = FMT_SUCC_FALSE_COMPAT_id;
	FMT_SUCC_FALSE_COMPAT = bpf_map_lookup_elem(&insn_fmt, &key);
	if (!FMT_SUCC_FALSE_COMPAT)
		return;

	key = FMT_FAIL_NULL_COMPAT_id;
	FMT_FAIL_NULL_COMPAT = bpf_map_lookup_elem(&insn_fmt, &key);
	if (!FMT_FAIL_NULL_COMPAT)
		return;

	key = FMT_FAIL_PTR_COMPAT_id;
	FMT_FAIL_PTR_COMPAT = bpf_map_lookup_elem(&insn_fmt, &key);
	if (!FMT_FAIL_PTR_COMPAT)
		return;

	key = FMT_SUCC_PTR_COMPAT_id;
	FMT_SUCC_PTR_COMPAT = bpf_map_lookup_elem(&insn_fmt, &key);
	if (!FMT_SUCC_PTR_COMPAT)
		return;

	key = FMT_FAIL_LONG_COMPAT_id;
	FMT_FAIL_LONG_COMPAT = bpf_map_lookup_elem(&insn_fmt, &key);
	if (!FMT_FAIL_LONG_COMPAT)
		return;

	key = FMT_SUCC_LONG_COMPAT_id;
	FMT_SUCC_LONG_COMPAT = bpf_map_lookup_elem(&insn_fmt, &key);
	if (!FMT_SUCC_LONG_COMPAT)
		return;

	key = FMT_FAIL_INT_COMPAT_id;
	FMT_FAIL_INT_COMPAT = bpf_map_lookup_elem(&insn_fmt, &key);
	if (!FMT_FAIL_INT_COMPAT)
		return;

	key = FMT_SUCC_INT_COMPAT_id;
	FMT_SUCC_INT_COMPAT = bpf_map_lookup_elem(&insn_fmt, &key);
	if (!FMT_SUCC_INT_COMPAT)
		return;

	if (printk_needs_endline) {
		/* before bpf_trace_printk() started using underlying
		 * tracepoint mechanism for logging to trace_pipe it didn't
		 * automatically append endline, so we need to adjust our
		 * format strings to have \n, otherwise we'll have a dump of
		 * unseparate log lines
		 */
		APPEND_ENDLINE(FMT_SUCC_VOID);
		APPEND_ENDLINE(FMT_SUCC_TRUE);
		APPEND_ENDLINE(FMT_SUCC_FALSE);
		APPEND_ENDLINE(FMT_FAIL_NULL);
		APPEND_ENDLINE(FMT_FAIL_PTR);
		APPEND_ENDLINE(FMT_SUCC_PTR);
		APPEND_ENDLINE(FMT_FAIL_LONG);
		APPEND_ENDLINE(FMT_SUCC_LONG);
		APPEND_ENDLINE(FMT_FAIL_INT);
		APPEND_ENDLINE(FMT_SUCC_INT);

		APPEND_ENDLINE(FMT_SUCC_VOID_COMPAT);
		APPEND_ENDLINE(FMT_SUCC_TRUE_COMPAT);
		APPEND_ENDLINE(FMT_SUCC_FALSE_COMPAT);
		APPEND_ENDLINE(FMT_FAIL_NULL_COMPAT);
		APPEND_ENDLINE(FMT_FAIL_PTR_COMPAT);
		APPEND_ENDLINE(FMT_SUCC_PTR_COMPAT);
		APPEND_ENDLINE(FMT_FAIL_LONG_COMPAT);
		APPEND_ENDLINE(FMT_SUCC_LONG_COMPAT);
		APPEND_ENDLINE(FMT_FAIL_INT_COMPAT);
		APPEND_ENDLINE(FMT_SUCC_INT_COMPAT);
	}

	key = id & MAX_FUNC_MASK;
	func_flags_ptr = bpf_map_lookup_elem(&func_flags, &key);
	if (!func_flags_ptr)
		return;
	//flags = func_flags[id & MAX_FUNC_MASK];
	flags = *func_flags_ptr;
	if (flags & FUNC_RET_VOID) {
		fmt = printk_is_sane ? FMT_SUCC_VOID : FMT_SUCC_VOID_COMPAT;
		failed = false;
	} else if (flags & FUNC_RET_PTR) {
		/* consider NULL pointer an error */
		failed = (res == 0) || IS_ERR_VALUE(res);
		if (printk_is_sane)
			fmt = failed ? (res ? FMT_FAIL_PTR : FMT_FAIL_NULL) : FMT_SUCC_PTR;
		else
			fmt = failed ? (res ? FMT_FAIL_PTR_COMPAT : FMT_FAIL_NULL_COMPAT) : FMT_SUCC_PTR_COMPAT;
	} else if (flags & FUNC_RET_BOOL) {
		if (printk_is_sane)
			fmt = res ? FMT_SUCC_TRUE : FMT_SUCC_FALSE;
		else
			fmt = res ? FMT_SUCC_TRUE_COMPAT : FMT_SUCC_FALSE_COMPAT;
		failed = false;
	} else if (flags & FUNC_NEEDS_SIGN_EXT) {
		failed = IS_ERR_VALUE32(res);
		if (failed)
			fmt = printk_is_sane ? FMT_FAIL_INT : FMT_FAIL_INT_COMPAT;
		else
			fmt = printk_is_sane ? FMT_SUCC_INT : FMT_SUCC_INT_COMPAT;
	} else {
		failed = IS_ERR_VALUE(res);
		if (failed)
			fmt = printk_is_sane ? FMT_FAIL_LONG : FMT_FAIL_LONG_COMPAT;
		else
			fmt = printk_is_sane ? FMT_SUCC_LONG : FMT_SUCC_LONG_COMPAT;
	}

	key = 0;
	spaces_ptr = bpf_map_lookup_elem(&spaces, &key);
	if (!spaces_ptr)
		return;

	if (printk_is_sane) {
		bpf_trace_printk(fmt, FMT_MAX_SZ, spaces_ptr->space + 2 * ((255 - d) & 0xff), func_name, res);
	} else {
		bpf_trace_printk(fmt, FMT_MAX_SZ, d + 1, func_name, res);
	}
	//bpf_printk("POP(1) ID %d ADDR %lx NAME %s", id, ip, func_name);
}
#endif

#ifndef BPF_NO_GLOBAL_DATA
static __noinline bool pop_call_stack(void *ctx, u32 id, u64 ip, long res)
{
	const char *func_name = func_names[id & MAX_FUNC_MASK];
	struct call_stack *stack;
	u32 pid, exp_id, flags, fmt_sz;
	const char *fmt;
	bool failed;
	u64 d, lat;

	pid = (u32)bpf_get_current_pid_tgid();
	stack = bpf_map_lookup_elem(&stacks, &pid);
	if (!stack)
		return false;

	stack->next_seq_id++;

	d = stack->depth;
	if (d == 0)
		return false;
 
	d -= 1;
	barrier_var(d);
	if (d >= MAX_FSTACK_DEPTH)
		return false;

	flags = func_flags[id & MAX_FUNC_MASK];
	if (flags & FUNC_CANT_FAIL)
		failed = false;
	else if ((flags & FUNC_RET_PTR) && res == 0)
		/* consider NULL pointer an error as well */
		failed = true;
	else if (flags & FUNC_NEEDS_SIGN_EXT)
		failed = IS_ERR_VALUE32(res);
	else
		failed = IS_ERR_VALUE(res);

	lat = bpf_ktime_get_ns() - stack->func_lat[d];

	if (emit_func_trace) {
		struct func_trace_entry *fe;

		fe = bpf_ringbuf_reserve(&rb, sizeof(*fe), 0);
		if (!fe)
			goto skip_ft_exit;

		fe->type = REC_FUNC_TRACE_EXIT;
		fe->ts = bpf_ktime_get_ns();
		fe->pid = pid;
		fe->seq_id = stack->next_seq_id - 1;
		fe->depth = d + 1;
		fe->func_id = id;
		fe->func_lat = lat;
		fe->func_res = res;

		bpf_ringbuf_submit(fe, 0);
skip_ft_exit:;
	}
	if (verbose)
		print_exit(ctx, d, id, res);

	exp_id = stack->func_ids[d];
	if (exp_id != id) {
		const char *exp_func_name = func_names[exp_id & MAX_FUNC_MASK];
		u64 exp_ip;

		if (exp_id < MAX_FUNC_CNT)
			exp_ip = func_ips[exp_id];
		else
			exp_ip = 0;

		if (verbose) {
			bpf_printk("POP(0) UNEXPECTED PID %d DEPTH %d MAX DEPTH %d",
				   pid, stack->depth, stack->max_depth);
			bpf_printk("POP(1) UNEXPECTED GOT  ID %d ADDR %lx NAME %s",
				   id, ip, func_name);
			bpf_printk("POP(2) UNEXPECTED WANT ID %u ADDR %lx NAME %s",
				   exp_id, exp_ip, exp_func_name);
		}

		stack->depth = 0;
		stack->max_depth = 0;
		stack->is_err = false;
		stack->kstack_sz = 0;
		stack->lbrs_sz = 0;

		bpf_map_delete_elem(&stacks, &pid);

		return false;
	}

	stack->func_res[d] = res;
	stack->func_lat[d] = lat;

	if (failed && !stack->is_err) {
		stack->is_err = true;
		stack->max_depth = d + 1;
		stack->kstack_sz = bpf_get_stack(ctx, &stack->kstack, sizeof(stack->kstack), 0);
		stack->lbrs_sz = copy_lbrs(&stack->lbrs, sizeof(stack->lbrs));
	}
	stack->depth = d;

	/* emit last complete stack trace */
	if (d == 0) {
		if (stack->is_err) {
			if (extra_verbose) {
				bpf_printk("EMIT ERROR STACK DEPTH %d (SAVED ..%d)\n",
					   stack->max_depth, stack->saved_max_depth);
			}
			output_stack(ctx, &rb, stack);
		} else if (emit_success_stacks) {
			if (extra_verbose) {
				bpf_printk("EMIT SUCCESS STACK DEPTH %d (SAVED ..%d)\n",
					   stack->max_depth, stack->saved_max_depth);
			}
			output_stack(ctx, &rb, stack);
		}
		stack->is_err = false;
		stack->saved_depth = 0;
		stack->saved_max_depth = 0;
		stack->depth = 0;
		stack->max_depth = 0;
		stack->kstack_sz = 0;
		stack->lbrs_sz = 0;

		bpf_map_delete_elem(&stacks, &pid);
	}

	return true;
}
#else
static __always_inline bool pop_call_stack(void *ctx, u32 id, u64 ip, long res)
{
	char *func_name;
	struct call_stack *stack;
	u32 pid, exp_id, flags, fmt_sz;
	const char *fmt;
	bool failed;
	u64 d, lat;
	int key;
	__u64 *func_flag, *val;
	__u64 emit_func_trace, verbose, extra_verbose, emit_success_stacks;

	key = id & MAX_FUNC_MASK;
	func_name = bpf_map_lookup_elem(&func_names, &key);
	if (!func_name)
		return false;

	pid = (u32)bpf_get_current_pid_tgid();
	stack = bpf_map_lookup_elem(&stacks, &pid);
	if (!stack)
		return false;

	stack->next_seq_id++;

	d = stack->depth;
	if (d == 0)
		return false;

	d -= 1;
	barrier_var(d);
	if (d >= MAX_FSTACK_DEPTH)
		return false;

	key = id & MAX_FUNC_MASK;
	func_flag = bpf_map_lookup_elem(&func_flags, &key);
	if (!func_flag)
		return false;
	flags = *func_flag;
	//flags = func_flags[id & MAX_FUNC_MASK];
	if (flags & FUNC_CANT_FAIL)
		failed = false;
	else if ((flags & FUNC_RET_PTR) && res == 0)
		/* consider NULL pointer an error as well */
		failed = true;
	else if (flags & FUNC_NEEDS_SIGN_EXT)
		failed = IS_ERR_VALUE32(res);
	else
		failed = IS_ERR_VALUE(res);

	d = d & (MAX_FSTACK_DEPTH-1);
	barrier_var(d);
	lat = bpf_ktime_get_ns() - stack->func_lat[d];

	key = retsnoop_emit_func_trace;
	val = bpf_map_lookup_elem(&global_var, &key);
	if (!val)
		return 0;
	emit_func_trace = *val;
	if (emit_func_trace) {
		if (bpf_core_enum_value_exists(enum bpf_map_type, BPF_MAP_TYPE_RINGBUF)) {
			struct func_trace_entry *fe;

			fe = bpf_ringbuf_reserve(&rb, sizeof(*fe), 0);
			if (!fe)
				goto skip_ft_exit;

			fe->type = REC_FUNC_TRACE_EXIT;
			fe->ts = bpf_ktime_get_ns();
			fe->pid = pid;
			fe->seq_id = stack->next_seq_id - 1;
			fe->depth = d + 1;
			fe->func_id = id;
			fe->func_lat = lat;
			fe->func_res = res;

			bpf_ringbuf_submit(fe, 0);
		}
skip_ft_exit:;
	}

	key = retsnoop_verbose;
	val = bpf_map_lookup_elem(&global_var, &key);
	if (!val)
		return 0;
	verbose = *val;
	if (verbose)
		print_exit(ctx, d, id, res);
	d = d & (MAX_FSTACK_DEPTH-1);
	barrier_var(d);
	exp_id = stack->func_ids[d];
	if (exp_id != id) {
		//const char *exp_func_name = func_names[exp_id & MAX_FUNC_MASK];
		char *exp_func_name;
		u64 exp_ip;

		key = exp_id & MAX_FUNC_MASK;
		exp_func_name = bpf_map_lookup_elem(&func_names, &key);
		if (!exp_func_name)
			return false;

		if (exp_id < MAX_FUNC_CNT) {
			key = exp_id & MAX_FUNC_MASK;
			val = bpf_map_lookup_elem(&func_ips, &key);
			if (!val)
				return false;
			exp_ip = *val;
		} else {
			exp_ip = 0;
		}

		if (verbose) {
			bpf_printk("POP(0) UNEXPECTED PID %d DEPTH %d MAX DEPTH %d",
				   pid, stack->depth, stack->max_depth);
			bpf_printk("POP(1) UNEXPECTED GOT  ID %d ADDR %lx NAME %s",
				   id, ip, func_name);
			bpf_printk("POP(2) UNEXPECTED WANT ID %u ADDR %lx NAME %s",
				   exp_id, exp_ip, exp_func_name);
		}

		stack->depth = 0;
		stack->max_depth = 0;
		stack->is_err = false;
		stack->kstack_sz = 0;
		stack->lbrs_sz = 0;

		bpf_map_delete_elem(&stacks, &pid);

		return false;
	}

	d = d & (MAX_FSTACK_DEPTH-1);
	barrier_var(d);
	stack->func_res[d] = res;
	d = d & (MAX_FSTACK_DEPTH-1);
	barrier_var(d);
	stack->func_lat[d] = lat;

	if (failed && !stack->is_err) {
		stack->is_err = true;
		stack->max_depth = d + 1;
		stack->kstack_sz = bpf_get_stack(ctx, &stack->kstack, sizeof(stack->kstack), 0);
		stack->lbrs_sz = copy_lbrs(&stack->lbrs, sizeof(stack->lbrs));
	}
	stack->depth = d;

	key = retsnoop_extra_verbose;
	val = bpf_map_lookup_elem(&global_var, &key);
	if (!val)
		return 0;
	extra_verbose = *val;

	key = retsnoop_emit_success_stacks;
	val = bpf_map_lookup_elem(&global_var, &key);
	if (!val)
		return 0;
	emit_success_stacks = *val;
	/* emit last complete stack trace */
	if (d == 0) {
		if (stack->is_err) {
			if (extra_verbose) {
				bpf_printk("EMIT ERROR STACK DEPTH %d (SAVED ..%d)\n",
					   stack->max_depth, stack->saved_max_depth);
			}
			output_stack(ctx, &rb, stack);
		} else if (emit_success_stacks) {
			if (extra_verbose) {
				bpf_printk("EMIT SUCCESS STACK DEPTH %d (SAVED ..%d)\n",
					   stack->max_depth, stack->saved_max_depth);
			}
			output_stack(ctx, &rb, stack);
		}
		stack->is_err = false;
		stack->saved_depth = 0;
		stack->saved_max_depth = 0;
		stack->depth = 0;
		stack->max_depth = 0;
		stack->kstack_sz = 0;
		stack->lbrs_sz = 0;

		bpf_map_delete_elem(&stacks, &pid);
	}

	return true;
}
#endif

#ifndef BPF_NO_GLOBAL_DATA
static __always_inline bool tgid_allowed(void)
{
	bool *verdict_ptr;
	u32 tgid;

	/* if no PID filters -- allow everything */
	if (tgid_allow_cnt + tgid_deny_cnt == 0)
		return true;

	tgid = bpf_get_current_pid_tgid() >> 32;

	verdict_ptr = bpf_map_lookup_elem(&tgids_filter, &tgid);
	if (!verdict_ptr)
		/* if allowlist is non-empty, then PID didn't pass the check */
		return tgid_allow_cnt == 0;

	return *verdict_ptr;
}
#else
static __always_inline bool tgid_allowed(void)
{
	bool *verdict_ptr;
	u32 tgid;
	__u64 *val;
	__u64 tgid_allow_cnt, tgid_deny_cnt;
	int key;

	key = retsnoop_tgid_allow_cnt;
	val = bpf_map_lookup_elem(&global_var, &key);
	if (!val)
		return 0;
	tgid_allow_cnt = *val;

	key = retsnoop_tgid_deny_cnt;
	val = bpf_map_lookup_elem(&global_var, &key);
	if (!val)
		return 0;
	tgid_deny_cnt = *val;

	/* if no PID filters -- allow everything */
	if (tgid_allow_cnt + tgid_deny_cnt == 0)
		return true;

	tgid = bpf_get_current_pid_tgid() >> 32;

	verdict_ptr = bpf_map_lookup_elem(&tgids_filter, &tgid);
	if (!verdict_ptr)
		/* if allowlist is non-empty, then PID didn't pass the check */
		return tgid_allow_cnt == 0;

	return *verdict_ptr;
}
#endif

#ifndef BPF_NO_GLOBAL_DATA
static __always_inline bool comm_allowed(void)
{
	char comm[TASK_COMM_LEN] = {};
	bool *verdict_ptr;

	/* if no COMM filters -- allow everything */
	if (comm_allow_cnt + comm_deny_cnt == 0)
		return true;

	bpf_get_current_comm(comm, TASK_COMM_LEN);

	verdict_ptr = bpf_map_lookup_elem(&comms_filter, comm);
	if (!verdict_ptr)
		/* if allowlist is non-empty, then COMM didn't pass the check */
		return comm_allow_cnt == 0;

	return *verdict_ptr;
}
#else
static __always_inline bool comm_allowed(void)
{
	char comm[TASK_COMM_LEN] = {};
	bool *verdict_ptr;
	__u64 *val;
	__u64 comm_allow_cnt, comm_deny_cnt;
	int key;

	key = retsnoop_comm_allow_cnt;
	val = bpf_map_lookup_elem(&global_var, &key);
	if (!val)
		return 0;
	comm_allow_cnt = *val;

	key = retsnoop_comm_deny_cnt;
	val = bpf_map_lookup_elem(&global_var, &key);
	if (!val)
		return 0;
	comm_deny_cnt = *val;

	/* if no COMM filters -- allow everything */
	if (comm_allow_cnt + comm_deny_cnt == 0)
		return true;

	bpf_get_current_comm(comm, TASK_COMM_LEN);

	verdict_ptr = bpf_map_lookup_elem(&comms_filter, comm);
	if (!verdict_ptr)
		/* if allowlist is non-empty, then COMM didn't pass the check */
		return comm_allow_cnt == 0;

	return *verdict_ptr;
}
#endif

/* mass-attacher BPF library is calling this function, so it should be global */
#ifndef BPF_NO_GLOBAL_DATA
__hidden int handle_func_entry(void *ctx, u32 func_id, u64 func_ip)
#else
static __always_inline int handle_func_entry(void *ctx, u32 func_id, u64 func_ip)
#endif
{
	if (!tgid_allowed() || !comm_allowed())
		return 0;

	push_call_stack(ctx, func_id, func_ip);
	return 0;
}

/* mass-attacher BPF library is calling this function, so it should be global */
#ifndef BPF_NO_GLOBAL_DATA
__hidden int handle_func_exit(void *ctx, u32 func_id, u64 func_ip, u64 ret)
#else
static __always_inline int handle_func_exit(void *ctx, u32 func_id, u64 func_ip, u64 ret)
#endif
{
	if (!tgid_allowed() || !comm_allowed())
		return 0;

	pop_call_stack(ctx, func_id, func_ip, ret);
	return 0;
}
