/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2021 Facebook */
#ifndef __RETSNOOP_H
#define __RETSNOOP_H

#define MAX_CPUS 256
#define MAX_CPUS_MSK (MAX_CPUS - 1)

/* MAX_FUNC_CNT needs to be power-of-2 */
#define MAX_FUNC_CNT (4 * 1024)
#define MAX_FUNC_MASK (MAX_FUNC_CNT - 1)
#define MAX_FUNC_NAME_LEN 40

#define MAX_FSTACK_DEPTH 64
#define MAX_KSTACK_DEPTH 128

#define MAX_LBR_ENTRIES 32

/* Linux allows error from -1 up to -4095, even though most of the values are
 * not used
 */
#define MAX_ERR_CNT 4096

enum rec_type {
	REC_CALL_STACK,
	REC_FUNC_TRACE_START,
	REC_FUNC_TRACE_ENTRY,
	REC_FUNC_TRACE_EXIT,
};

struct call_stack {
	/* REC_CALL_STACK */
	enum rec_type type;

	unsigned short func_ids[MAX_FSTACK_DEPTH];
	long func_res[MAX_FSTACK_DEPTH];
	long func_lat[MAX_FSTACK_DEPTH];
	unsigned depth;
	unsigned max_depth;
	int pid, tgid;
	long start_ts, emit_ts;
	char task_comm[16], proc_comm[16];
	bool is_err;

	unsigned short saved_ids[MAX_FSTACK_DEPTH];
	long saved_res[MAX_FSTACK_DEPTH];
	long saved_lat[MAX_FSTACK_DEPTH];
	unsigned saved_depth;
	unsigned saved_max_depth;

	long kstack[MAX_KSTACK_DEPTH];
	long kstack_sz;

	struct perf_branch_entry lbrs[MAX_LBR_ENTRIES];
	long lbrs_sz;

	int next_seq_id;
};

struct func_trace_start {
	/* REC_FUNC_TRACE_START */
	enum rec_type type;
	int pid;
};

struct func_trace_entry {
	/* REC_FUNC_TRACE_ENTRY or REC_FUNC_TRACE_EXIT */
	enum rec_type type;

	int pid;
	long ts;

	int seq_id;
	short depth;
	unsigned short func_id;

	long func_lat;
	long func_res;
};

#define FUNC_IS_ENTRY 0x1
#define FUNC_CANT_FAIL 0x2
#define FUNC_NEEDS_SIGN_EXT 0x4
#define FUNC_RET_PTR 0x8
#define FUNC_RET_BOOL 0x10
#define FUNC_RET_VOID 0x20

#define TASK_COMM_LEN 16

#ifdef BPF_NO_GLOBAL_DATA
enum calib_feat_global_var_id {
	calib_feat_my_tid,
	calib_feat_entry_ip,
	calib_feat_kret_ip_off,
	calib_feat_has_bpf_get_func_ip,
	calib_feat_has_fexit_sleep_fix,
	calib_feat_has_fentry_protection,
	calib_feat_has_branch_snapshot,
	calib_feat_has_ringbuf,
	calib_feat_has_bpf_cookie,
	calib_feat_has_kprobe_multi,
	calib_feat_ID_CNT,
};

enum retsnoop_global_var_id {
	retsnoop_ready,
	retsnoop_kret_ip_off,
	retsnoop_has_bpf_get_func_ip,
	retsnoop_has_bpf_cookie,
	retsnoop_has_fentry_protection,
	retsnoop_verbose,
	retsnoop_extra_verbose,
	retsnoop_use_ringbuf,
	retsnoop_use_lbr,
	retsnoop_targ_tgid,
	retsnoop_emit_success_stacks,
	retsnoop_emit_intermediate_stacks,
	retsnoop_emit_func_trace,
	retsnoop_tgid_allow_cnt,
	retsnoop_tgid_deny_cnt,
	retsnoop_comm_allow_cnt,
	retsnoop_comm_deny_cnt,
	retsnoop_duration_ns,
	retsnoop_ID_CNT,
};

enum fmt_insn_id {
	FMT_SUCC_VOID_id,
	FMT_SUCC_TRUE_id,
	FMT_SUCC_FALSE_id,
	FMT_FAIL_NULL_id,
	FMT_FAIL_PTR_id,
	FMT_SUCC_PTR_id,
	FMT_FAIL_LONG_id,
	FMT_SUCC_LONG_id,
	FMT_FAIL_INT_id,
	FMT_SUCC_INT_id,
	FMT_SUCC_VOID_COMPAT_id,
	FMT_SUCC_TRUE_COMPAT_id,
	FMT_SUCC_FALSE_COMPAT_id,
	FMT_FAIL_NULL_COMPAT_id,
	FMT_FAIL_PTR_COMPAT_id,
	FMT_SUCC_PTR_COMPAT_id,
	FMT_FAIL_LONG_COMPAT_id,
	FMT_SUCC_LONG_COMPAT_id,
	FMT_FAIL_INT_COMPAT_id,
	FMT_SUCC_INT_COMPAT_id,
	FMT_CNT,
};
#endif

#endif /* __RETSNOOP_H */
