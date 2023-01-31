/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef __GLOBAL_VAL_H
#define __GLOBAL_VAL_H

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

#endif /* __GLOBAL_VAL_H */
