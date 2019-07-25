/*
 * Seccomp BPF helper functions
 *
 * Copyright (c) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 * Author: Will Drewry <wad@chromium.org>
 *
 * The code may be used by anyone for any purpose,
 * and can serve as a starting point for developing
 * applications using prctl(PR_ATTACH_SECCOMP_FILTER).
 */

#define _GNU_SOURCE 1
#ifndef __GNUC__
#define __GNUC__ 1
#endif
typedef __builtin_va_list __gnuc_va_list;

#include "bpf-helper.h"
#include "internal.h"

int bpf_resolve_jumps(struct bpf_labels *labels,
		      struct sock_filter *filter, int count)
{
	struct sock_filter *begin = filter;
	__u8 insn = count - 1;

	if (count < 1)
		return -1;
	/*
	* Walk it once, backwards, to build the label table and do fixups.
	* Since backward jumps are disallowed by BPF, this is easy.
	*/
	filter += insn;
	for (; filter >= begin; --insn, --filter) {
		if (filter->code != (BPF_JMP+BPF_JA))
			continue;
		switch ((filter->jt<<8)|filter->jf) {
		case (JUMP_JT<<8)|JUMP_JF:
			if (labels->labels[filter->k].location == 0xffffffff) {
				printf("Unresolved label: '%s'\n",
				       labels->labels[filter->k].label);
				return 1;
			}
			filter->k = labels->labels[filter->k].location -
				    (insn + 1);
			filter->jt = 0;
			filter->jf = 0;
			continue;
		case (LABEL_JT<<8)|LABEL_JF:
			if (labels->labels[filter->k].location != 0xffffffff) {
				printf("Duplicate label use: '%s'\n",
				       labels->labels[filter->k].label);
				return 1;
			}
			labels->labels[filter->k].location = insn;
			filter->k = 0; /* fall through */
			filter->jt = 0;
			filter->jf = 0;
			continue;
		}
	}
	return 0;
}

/* Simple lookup table for labels. */
__u32 seccomp_bpf_label(struct bpf_labels *labels, const char *label)
{
	struct __bpf_label *begin = labels->labels, *end;
	int id;
	if (labels->count == 0) {
		begin->label = label;
		begin->location = 0xffffffff;
		labels->count++;
		return 0;
	}
	int len = strlen(label);
	end = begin + labels->count;
	for (id = 0; begin < end; ++begin, ++id) {
		if (!memcmp(label, begin->label, len + 1))
			return id;
	}
	begin->label = label;
	begin->location = 0xffffffff;
	labels->count++;
	return id;
}

void seccomp_bpf_print(struct sock_filter *filter, int count)
{
	struct sock_filter *end = filter + count;
	for ( ; filter < end; ++filter)
		printf("{ code=%u,jt=%u,jf=%u,k=%u },\n",
		       filter->code, filter->jt, filter->jf, filter->k);
}

