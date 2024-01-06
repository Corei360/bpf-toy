// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
//#include "template.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} ringbuf SEC(".maps");

SEC("kprobe/xbd_transmit")
int bpf_prog(struct pt_regs *ctx)
{
    void *data = (void *)PT_REGS_PARM1(ctx);
    long len = PT_REGS_PARM2(ctx);

    // 将数据推送到ringbuf
    char *buf = bpf_ringbuf_reserve(&ringbuf, len, 0);
    if (!buf)
        return 0;

    bpf_probe_read(buf, len, data);
    bpf_ringbuf_submit(buf, 0);

    return 0;
}
