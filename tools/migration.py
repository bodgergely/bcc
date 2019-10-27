#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# migration    Trace as processes migrate between CPUs.
#               For Linux, uses BCC, eBPF.
#
# This script traces as tasks migrate between CPU
# by taking note of the cpu the current process was
# scheduled previously.
#
# USAGE: migration [-p PID]
#
# REQUIRES: Linux 4.9+ (BPF_PROG_TYPE_PERF_EVENT support).
#
# Description: TODO
# 
# Copyright 2016 Cloudflare, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 27-Oct-2019   Gergely Bod   Created this.

from __future__ import print_function
from bcc import BPF
import argparse
from time import strftime

# arguments
examples = """examples:
    ./migration          # trace all process migrations system wide
    ./runqslower -p 123  # trace pid 123 only
"""
parser = argparse.ArgumentParser(
    description="Trace process cpu migrations.",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-p", "--pid", type=int, metavar="PID", dest="pid",
    help="trace this PID only")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
args = parser.parse_args()
debug = 0

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>

BPF_HASH(start, u32, u64);

struct rq;

struct data_t {
    u32 pid;
    char task[TASK_COMM_LEN];
    u64 prev_cpu;
    u64 curr_cpu;
};

BPF_PERF_OUTPUT(events);

// record enqueue cpu
static int trace_enqueue(u32 pid, u64 cpu)
{
    if (FILTER_PID || pid == 0)
        return 0;
    // u64 ts = bpf_ktime_get_ns();
    start.update(&pid, &cpu);
    return 0;
}
"""

bpf_text_kprobe = """
int trace_wake_up_new_task(struct pt_regs *ctx, struct task_struct *p)
{
    return trace_enqueue(p->pid, p->cpu);
}

int trace_ttwu_do_wakeup(struct pt_regs *ctx, struct rq *rq, struct task_struct *p,
    int wake_flags)
{
    return trace_enqueue(p->pid, p->cpu);
}

// calculate latency
int trace_run(struct pt_regs *ctx, struct task_struct *prev)
{
    u32 pid;
    u64* prev_cpu;
    u64  curr_cpu;
    struct task_struct *curr_task;

    curr_task = (struct task_struct *)bpf_get_current_task();
    if(!curr_task)
        return 0;

    pid = curr_task->pid;
    curr_cpu = curr_task->cpu;

    if(FILTER_PID || pid == 0)
        return 0;

    prev_cpu = start.lookup_or_init(&pid, &curr_cpu);
    if(!prev_cpu)
        return 0;

    if(curr_cpu == *prev_cpu) {
        return 0;
    }
    
    struct data_t data = {};
    data.pid = pid;
    bpf_get_current_comm(&data.task, sizeof(data.task));
    data.prev_cpu = *prev_cpu;
    data.curr_cpu = curr_cpu;

    // output
    events.perf_submit(ctx, &data, sizeof(data));

    start.delete(&pid);
    return 0;
}
"""

# TODO - raw tp support! support only kprobe for now
bpf_text += bpf_text_kprobe

# code substitutions
if args.pid:
    bpf_text = bpf_text.replace('FILTER_PID', 'pid != %s' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER_PID', '0')
if debug or args.ebpf:
    print(bpf_text)
    if args.ebpf:
        exit()

# process event
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print("%-8s %-16s %-6s %10s %14s" % (strftime("%H:%M:%S"), event.task, event.pid, 
                            event.prev_cpu, event.curr_cpu))

# load BPF program
b = BPF(text=bpf_text)
b.attach_kprobe(event="ttwu_do_wakeup", fn_name="trace_ttwu_do_wakeup")
b.attach_kprobe(event="wake_up_new_task", fn_name="trace_wake_up_new_task")
b.attach_kprobe(event="finish_task_switch", fn_name="trace_run")

print("Tracing CPU migration.")
print("%-8s %-16s %-6s %14s %14s" % ("TIME", "COMM", "PID", "PREV_CPU", "CURR_CPU"))

# read events
b["events"].open_perf_buffer(print_event, page_cnt=64)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
