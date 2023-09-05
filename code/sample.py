from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
import argparse
import signal
import re
import time
import os
import commands
import string
from sys import argv
from ctypes import *
prog = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
struct date_t{
    u32 pid;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);
BPF_HASH(counts, u32, int);
BPF_HASH(frq, int, int);

int kprobe__handle_mm_fault(struct pt_regs *ctx) {
    struct date_t data={};
    u32 pid=bpf_get_current_pid_tgid()>>32;
    bpf_get_current_comm(&data.comm,sizeof(data.comm));
    char p_name[]="mypr";
    int frequency=100000;
    if(__builtin_memcmp(data.comm,p_name,4)==0)
    {   
        data.pid=pid;
        counts.atomic_increment(pid);

        int key=0;
        frq.atomic_increment(key);//serve as cnt,every frequency times submit once
        int* val=frq.lookup(&key);
        if(val!=NULL && *val==frequency)
        {
           events.perf_submit(ctx,&data,sizeof(data));
           int zero=0;
           frq.update(&key,&zero);
        }
        return 0;
    }
    return 0;
}
"""
begin_time=time.time()


b = BPF(text=prog)
def print_event(cpu,data,size):
    counts=b["counts"]
    event=b["events"].event(data)
    key=event.pid
    if(len(counts.values()) > 0):#filter some empty arrays
      for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
        min_value=1000
        if(v.value>min_value):
            print("%s %-6d %d\t" % (event.comm,event.pid,v.value),end="")
            print("time : ",(time.time()-begin_time))
            counts.clear()




b["events"].open_perf_buffer(print_event)
while 1:
    try:
        print()
    except KeyboardInterrupt:
        exiting = 1
        # as cleanup can take many seconds, trap Ctrl-C:
        signal.signal(signal.SIGINT, signal_ignore)
   
    program = "mypr"
    output = commands.getoutput("ps -ef | grep ./" + program)
    proginfo = output.split()
    pid=int(proginfo[1])
    os.system("sudo perl wss.pl %d 1" % pid)

    b.perf_buffer_poll()
