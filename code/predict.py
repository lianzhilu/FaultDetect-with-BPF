from __future__ import print_function
import numpy as np
import joblib
from bcc import BPF
import signal
import time
import random
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
    int frequency=5000;
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
b = BPF(text=prog)
begin_time=time.time()
page_fault=0
now = 0
def get_pagefault(cpu,data,size):
    counts = b["counts"]
    event = b["events"].event(data)
    global now
    if (len(counts.values()) > 0):
        for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
            min_value = 10000
            if (v.value > min_value):
                global page_fault
                page_fault=v.value
                global now
                now=time.time()-begin_time
               # print('now=',now)
                counts.clear()
            

def mmypredict(model,loss,timeinterval):
    # load model
    testX = np.array((loss,timeinterval)).reshape(1,2)
    forecasttestY = model.predict(testX)
    return forecasttestY


b["events"].open_perf_buffer(get_pagefault)

last_time=0
while 1:
    time.sleep(2)
    this_time = time.time()
    try:
        model = joblib.load('lgb_006.pkl')
        b.perf_buffer_poll()
       # print('last_time=',last_time)
        interval=now-last_time
        if(interval==0):
          continue
        #print('interval=',interval)
       #print('pgf=',page_fault)
        predict=mmypredict(model, page_fault,interval)
        if(last_time):
          print(predict,'\t',time.time()-this_time)
        last_time=now


    except KeyboardInterrupt:
        exiting = 1
        # as cleanup can take many seconds, trap Ctrl-C:
        signal.signal(signal.SIGINT, signal_ignore)







