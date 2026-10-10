#!/usr/bin/env python3
"""Run on the test host; emit 500 ms system/cgroup samples without credentials."""
import os,time,json,subprocess,signal,urllib.request
stop=False
signal.signal(signal.SIGTERM,lambda *a:globals().__setitem__('stop',True))
def read(path):
 try:return open(path).read().strip()
 except:return ''
def fields(path):
 return {k:int(v) for k,v in (line.split()[:2] for line in read(path).splitlines())}
def service():
 try:
  data=subprocess.check_output(['systemctl','show','zkf-notary','-p','MainPID','-p','ControlGroup','-p','NRestarts','-p','ActiveState'],text=True)
  d=dict(line.split('=',1) for line in data.splitlines());cg='/sys/fs/cgroup'+d['ControlGroup']
  return d,cg if d['ControlGroup'] else None
 except:return {},None
x,cg=service(); prev=None; tick=0
while not stop:
 now=time.time(); mem={k.rstrip(':'):int(v) for k,v,*_ in (line.split() for line in read('/proc/meminfo').splitlines())}
 cpu=list(map(int,read('/proc/stat').splitlines()[0].split()[1:])); net=read('/proc/net/dev')
 stat=os.statvfs('/'); row=dict(time=now,hostMemTotalKiB=mem['MemTotal'],hostMemAvailableKiB=mem['MemAvailable'],swapUsedKiB=mem['SwapTotal']-mem['SwapFree'],diskTotal=stat.f_blocks*stat.f_frsize,diskUsed=(stat.f_blocks-stat.f_bfree)*stat.f_frsize,diskAvailable=stat.f_bavail*stat.f_frsize,load=read('/proc/loadavg'),vmstat={k:v for k,v in fields('/proc/vmstat').items() if k in ['pswpin','pswpout','pgmajfault','oom_kill']},net=net,diskstats=read('/proc/diskstats'))
 if prev:
  d=[a-b for a,b in zip(cpu,prev)];total=sum(d[:8]);row['hostCpuPct']=100*(total-d[3]-d[4])/total if total else 0;row['iowaitPct']=100*d[4]/total if total else 0;row['stealPct']=100*d[7]/total if total else 0
 prev=cpu
 if tick%10==0:x,cg=service()
 try:
  row['notaryMetrics']=urllib.request.urlopen('http://127.0.0.1:9001/metrics',timeout=.3).read().decode()
 except:pass
 row['serviceState']=x;row['restarts']=int(x.get('NRestarts',0))
 if cg:
  for name in ['memory.current','memory.peak','memory.swap.current','memory.events','cpu.stat','io.stat','pids.current']:
   row[name]=read(cg+'/'+name)
 print(json.dumps(row),flush=True);tick+=1;time.sleep(.5)
