Prints acquired threads in given process with pid.
This is similar to `windbg` extenions for dumping critsecs `!locks`

A bit more information here:
[https://msdn.microsoft.com/en-us/library/windows/hardware/ff541979%28v=vs.85%29.aspx](https://msdn.microsoft.com/en-us/library/windows/hardware/ff541979%28v=vs.85%29.aspx)

```
C:\>locksinfo.exe 51204

a handy utility to list locks acquired in a process
author: Sarang Baheti, source: https://github.com/angeleno/locksinfo

Locks information for process- 51204, testprocess.exe
Found 63391 locks

Printing 3 acquired locks
------------------------------------------------------------------------

#0 Lock at address-   0x00000000249251D0
Type:              0
OwningThread:      57620
LockingSemaphore:  0x0000000000000A24
ContentionCount:   0
LockCountRaw:      -2
  LockStatus:      locked
  AnyThreadsWoken: no
  #ThreadsWaiting: 0

#1 Lock at address-   0x000000002CB69C70
Type:              0
OwningThread:      84440
LockingSemaphore:  0x0000000000000000
ContentionCount:   0
LockCountRaw:      -2
  LockStatus:      locked
  AnyThreadsWoken: no
  #ThreadsWaiting: 0

#2 Lock at address-   0x0000000013EC4C50
Type:              0
OwningThread:      53540
LockingSemaphore:  0x0000000000001BB4
ContentionCount:   1
LockCountRaw:      -6
  LockStatus:      locked
  AnyThreadsWoken: no
  #ThreadsWaiting: 1
  
```

If you run with flags set to track Locks in your process it can print creation site for the critical section:
Off course i am not translating symbols but that is not too hard if you want to try. Perhaps i will do it later.

```
Printing 1 acquired locks
------------------------------------------------------------------------

#0 Lock at address-   0x000007FED6B539C0
Type:              0
OwningThread:      44356
LockingSemaphore:  0x0000000000000000
ContentionCount:   0
LockCountRaw:      -2
  LockStatus:      locked
  AnyThreadsWoken: no
  #ThreadsWaiting: 0

Creation traceback:
[ 0] 000F003500000040
[ 1] 000007FEF210A992
[ 2] 000007FEFD1C32CA
[ 3] 000007FED6AAD0C1
[ 4] 000007FED6A7DCF6
[ 5] 000007FED6A7D70C
[ 6] 000007FED6A7D575
[ 7] 000007FED6A7DF86
[ 8] 000007FED6A79363
[ 9] 000007FEF2053EB8
[10] 000007FEF24BBAE5
[11] 000007FEF2106F62
[12] 00000000774A6CA8
[13] 00000000774AD0D7
[14] 000000007750BD09
[15] 000000007749A36E
```

