# CVE-2021-40449-NtGdiResetDC-UAF

A POC for CVE-2021-40449.
Only tested on 1809, the code is a bit rough, but it's a good experience for me.
Instead of using the `ThreadName` method, user-space memory allocation is used.

![result.PNG](https://github.com/BL0odz/CVE-2021-40449-NtGdiResetDC-UAF/blob/main/result.PNG?raw=true)
