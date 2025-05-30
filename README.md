# Windows-11 Kernel Rootkit
A Windows 11 Rootkit

## About
This is as said a kernel Rootkit driver hiding any Processes or files you don't want people seeing.
It also has some more functions involved like a BSOD and (offcourse) a hooking function called CloudHook.

It is highly customizable by simple editing of lists and variables in the code or configuring it via the hpp file **defs**.
It is built to *bypass* any Sys Admin Tool and may (if you choose) trigger a BlueScreen when one opens, 
it isnt suggested to activate this BSOD function since it may rise suspicion and since **NtQuerySystemInformation** is already edited it will already be hidden.

## Config ⚙️
You need to enable BSOD in the defs.hpp file. You can also enable other stuff like:
- File Hiding (Enable / Disable)
- Process Hiding (Enable / Disable)
- Process Hide Items (List)
- File Hide Items (List)
- Enable hiding Registry Keys (Enable / Disable)
- Registry Keys Items (List)
  On default File Hiding and Process Hiding are enabled also the driver is hidden in the Registry (if enabled). BSOD is disabled and the lists are just
  "mocks" a few are real processes but I suggest to edit it and add you're own stuff.


## Some More Stuff 🤓
**Thanks to [Hakai Offsec](https://github.com/hakaioffsec) for their [CVE-2024-21338](https://github.com/hakaioffsec/CVE-2024-21338) Kernel Privelege Escalation PoC!**
**All the credits are in the codes comments.**
**This is under the MIT license.**

## Working on it...
I am currently working on removing any form of logs of the [PoC](https://github.com/hakaioffsec/CVE-2024-21338) or only enabling them in a *debug* mode...
