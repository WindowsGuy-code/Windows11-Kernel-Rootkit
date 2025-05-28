# Windows11 Kernel Rootkit
A Windows 11 Rootkit driver - currently no dropper involved.

## About
This is as said a kernel Rootkit driver hiding any Processes or files you don't want people seeing.
It also has some more functions involved like a BSOD and (offcourse) a hooking function called CloudHook.

It is highly customizable by simple editing of lists and variables in the code.
It is built to *bypass* ProcessHacker and may (if you choose) trigger a BlueScreen when it opens, 
it isnt suggested to activate this function since it may rise suspicion and since **NtQuerySystemInformation** is already edited it will already be hidden.

## Some More Stuff 🤓

**All the credits are in the codes comments.**
**This is under the MIT license.**

## Working on it...
I am working on a dropper/planter using an kernel exploit by [Milad Karimi](https://www.exploit-db.com/?author=10413): [Kernel Exploit](https://www.exploit-db.com/exploits/52275)
