# Windows-11 Kernel Rootkit
A Windows 11 Rootkit - in progress 🔧

## About
This is as said a kernel Rootkit driver hiding any Processes or files you don't want people seeing.
It also has some more functions involved like a BSOD and (offcourse) a hooking function called CloudHook.

It is highly customizable by simple editing of lists and variables in the code or configuring it via the hpp file **defs**.
It is built to *bypass* any Sys Admin Tool and may (if you choose) trigger a BlueScreen when one opens, 
it isnt suggested to activate this BSOD function since it may rise suspicion and since **NtQuerySystemInformation** is already edited it will already be hidden.

## Config ⚙️
You need to enable BSOD in the defs.hpp file (If you want to). You can also enable other stuff like:
- File Hiding (Enable / Disable)
- Process Hiding (Enable / Disable)
- Process Hide Items (List)
- File Hide Items (List)
- Enable hiding Registry Keys (Enable / Disable)
- Registry Keys Items (List)
- Debug Mode (Enable / Disable)
- Delay Execution (Enable / Disable)
- Delay TIme (Number)
  On default File Hiding and Process Hiding are enabled also the driver is hidden in the Registry (if enabled). BSOD is disabled and the lists are just
  "mocks" a few are real processes but I suggest to edit it and add you're own stuff.
  If you don't want to calculate the time in seconds on youre self just use *TimeConverter.py* :).
  The Debug Mode is disabled on default but it logs everything it currently does by using a bit modified *console.hpp* that can be found in *defs.hpp* ;p.

## delivery.cs
This file is a mockup of what a Payload delivery might look like for this rootkit. It wont work right now but I plan on hosting a download link from my Rasperry Pi!
It also includes a UAC bypass since the Kernel Exploit needs to run with Admin Privileges and a *cleanup* function.
It is my first c# script so dont excpect much guys😅!

## BTW
I highly suggest reading the comments in the USER CONFIGURATION since otherwise you might understand something wrong;
If you want to host a site to curl and download the rootkit you will probaly have to change some of the folder logic,
When I get to host my own download site I will be setting everything default optimised to that file structure;
Not everything is optimised 😉.


## Some More Stuff 🤓
**Thanks to [Hakai Offsec](https://github.com/hakaioffsec) for their [CVE-2024-21338](https://github.com/hakaioffsec/CVE-2024-21338) Kernel Privelege Escalation PoC!**
**All the credits are in the codes comments.**
**This is under the MIT license.**

## Recently finished ✅
- Payload delivery example (delivery.cs)
- UAC Bypass (delivery.cs)
- Debug Mode (Everything)
- Obsfuscated delivery example (delivery.cs); This was more of a Test.
- Time Delay (defs.hpp)
- Time converter (TimeConverter.py)

## Working on it...
I am currently making the delay time work better and adding comments explaining everything...
