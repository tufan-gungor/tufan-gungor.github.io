---
title: Hunt and Analysis - Neptune Loader
author: Tufan Gungor
date: 2024-01-14 00:00:00 +0800
categories: [Reverse Engineering,Malware Hunting]
tags: [reverse engineering,malware hunting]
math: true
mermaid: true
---
# Part 1 - Neptune || **A Native HTTP Loader**

A user named `m0hx` shared a post on [hackforums.net](https://hackforums.net/showthread.php?tid=6256979) on November 22, 2023, promoting a loader called `Neptune`. In the threat actor's exact words;

*"Neptune is an innovative HTTP loader project that provides robust and efficient control over computer systems through commands administered via user-friendly web panel.”*

![Untitled](/assets/img/neptune/0.png)

On January 9th, nearly two months subsequent to the initial post, [@ViriBack](https://twitter.com/ViriBack), a user on X (formerly Twitter), disclosed the IP addresses of three detected Neptune Loader command and control centers.

![Untitled](/assets/img/neptune/1.png)

After [@Viriback](https://twitter.com/ViriBack)'s post, Twitter users [@banthisguy9349](https://twitter.com/banthisguy9349) and [@ShanHolo](https://twitter.com/ShanHolo) also shared the Neptune Loader C2 addresses they had identified.

```text
tdboat.online
mfuk.app
```

# Part 2 - Dissecting the First Neptune Sample

By conducting a search for the domain `tdboat.online` on VirusTotal and examining its associated relations, an intriguing discovery emerges: a URL containing `task.php` in its path.

![Untitled](/assets/img/neptune/2.png)

Upon examining the relationships of this URL, we uncover an associated malware named "Valorant_Cheat.exe". 

![Untitled](/assets/img/neptune/3.png)

Our analysis will initially focus on this particular file.

![Untitled](/assets/img/neptune/4.png)

**SHA256: *2a3549512f5f9cf1b11a26897a79532adc548c3000fb7b07fcae6b49cd5222ad***

*Exeinfo output for Valorant_Cheat.exe*

`[ (GNU) 9.3-win32 20200320 ] - GCC MINGW-64w compiler for 32/64 bit ( exe )`

Upon loading this sample into IDA, we observe a sizable data blob in the section named `.UH2oS6N`. Additionally, the IDA Navigator reveals a notably small code area, which typically implies two potential scenarios: the file is either packed or encrypted.

![Untitled](/assets/img/neptune/5.png)

The function `sub_401530`, identified during our examination of calls made by the `start` function, exhibits compelling behavior. It dynamically loads `USER32.dll` and retrieves the `VirtualAlloc` function. The function then allocates new memory with **`PAGE_EXECUTE_READWRITE`** permissions (0x40) and uses **`memcpy`** to transfer data from the `.UH2oS6N` section into this allocated space. Finally, it shifts execution to the beginning of this newly written section, a technique commonly seen in unpacking or decrypting executable code.

![Untitled](/assets/img/neptune/6.png)

The unmodified transfer of data from the `.UH2oS6N` section to the allocated memory, followed by a change in the execution flow to this area, suggests that the `.UH2oS6N` section could contain executable code instead of data. We can confirm this in IDA by transforming this section's data into code, enabling a deeper examination of its contents.

![Untitled](/assets/img/neptune/7.png)

Transforming the initial part of the '.UH2oS6N' section into code within IDA, we quickly notice a call to 'sub_4AF27C'. Intriguingly, this function employs rotational (ror/rol) and XOR techniques for decryption, suggesting complex encryption mechanisms at play.

![Untitled](/assets/img/neptune/8.png)

Rather than dedicating time to statically dissecting this routine in IDA, a more efficient approach would be to open the file in a debugger. This allows the decryption process to unfold naturally, enabling us to observe the decrypted code directly.

## Unpacking / Decryption

In x64dbg, to reach the same point of analysis as in IDA, these steps should be followed: Initially, place a breakpoint on **`VirtualAlloc`**. Proceed to run the code until this breakpoint is hit. Continue running the code until it completes the return, then step over to revert to the user code. This process will bring us to the crucial moment where the `.UH2oS6N` section is written into the allocated memory, and the execution is redirected there.

![Untitled](/assets/img/neptune/9.png)

For deeper analysis, the next step in x64dbg involves running the code up to the `call eax` instruction at the address `0040165F`. Once there, use 'Step into' (F7) to delve into the function being called. There are few more xor decryptions.

![Untitled](/assets/img/neptune/10.png)

Continuing to run the code step by step in x64dbg, while keeping a close eye on the allocated memory, reveals the unfolding decryption. Intriguingly, this process gradually uncovers the 'MZ' and 'PE' headers, hallmarks of executable files, signifying that the decrypted data forms a valid executable structure.

![Untitled](/assets/img/neptune/11.png)

At this point, we have a few options:

- Continue analysis in the debugger, which is quicker but lacks decompiling features and might face anti-debugger methods.
- Extract and examine a memory dump of the executable, which may involve fixing the Import Address Table (IAT).
- Use [Unpacme](https://www.unpac.me/) to automatically extract the unpacked child process.

***Later in this article, we will uncover that this is the Amber Reflective PE Packer.***

## Analysis of Unpacked Sample

After successfully unpacking the file using one of the recommended methods, we can proceed to analyze the unpacked sample in IDA.

The function 'sub_7FF16612', called immediately in the WinMain function, primarily checks for the presence of a debugger. It begins by calling **`IsDebuggerPresent`** and **`CheckRemoteDebuggerPresent`** to detect debugging environments. Additionally, it employs a timing check using **`QueryPerformanceCounter`** and **`Sleep`** to identify unusually fast execution, which could indicate a debugger's presence. If any of these checks suggest debugging, the function triggers a breakpoint with **`__debugbreak`**. The use of multiple debugger detection techniques indicates a deliberate effort to hinder reverse engineering or analysis in a debugging environment.

![Untitled](/assets/img/neptune/12.png)

In the scenario where no debugger is detected and the code executes successfully, the `WinMain` function proceeds to create a mutex with the name `d6d8c8d7-eacb-dc01-35aa-e872082a1ca1`. It then checks for creation failure, specifically for the error code `183`, which corresponds to `ERROR_ALREADY_EXISTS`. This check is a safeguard to prevent the program from running multiple instances on the same computer. If this specific error is encountered, indicating that the mutex already exists, the program halts, effectively preventing duplicate executions.

![Untitled](/assets/img/neptune/13.png)

If the program bypasses the mutex check, indicating that error `183 ('ERROR_ALREADY_EXISTS')` is not present, it initiates multiple threads. First, a thread is created with **`CreateThread`**, invoking the function `sub_7FF116B2` with the argument `REGISTER`. Following this, two additional threads are created, both calling `sub_7FF116B2` and `sub_7FF11932`, respectively, each with the argument `GETCMD`. The program then waits for the first thread to complete using **`WaitForSingleObject`** with an infinite timeout (`0xFFFFFFFF`). Finally, it returns 0, concluding this sequence of operations.

1. REGISTER (sub_7FF116B2)

In the `REGISTER` routine of the Neptune malware, a pivotal network communication is established. It sends a request to `gate.php`, accompanied by a `password` parameter. 

*The routine's extensive scope and complexity make it too large to fit within the confines of a single screenshot in IDA Graph, prompting the use of a decompiler for more effective visualization and detailed analysis*

![Untitled](/assets/img/neptune/14.png)

This step acts as a verification process with the command and control (C2) server. A correct password elicits a response of `Gate is open` from the C2, indicating successful entry. On the other hand, an incorrect password triggers a redirection to `index.php`, serving as a gatekeeping mechanism.

![Untitled](/assets/img/neptune/15.png)

"Once the 'Gate is open' response is received from the C2 server, indicating successful password verification, Neptune proceeds to the next stage. It sends a request to 'addbot.php', this time with a set of specific parameters:

```c
&lan=
&macAddress=
&port=
&computerName=
&userName=
&osName=
&country=
&language=
&latitude=
&longitude=
&timezone=
&isAdmin=
&isLaptop=
&idle=
&version=v
&tag=
&note=
&antivirus=
&antivirus=None
&dotNETFramework=
&dotNET=
&java=
&sandboxie=
&vmware=
&virtualbox=
&sandbox=
&osType=
&osBit=
&exeBit=
&exePath=
&ram=
&cpuno=
&cpuName=
&gpuName=
&ramUsg=
&cpuUsg=
```

![Untitled](/assets/img/neptune/16.png)

As part of its device information gathering process, the malware conducts a thorough check for the presence of antivirus software on the computer. It methodically scans through a predefined list of antivirus programs,

![Untitled](/assets/img/neptune/17.png)

The list of antivirus software was retrieved from this [GitHub repository](https://github.com/Karanxa/Bug-Bounty-Wordlists/blob/0cab044246b3f5d11949ce2dc935245f4d5af147/antivirus_names.txt).

The malware's detection capabilities extend to identifying sandbox environments. It scrutinizes the process list for the presence of `SandMan.exe` and `SbieCtrl.exe`, both indicative of sandboxing. Additionally, it probes the system's registry for the key `HKLM_SOFTWARE\Sophos\Sandboxie`, a telltale sign of a sandbox setup.

![Untitled](/assets/img/neptune/18.png)

Neptune initiates its virtualization detection by checking the `cpuid` instruction, a common method for identifying virtual machine environments. Following this, it employs a comprehensive strategy that includes process enumeration, registry key examination, and targeted file and library probes. Specifically, it seeks out the `VBoxService.exe` process, scrutinizes registry entries for VirtualBox-related information, and tests access to files and libraries unique to VirtualBox. This layered approach, starting from CPU instruction analysis to specific system checks, ensures a thorough and effective verification to determine if the malware is running in a virtualized setting.

```text
cpuid
SOFTWARE\\Sophos\\Sandboxie
SOFTWARE\\VMware, Inc.
SOFTWARE\\Oracle\\VirtualBox Guest Additions
SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Virtualization
VBoxService.exe
HARDWARE\\ACPI\\DSDT\\
VBOX__
\\\\.\\VBoxMiniRdrDN
VBoxHook.dll
```

![Untitled](/assets/img/neptune/19.png)

1. GET_CMD (sub_7FF116B2, sub_7FF11932)

In the next phase of operation, the `GETCMD` routine engages in regular communication with the C2 server. It does so by periodically dispatching requests to `tasks.php`, each tagged with a `bid` parameter that serves as the bot's identification. This process is essential for the malware to receive and execute commands or tasks that the C2 server may have pending, maintaining its operational alignment with the server's objectives.

![Untitled](/assets/img/neptune/20.png)

Below is a screenshot showcasing the full range of commands supported by the malware.

![Untitled](/assets/img/neptune/21.png)

Securing its communication channels, the Neptune malware implements AES (Rijndael) encryption, a step that comes into play after thorough parameter preparation.

# Part 3 - C2 Panel

As we move into Part 3 of our analysis, focusing on the C2 Panel, we encounter key contributions from the cybersecurity community. On January 9, following [@ViriBack](https://twitter.com/ViriBack)'s initial tweet on the topic, [@0xperator](https://twitter.com/0xperator) further expanded our understanding by posting several screenshots on January 10 that reveal the inner workings of the Neptune C2 Panel.

![Untitled](/assets/img/neptune/22.png)

You can find the [original post here](https://twitter.com/0xperator/status/1745176382915695096).

To uncover C2 panels linked to Neptune, we utilize various online services like Shodan, FOFA, and Censys. In this context, we concentrate on [Censys](https://search.censys.io/). By examining known C2 addresses we can select few specific point to use in our query. Here is 3 example queries;

```python
services.http.response.favicons.md5_hash="39705673fd05bd34b425d495ed8471c9"
services.software.uniform_resource_identifier: "cpe:2.3:a:neptune-loader:neptune-loader:*:*:*:*:*:*:*:*"
services.http.response.body_hash="sha1:85cc188de3d85d423ef3f5f1cd1f6955c1d575d2"
```

As of the time when this article was written, our Censys search queries have unveiled four IP addresses connected to the Neptune C2 Panel.

![Untitled](/assets/img/neptune/23.png)

# Part 4 - Hunting with Yara

As we embark on the journey to uncover more Neptune samples, we will develop two YARA rules. The first rule is aimed at detecting the packed sample, while the second rule is optimized for identifying the unpacked variant.

1. **Yara Rule for Packed Sample**

While examining the distinctive traits of the packed sample, several noteworthy characteristics emerge. Typically, the packed sample exhibits `more than seven sections`, one of which bears a `randomly generated seven-character name` and often possesses an `entropy value exceeding seven`. Additionally, this section tends to have a `substantial size`. The packer employs `VirtualAlloc` to allocate memory, utilizes `memcpy` for copying data from this section to the allocated memory, and concludes with a call to `eax` signifying the start of the newly allocated memory.

*Our YARA rule adopts a somewhat aggressive approach by verifying if the entropy of the specific section exceeds 7 and if its size surpasses 240,000. While it is possible to lower these thresholds in certain scenarios, doing so may increase the likelihood of encountering false positives.*

```php
import "pe"
import "math"
rule NeptuneLoader_Packed_Amber {
	meta:
		author = "tufan - @tufan_gngr"
		description = "Detects Amber PE Reflective Packer used on Neptune Loader"
		date = "2024-01-14"
		references = "https://tufan-gungor.github.io/"
	strings:
		$s1 = "VirtualAlloc"
		$s2 = "memcpy"
		$s3 = {E8 70 10 00 00 8B 45 D4 FF D0} // call eax, following by memcpy
		$s4 = {E8 7? 52 0A 00} // immediate call in encrypted section
	condition:
		uint16(0) == 0x5A4D and
		uint32(uint32(0x3C)) == 0x00004550 and
		pe.number_of_sections > 7 and
		for any j in (0..pe.number_of_sections - 1): (
			math.entropy(pe.sections[j].raw_data_offset, pe.sections[j].raw_data_size) >= 7 and
			pe.sections[j].raw_data_size >= 0x0003A980 and
			pe.sections[j].name matches /\.[A-Za-z0-9]{7}/
		) and
		3 of them

}
```

After running RetroHunt in VirusTotal with this Yara rule to find related samples, it yields numerous matches. Upon examining the characteristics of these files, there are suggestive similarities that might point to a potential association with an edited version reminiscent of the [Amber Reflective PE packer](https://github.com/EgeBalci/amber). 

![Untitled](/assets/img/neptune/24.png)

While we refer to it as an 'edited' version, it's important to note that YARA rules crafted by other researchers for detecting Amber do not align with the packed Neptune samples. However, the YARA rule designed specifically for packed Neptune samples has shown matches with files that have been packed using Amber.

All the packed samples share similar technical characteristics, including a seven-character-long section with encrypted data, among others. However, it's worth noting that there are no strings or indicators explicitly related to Amber in these samples.

Given these circumstances, hunting Neptune samples by concentrating on its packer proves challenging. If the packer is identified as Amber, it can lead to numerous false positives. Therefore, our focus will shift towards the unpacked sample.

1. **Yara Rule for Unpacked Sample**

As you may recall, the unpacked sample reveals numerous distinct characteristics, including AV checks, VM checks, anti-debugging measures, C2 communication, and more. With this wealth of specific functions and behaviors, we can pinpoint and utilize particular strings associated with these functions to construct our YARA rule.

```php
rule NeptuneLoader_Unpacked {
	meta:
		author = "tufan - @tufan_gngr"
		description = "Detects unpacked sample of Neptune Loader"
		date = "2024-01-14"
		references = "https://tufan-gungor.github.io/"
	strings:
		$s1 = "REGISTER"
		$s2 = "GETCMD"
		$s3 = "httpflood"
		$s4 = "visitpagehidden"
		$s5 = "&sandboxie="
		$s6 = "&isLaptop="
		$s7 = "addbot.php"
		$s8 = "tasks.php"
		$s9 = "SOFTWARE\\VMware"
		$s10 = "SOFTWARE\\Oracle\\VirtualBox"
		$s11 = "Gate is open"
	condition:
		uint16(0) == 0x5A4D and
		uint32(uint32(0x3C)) == 0x00004550 and
		7 of them
}
```

As our hunt primarily revolves around locating unpacked Neptune samples, we will deviate from the conventional approach of utilizing VirusTotal and initiate our search on [Unpacme](https://www.unpac.me/).

Upon running the Yara Hunt on Unpacme using our Yara rule, it flags three matches. Notably, the first two matches were as expected, representing samples employed within the ongoing campaign we are investigating. These files closely resemble the ones we've previously examined.

![Untitled](/assets/img/neptune/25.png)

However, the third file stands out as significantly distinct from the files we've previously analyzed. This particular file is a .NET executable named 'ablast.exe,' and it unfolds the Neptune sample after processing several others.

**SHA256: *f98cf9ee6e3f42fe35ec570b4728ecd65929ba24ba4c090c3b438c8de4677cc8 (packed parent)***

**SHA256: *cf70fa1d010f0077ccb4ff039f3764c47756113a7bcc28acbd5f96d6df56e9a7 (unpacked child)***

Upon examining the packed parent of this file on Tria.ge and VirusTotal, it becomes apparent that this particular sample is a variant of `zgRAT`. Intriguingly, following the unpacking process, it proceeds to execute Neptune.

![Untitled](/assets/img/neptune/26.png)

In examining its relations on VirusTotal, we notice a familiar network traffic.

![Untitled](/assets/img/neptune/27.png)

# Part 5 - IOCs

```text
2a3549512f5f9cf1b11a26897a79532adc548c3000fb7b07fcae6b49cd5222ad
f98cf9ee6e3f42fe35ec570b4728ecd65929ba24ba4c090c3b438c8de4677cc8
cf70fa1d010f0077ccb4ff039f3764c47756113a7bcc28acbd5f96d6df56e9a7
f98cf9ee6e3f42fe35ec570b4728ecd65929ba24ba4c090c3b438c8de4677cc8
91.92.240.153
91.92.240.152
194.33.191.106
91.92.252.7
94.156.65.54
mfuk.app
tdboat.online
ruspyc.top
```

# References

- [https://hackforums.net/showthread.php?tid=6256979](https://hackforums.net/showthread.php?tid=6256979)
- [https://twitter.com/ViriBack/status/1744726264618119591](https://twitter.com/ViriBack/status/1744726264618119591)
- [https://twitter.com/ShanHolo/status/1744740555203203074](https://twitter.com/ShanHolo/status/1744740555203203074)
- [https://twitter.com/banthisguy9349/status/1744772559730593998](https://twitter.com/banthisguy9349/status/1744772559730593998)
- [https://twitter.com/0xperator/status/1745176382915695096](https://twitter.com/0xperator/status/1745176382915695096)

**I utilized AI assistance to fine-tune certain sentences in this post, enhancing clarity and precision.**
