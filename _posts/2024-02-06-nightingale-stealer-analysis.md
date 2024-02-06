---
title: Hunt and Analysis - Nightingale Stealer
author: Tufan Gungor
date: 2024-02-06 00:00:00 +0800
categories: [Reverse Engineering,Malware Hunting]
tags: [reverse engineering,malware hunting]
math: true
mermaid: true
---

# Part 1 - Nightingale Stealer

*Spoiler Alert: If you are familiar with Phemedrone Stealer, be prepared for a revelation. Nightingale Stealer, as it turns out, is essentially an edited version of Phemedrone Stealer. Knowing this beforehand can help manage expectations as you read through this article.*

![Untitled](/assets/img/nightingale/0.png)

On `December 15, 2023`, a user operating under the alias `-Nightingale-` posted an advertisement on [HackForums](https://hackforums.net/showthread.php?tid=6258265) for a stealer malware dubbed `Nightingale's Stealer`. This threat is designed to exfiltrate credentials from 75 different wallets, alongside passwords, cookies, browser data, and application data from platforms such as `Steam`, `Telegram`, and `Discord`.

![Untitled](/assets/img/nightingale/1.png)

On January 29, 2024, nearly a month and a half after its initial appearance, Twitter user [@suyog41](https://twitter.com/suyog41/status/1751930165230469619) posted about `Nightingale's Stealer`, sharing the hash of the malware sample.

![Untitled](/assets/img/nightingale/2.png)

In this article, we will concentrate on examining this particular malware sample. We'll download it from `VirusTotal`, analyze its components, and decode its operational framework to gain a deeper understanding of its functionalities.

# Part 2 - Dissecting The First Nightingale’s Stealer Sample

Upon searching the hash on VirusTotal, it was found to be flagged as malicious by 52 out of 71 antivirus engines. Intriguingly, Yara Rules indicate that this sample is associated with `Phemedrone Stealer`, while various collections and comments suggest it might be `Formbook`. Let's proceed to download the sample to ascertain its true nature.

![Untitled](/assets/img/nightingale/3.png)

**SHA256: *0cc6d724ac017163b40866c820fd67df6ac89924a623490ec1de2ecacf1d0219***

Upon opening the file in IDA, an intriguing aspect becomes apparent in the IDA navigator: the code area is noticeably small compared to a significantly larger data area. This characteristic typically indicates one of two possibilities: the file is either `encrypted` or `packed`.

![Untitled](/assets/img/nightingale/4.png)

## Unpacking / Decryption

IDA proficiently renamed all functions, streamlining the analysis of the `main` function. Initially, the main function duplicates `two data blobs` into `memory via memcpy`. It then utilizes the `first blob as data` and the `second as an XOR key` for decrypting the first blob. Subsequently, the decrypted data is written to a file named `sms2A85.tmp` (in this instance) located under the `\AppData\Local\Temp\` folder. Following this, the malware initiates a new process with this file.

![Untitled](/assets/img/nightingale/5.png)

Instead of dedicating time to decrypt the blob through static analysis, we'll employ the debugger, placing a breakpoint on `CreateProcessA`. This method facilitates the retrieval of the decrypted file from the `\AppData\Local\Temp` folder, streamlining our analysis.

This approach resulted in the discovery of a new `.NET executable file` named `sms2A85.tmp`, advancing our investigation further.

**SHA256: *1fdd63b4b1db9637871a4f574c746980977accf2a0f6c3ceaef82b6641a3e9e7***

![Untitled](/assets/img/nightingale/6.png)

The file is identified as `Phemedrone Stealer` by crowdsourced Yara rules and comments in VirusTotal. Keeping this in mind, we will continue with our analysis and circle back to this classification at the end of our investigation.

## Detailed Analysis of the Extracted .NET File

Moving forward with our analysis, we'll leverage `DNSpy` based on the identification of the second file as a `.NET executable`, as determined by `ExeInfo` .

**SHA256: *1fdd63b4b1db9637871a4f574c746980977accf2a0f6c3ceaef82b6641a3e9e7***

![Untitled](/assets/img/nightingale/7.png)

In our examination using `dnSpy`, we encountered `obfuscated function names` and observed that nearly all strings utilized within the malware are `encrypted`. To navigate these hurdles, our initial step will involve dissecting the string decryption routine. This process will enable us to decrypt and appropriately label these strings as we progress through the analysis of the functions. Furthermore, we will assign meaningful names to the functions, enhancing the clarity of our investigation.

![Untitled](/assets/img/nightingale/8.png)

Upon further scrutiny of the main function, we noticed numerous instances where encrypted strings are passed to a method named `Odebelivagy.Bacaruzehakik`. This pattern strongly suggests that we have identified the decryption function

![Untitled](/assets/img/nightingale/9.png)

The decryption routine initiates by base64 decoding the encoded data, followed by an XOR decryption process using a hardcoded key.

### String Decryption

In order to facilitate a quicker analysis, we intend to rewrite the string decryptor using `Python`. This adaptation will enhance our ability to navigate through the malware's obfuscations more swiftly. Additionally, at the end of this article, `we will share a Python-based string extractor/decryptor`, designed to automate the decryption of the malware's strings.

```python
>>> import base64
>>> xor_key = "83o8vqawvcq7uy8f"
>>> enc_string = "a1wJTAEQExIq"
>>> result = []
>>> dec_string = base64.b64decode(enc_string)
>>> for i in range(len(dec_string)):
...     value = dec_string[i] ^ ord(xor_key[i % len(xor_key)])
...     result.append(chr(value))
...
>>> print(''.join(result))
Software\
```

In certain instances, the output from the initial `base64 decoding` and `XOR decryption` steps contains `special characters`, rather than the expected decrypted strings. This anomaly indicates the presence of an additional layer of decryption or decoding. The process involves splitting the resultant string at spaces to isolate the special character set, which is then mapped to corresponding values using a predefined dictionary. This secondary step is crucial for fully deciphering the encrypted data.

![Untitled](/assets/img/nightingale/10.png)

Given the complexity of the additional decryption/decoding step, we can again turn to Python to reimplement this function.

```python
import base64

def decrypt_base64(encoded_str):
        xor_key = "83o8vqawvcq7uy8f"
        result = []

        dec_string = base64.b64decode(encoded_str)
        for i in range(len(dec_string)):
            value = dec_string[i] ^ ord(xor_key[i % len(xor_key)])
            result.append(chr(value))

        return ''.join(result)

char_to_word_mapping = {
    'A': decrypt_base64("Fh4="),
    'B': decrypt_base64("FR1BFg=="),
    'C': decrypt_base64("FR1CFg=="),
    'D': decrypt_base64("FR1B"),
    'E': decrypt_base64("Fg=="),
    'F': decrypt_base64("Fh1CFg=="),
    'G': decrypt_base64("FR5B"),
    'H': decrypt_base64("Fh1BFg=="),
    'I': decrypt_base64("Fh0="),
    'J': decrypt_base64("Fh5CFQ=="),
    'K': decrypt_base64("FR1C"),
    'L': decrypt_base64("Fh5BFg=="),
    'M': decrypt_base64("FR4="),
    'N': decrypt_base64("FR0="),
    'O': decrypt_base64("FR5C"),
    'P': decrypt_base64("Fh5CFg=="),
    'Q': decrypt_base64("FR5BFQ=="),
    'R': decrypt_base64("Fh5B"),
    'S': decrypt_base64("Fh1B"),
    'T': decrypt_base64("FQ=="),
    'U': decrypt_base64("Fh1C"),
    'V': decrypt_base64("Fh1BFQ=="),
    'W': decrypt_base64("Fh5C"),
    'X': decrypt_base64("FR1BFQ=="),
    'Y': decrypt_base64("FR1CFQ=="),
    'Z': decrypt_base64("FR5BFg=="),
    '1': decrypt_base64("Fh5CFVs="),
    '2': decrypt_base64("Fh1CFVs="),
    '3': decrypt_base64("Fh1BFVs="),
    '4': decrypt_base64("Fh1BFls="),
    '5': decrypt_base64("Fh1BFlg="),
    '6': decrypt_base64("FR1BFlg="),
    '7': decrypt_base64("FR5BFlg="),
    '8': decrypt_base64("FR5CFlg="),
    '9': decrypt_base64("FR5CFVg="),
    '0': decrypt_base64("FR5CFVs="),
    'a': decrypt_base64("Em0="),
    'b': decrypt_base64("ZhlFEg=="),
    'c': decrypt_base64("ZhkxEg=="),
    'd': decrypt_base64("ZhlF"),
    'e': decrypt_base64("Eg=="),
    'f': decrypt_base64("EhkxEg=="),
    'g': decrypt_base64("Zm1F"),
    'h': decrypt_base64("EhlFEg=="),
    'i': decrypt_base64("Ehk="),
    'j': decrypt_base64("Em0xZg=="),
    'k': decrypt_base64("Zhkx"),
    'l': decrypt_base64("Em1FEg=="),
    'm': decrypt_base64("Zm0="),
    'n': decrypt_base64("Zhk="),
    'o': decrypt_base64("Zm0x"),
    'p': decrypt_base64("Em0xEg=="),
    'q': decrypt_base64("Zm1FZg=="),
    'r': decrypt_base64("Em1F"),
    's': decrypt_base64("EhlF"),
    't': decrypt_base64("Zg=="),
    'u': decrypt_base64("Ehkx"),
    'v': decrypt_base64("EhlFZg=="),
    'w': decrypt_base64("Em0x"),
    'x': decrypt_base64("ZhlFZg=="),
    'y': decrypt_base64("ZhkxZg=="),
    'z': decrypt_base64("Zm1FEg=="),
    '.': decrypt_base64("Eh5FFVxc"),
    ',': decrypt_base64("FR5FEltc"),
    '?': decrypt_base64("EhlCFVxb"),
    '_': decrypt_base64("EhlCFTYx"),
    ':': decrypt_base64("EhkwZ1BX"),
    ';': decrypt_base64("Rk0xZg=="),
    '-': decrypt_base64("eE0wEg=="),
    '/': decrypt_base64("HBkwEw=="),
    '\\': decrypt_base64("EmxEZihS"),
    '&': decrypt_base64("Rk0RZg=="),
    '=': decrypt_base64("ZhVFElxb"),
    ')': decrypt_base64("HW1K"),
    '(': decrypt_base64("ZhYx"),
    '+': decrypt_base64("HRYxZg=="),
    '$': decrypt_base64("Zm1KHSgv"),
    '@': decrypt_base64("Zm1KZlMvPw=="),
    '#': decrypt_base64("HhlJElA="),
    '!': decrypt_base64("RhUREg=="),
    '"': decrypt_base64("EGwwRCkuSA=="),
    ' ': decrypt_base64("EGwwEF8uPl4="),
    '>': decrypt_base64("EHJG"),
    '<': decrypt_base64("EHFG")
}

def decode_text(input_text):
    words = input_text.split(' ')
    decoded_chars = []

    for word in words:
        for char, encrypted_word in char_to_word_mapping.items():
            if encrypted_word == word:
                decoded_chars.append(char)
                break

    return ''.join(decoded_chars)

decoded_text = decode_text(input("Enc Data: "))
print(decoded_text)
```

```
└─[$]> python3 dec.py

Enc Data: -.-. *^** *^ *** *** * *** *_+^^# *_+^^# ^^ *** @~_* *** * ^ ^ ** ^* ^^* *** *_+^^# *_+^^# *** **** * *^** *^** *_+^^# *_+^^# ^^^ *^^* * ^* *_+^^# *_+^^# ^*^* ^^^ ^^ ^^ *^ ^* ^**

Classes\\ms-settings\\shell\\open\\command
```

Now that we have successfully implemented the essential string decoding and decryption mechanisms in Python, we are fully equipped to commence the detailed analysis of the malware's functionalities.

### Persistency

Initially, the malware conducts a preliminary check of the current user and the name of the file it is executing from. To ensure its persistence on the host system, it proceeds to create a new registry key at `Classes\ms-settings\shell\open\command` with `DelegateExecute` set to `0`. Following this setup, it executes the command `cmd.exe /c start computerdefaults.exe`, embedding itself further into the system.

![Untitled](/assets/img/nightingale/11.png)

With Nightingale Stealer's configurable options accessible via their panel, users can select from various methods of achieving persistency. If the chosen configuration dictates this path, the malware employs an alternative approach. This begins with the creation of a new registry subkey under `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, followed by the setup of a scheduled task using the command `schtasks.exe /create /tn {0} /tr "{1}" /sc MINUTE /mo {2} /ru "System" /F`. This adaptable strategy ensures the malware remains operational within the system.

![Untitled](/assets/img/nightingale/12.png)

![Untitled](/assets/img/nightingale/13.png)

### Anti CIS and Target Countries

Nightingale Stealer determines if there are specific target countries identified for its operation. It conducts a check to ascertain if the compromised device is located within these predefined countries. In the event the location does not match any of the target countries, the malware will cease its activity and exit.

![Untitled](/assets/img/nightingale/14.png)

The malware then conducts a check on the installed Keyboard Input Layouts to see if they match a predefined list associated with CIS countries.

![Untitled](/assets/img/nightingale/15.png)

```
ru-RU
uk-UA
kk-KZ
ro-MD
uz-UZ
be-BY
az-Latn-AZ
hy-AM
ky-KG
tg-Cyrl-Tj
```

### VM Detection

After confirming the current country of the device, the malware methodically checks for an internet connection, continually monitoring until the device secures a connection to the internet. Following this, it embarks on detecting virtual machines by examining information related to the graphics card, aiming to discern whether the system is a real or virtualized environment.

![Untitled](/assets/img/nightingale/16.png)

```
VirtualBox
VBox
VMWare Virtual
VMware
Hyper-V Video
SELECT * FROM Win32_VideoController
```

### Other Checks and Configs

To maintain stealth and efficiency, Nightingale Stealer incorporates multiple checks within its operations. It begins by examining the existence of a Mutex named `Usabiribejagamocazo` ensuring that only a single instance runs at any given time. Additionally, the malware surveys the running processes, terminating itself if it identifies `wireshark` or `httpdebbugerui` to avoid unwanted attention. Lastly, it executes two strategic commands designed to exclude itself from `Windows Defender's` scrutiny, further enhancing its covert operation.

```powershell
cmd /k start /b powershell -inputformat none -outputformat none -NonInteractive -Command Add-MpPreference -ExclusionPath & exit
cmd /k start /b powershell -inputformat none -outputformat none -NonInteractive -Command Add-MpPreference -ExclusionExtension .exe & exit
```

![Untitled](/assets/img/nightingale/17.png)

### Data Collection Functions

1. File Grabber

Our exploration of `Nightingale Stealer`'s Data Collection Functions brings us to the `File Grabber`. This particular function is responsible for harvesting files from the user's personal and desktop directories.

![Untitled](/assets/img/nightingale/18.png)

```
*.txt
*.dat
*seed*
*.mafile
```

1. Wallet Grabber

Next up is the `Wallet Grabber` function in Nightingale Stealer's Data Collection Functions. It simply looks for wallet data in the user's `ApplicationData` and `LocalApplicationData` folders. It checks both `desktop` wallet app data and `browser wallet extensions`.

![Untitled](/assets/img/nightingale/19.png)

```
wallet.dat
Wallets/
atomic\Local Storage\leveldb
Google\Chrome\User Data\Default\Local Extension Settings\kpfopkelmapcoipemfendmdcghnegimn
.
.
.
```

1. FTP Grabber

The `FTP Grabber` function in Nightingale Stealer collects data from folders such as `FTP/` and `FileZilla/` located within the `AppData` directory.

![Untitled](/assets/img/nightingale/20.png)

```
\FileZilla\sitemanager.xml
\FileZilla\recentservers.xml
\FileZilla
FTP/
```

1. Discord & Steam & Telegram Grabber

There are three functions dedicated to data collection from `Discord`, `Steam`, and `Telegram`. These functions gather data from application data folders, registries, and other relevant sources.

![Untitled](/assets/img/nightingale/21.png)

```
*cord*
HKEY_CURRENT_USER\Software\Valve\Steam
SteamPath
*ssfn*
*.vdf
\config
Steam/
HKEY_CLASSES_ROOT\tg\DefaultIcon
usertag
settings
key_data
prefix
Messengers/TGgoods/
```

1. Browser Data Grabber

`Nightingale Stealer` includes two Browser Data Grabber functions. The first one collects a wide range of browser data, including `extensions`, `autofills`, `cookies`, `sessions`, and more. The second function specializes in gathering key databases. Additionally, the malware places a specific emphasis on targeting certain extensions, particularly password managers.

![Untitled](/assets/img/nightingale/22.png)

```
User Data
Local State
Module Info Cache
Last Version
1.0.0.0
Cookies
autofill
credit_cards
Web Data
Browser Data/Cookies_
Authenticator
EOS Authenticator
.
.
.

```

1. Device Info Grabber

`Nightingale Stealer` features two Device Info Grabber functions, responsible for collecting detailed information about the device. This data includes `IP addresses`, `country information`, `hardware details`, and more. The collected information is then prepared for transmission to the command and control (C2) server.

![Untitled](/assets/img/nightingale/23.png)

```
IP:
query
Country:
country
countryCode
City:
city
Postal:
zip
MAC:
Username:
Windows name:
x64
Hardware ID:
GPU:

{0,-25}
CPU:
RAM:
Passwords:
Cookies:
Credit Cards:
AutoFills:
Extensions
Wallets:
Files:

Passwrods Tags:
,
Cookies Tags:
,
Antivirus products:
,
File Location:
unknown
Information.txt
query
country
countryCode
*Nightingale Stealer Report* \| by Nightingale

``` - IP: {0} \({1}\)
 - Tag: {2} {3}
 - Passwords: {4}
 - Cookies: {5}
 - Wallets: {6}```

Unknown
Unknown
(
query
country
countryCode
Unknown
Unknown
Unknown
,
,
query
countryCode
(
Unknown
)
-
Unknown
-Nightingale-Report.zip
http://ip-api.com/json/?fields=11827
Unknown
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion
Unknown
root\SecurityCenter2
displayName
X2
:
Unknown
Memory
SELECT * FROM Win32_VideoController
Name
Unknown
Unknown
SELECT * FROM Win32_Processor
Name
Unknown
Unknown
SELECT * FROM Win32_ComputerSystem
TotalPhysicalMemory
0
Win32_Processor
ProcessorId
Win32_DiskDrive
SerialNumber
SELECT * FROM
X2
Unknown
```

1. Screenshot

Finally, Nightingale Stealer includes the capability to capture a screenshot of the current view on the device.

![Untitled](/assets/img/nightingale/24.png)

### Data Exfiltration

Nightingale Stealer offers three distinct data exfiltration methods: Telegram, Panel, and Server (Gate). In the current instance, stolen data is sent to the threat actor via the Panel method, with the data being exfiltrated to `kinggru.duckdns.org` through port `3999`.

![Untitled](/assets/img/nightingale/25.png)

# Part 3 - String Extractor / Decryptor

As previously mentioned, Nightingale Stealer employs two distinct encoding and encryption routines to conceal strings. To gain a comprehensive view of all the concealed strings within the malware, we will develop a Python-based string extractor/decryptor.

```python
import base64
import subprocess

def decrypt(encoded_string):
    decryption_key = "83o8vqawvcq7uy8f"
    decoded_bytes = base64.b64decode(encoded_string)
    decrypted_chars = [
        chr(byte ^ ord(decryption_key[i % len(decryption_key)]))
        for i, byte in enumerate(decoded_bytes)
    ]
    return ''.join(decrypted_chars)

def extract_and_decrypt_strings(file_name):
    output = subprocess.check_output(['strings', '-e', 'l', file_name])
    strings = output.decode().splitlines()
    
    for string in strings:
        try:
            decrypted_string = decrypt(string)
            if decrypted_string.isascii():
                clear_str = decode_text(decrypted_string)
                if clear_str == "":
                    print(decrypted_string)
                else:
                    print(clear_str)
        except Exception as e:
            continue

char_to_word_mapping = {
    'A': decrypt("Fh4="),
    'B': decrypt("FR1BFg=="),
    'C': decrypt("FR1CFg=="),
    'D': decrypt("FR1B"),
    'E': decrypt("Fg=="),
    'F': decrypt("Fh1CFg=="),
    'G': decrypt("FR5B"),
    'H': decrypt("Fh1BFg=="),
    'I': decrypt("Fh0="),
    'J': decrypt("Fh5CFQ=="),
    'K': decrypt("FR1C"),
    'L': decrypt("Fh5BFg=="),
    'M': decrypt("FR4="),
    'N': decrypt("FR0="),
    'O': decrypt("FR5C"),
    'P': decrypt("Fh5CFg=="),
    'Q': decrypt("FR5BFQ=="),
    'R': decrypt("Fh5B"),
    'S': decrypt("Fh1B"),
    'T': decrypt("FQ=="),
    'U': decrypt("Fh1C"),
    'V': decrypt("Fh1BFQ=="),
    'W': decrypt("Fh5C"),
    'X': decrypt("FR1BFQ=="),
    'Y': decrypt("FR1CFQ=="),
    'Z': decrypt("FR5BFg=="),
    '1': decrypt("Fh5CFVs="),
    '2': decrypt("Fh1CFVs="),
    '3': decrypt("Fh1BFVs="),
    '4': decrypt("Fh1BFls="),
    '5': decrypt("Fh1BFlg="),
    '6': decrypt("FR1BFlg="),
    '7': decrypt("FR5BFlg="),
    '8': decrypt("FR5CFlg="),
    '9': decrypt("FR5CFVg="),
    '0': decrypt("FR5CFVs="),
    'a': decrypt("Em0="),
    'b': decrypt("ZhlFEg=="),
    'c': decrypt("ZhkxEg=="),
    'd': decrypt("ZhlF"),
    'e': decrypt("Eg=="),
    'f': decrypt("EhkxEg=="),
    'g': decrypt("Zm1F"),
    'h': decrypt("EhlFEg=="),
    'i': decrypt("Ehk="),
    'j': decrypt("Em0xZg=="),
    'k': decrypt("Zhkx"),
    'l': decrypt("Em1FEg=="),
    'm': decrypt("Zm0="),
    'n': decrypt("Zhk="),
    'o': decrypt("Zm0x"),
    'p': decrypt("Em0xEg=="),
    'q': decrypt("Zm1FZg=="),
    'r': decrypt("Em1F"),
    's': decrypt("EhlF"),
    't': decrypt("Zg=="),
    'u': decrypt("Ehkx"),
    'v': decrypt("EhlFZg=="),
    'w': decrypt("Em0x"),
    'x': decrypt("ZhlFZg=="),
    'y': decrypt("ZhkxZg=="),
    'z': decrypt("Zm1FEg=="),
    '.': decrypt("Eh5FFVxc"),
    ',': decrypt("FR5FEltc"),
    '?': decrypt("EhlCFVxb"),
    '_': decrypt("EhlCFTYx"),
    ':': decrypt("EhkwZ1BX"),
    ';': decrypt("Rk0xZg=="),
    '-': decrypt("eE0wEg=="),
    '/': decrypt("HBkwEw=="),
    '\\': decrypt("EmxEZihS"),
    '&': decrypt("Rk0RZg=="),
    '=': decrypt("ZhVFElxb"),
    ')': decrypt("HW1K"),
    '(': decrypt("ZhYx"),
    '+': decrypt("HRYxZg=="),
    '$': decrypt("Zm1KHSgv"),
    '@': decrypt("Zm1KZlMvPw=="),
    '#': decrypt("HhlJElA="),
    '!': decrypt("RhUREg=="),
    '"': decrypt("EGwwRCkuSA=="),
    ' ': decrypt("EGwwEF8uPl4="),
    '>': decrypt("EHJG"),
    '<': decrypt("EHFG")
}

def decode_text(input_text):
    words = input_text.split(' ')
    decoded_chars = []

    for word in words:
        for char, encrypted_word in char_to_word_mapping.items():
            if encrypted_word == word:
                decoded_chars.append(char)
                break

    return ''.join(decoded_chars)

file_name = "dropped_file.exe"
extract_and_decrypt_strings(file_name)
```

For the sake of simplicity and code brevity, we utilized the `strings -e l` command to extract encrypted strings from the malware. However, it's worth noting that this extraction process can also be implemented in Python.

Decrypted Strings:

```
Panel
NightingalePanel
Gate
Telegram
kinggru.duckdns.org
3999
%GATE%
Token
Chat ID
Invalid input
%TARGET%
@anontsugumi
Asimuxu
50
*.txt
*seed*
*.dat
*.mafile
false
true
Usabiribejagamocazo
A
B
C
D
E
F
G
H
I
J
K
L
M
N
O
P
Q
R
S
T
U
V
W
X
Y
Z
1
2
3
4
5
6
7
8
9
0
a
b
c
d
e
f
g
h
i
j
k
l
m
n
o
p
q
r
s
t
u
v
w
x
y
z
.
,
?
_
:
;
-
/
\
&
=
)
(
+
$
@
#
!
"
 
>
<
Classes\\ms-settings\\shell\\open\\command
DelegateExecute
Software\
Waiting for network connection...
Network connection established.
8.8.8.8
Canada
France
USA
England
Germany
Not connected to network. Waiting for network connection...
Password.txt
Messengers/Discord Tokens.txt
cmd.exe
/c start computerdefaults.exe
wallet.dat
Wallets/
\
Armory
Atomic
atomic\Local Storage\leveldb
Bytecoin
bytecoin
Coninomi
Coinomi\Coinomi\wallets
Jaxx
com.liberty.jaxx\IndexedDB\file_0.indexeddb.leveldb
Electrum
Electrum\wallets
Exodus
Exodus\exodus.wallet
Guarda
Guarda\Local Storage\leveldb
Zcash
Ethereum
Ethereum\keystore
Liquality
Google\Chrome\User Data\Default\Local Extension Settings\kpfopkelmapcoipemfendmdcghnegimn
Nifty
Google\Chrome\User Data\Default\Local Extension Settings\jbdaocneiiinmjbjlgalhcelgbejmnid
Oxygen
Google\Chrome\User Data\Default\Local Extension Settings\fhilaheimglignddkjgofkcbgekhenbh
Crocobit
Google\Chrome\User Data\Default\Local Extension Settings\pnlfjmlcjdjgkddecgincndfgegkecke
Keplr
Google\Chrome\User Data\Default\Local Extension Settings\dmkamcknogkgcdfhhbddcghachkejeap
Finnie
Google\Chrome\User Data\Default\Local Extension Settings\cjmkndjhnagcfbpiemnkdpomccnjblmj
Swash
Google\Chrome\User Data\Default\Local Extension Settings\cmndjbecilbocjfkibfbifhngkdmjgog
Starcoin
Google\Chrome\User Data\Default\Local Extension Settings\mfhbebgoclkghebffdldpobeajmbecfk
Slope
Google\Chrome\User Data\Default\Local Extension Settings\pocmplpaccanhmnllbbkpgfliimjljgo
Phantom
Google\Chrome\User Data\Default\Local Extension Settings\bfnaelmomeimhlpmgjnjophhpkkoljpa
Carat
Google\Chrome\User Data\Default\Local Extension Settings\gjdpfnfmelhakanjicgoeepdoninjjod
Bitfi
Google\Chrome\User Data\Default\Local Extension Settings\kffganmbldfgkgineogpgclfkkngcool
Gemini
Google\Chrome\User Data\Default\Local Extension Settings\llmlhlddaeediifoladephjpgejknmal
Rainbow
Google\Chrome\User Data\Default\Local Extension Settings\fgmanlmbjbclcnkficdodlognkeheejb
Raven
Google\Chrome\User Data\Default\Local Extension Settings\gchanpaeodapopimpablnkmenhkndddi
Tomo
Google\Chrome\User Data\Default\Local Extension Settings\kcbnmnnkigeelbhlfllahgejbhdnlhan
Monarch
Google\Chrome\User Data\Default\Local Extension Settingspgnemdcbsnenjgpajdflhjnelnhkdcb
Catalyst
Google\Chrome\User Data\Default\Local Extension Settings
ojhmikaojhghfplekghaghaeogmdhnl
Ruby
Google\Chrome\User Data\Default\Local Extension Settings\gbanjdaphdabiocllfbjolmdjckocjnj
Crypton
Google\Chrome\User Data\Default\Local Extension Settings\edffijlgmobnajlneenopceappncihfj
Rumble
Google\Chrome\User Data\Default\Local Extension Settings\mlnmjikdhcblohfpfdfmegjkjlnbbkna
Lido
Google\Chrome\User Data\Default\Local Extension Settings\fnlgpnbkflbpcpkkohbiojomgeokejjn
Jelly
Google\Chrome\User Data\Default\Local Extension Settings\okompkjedlhgdlkhbanmiboeploplgpc
OpenSea
Google\Chrome\User Data\Default\Local Extension Settings\aabeakehlapikpddikddcikneklnfbfl
SimpleSwap
Google\Chrome\User Data\Default\Local Extension Settings\lfmgcmgkbkphaaggnofnhoonmjfmjhah
TronLink
Google\Chrome\User Data\Default\Local Extension Settings\ibnejdfjmmkpcnlpebklmnkoeoihofec
UniSwap
Google\Chrome\User Data\Default\Local Extension Settings\ncljmiffkofogcgiepiflbfhjelkklkb
MetaVault
Google\Chrome\User Data\Default\Local Extension Settings\apakagogmckphjnojeblmiaahdnogkni
SafePal
Google\Chrome\User Data\Default\Local Extension Settings\jcjejccajkejpnadafclaophjfpjebhm
Chrome_Sollet
Google\Chrome\User Data\Default\Local Extension Settings\fhmfendgdocmcbmfikdcogofphimnkno
Chrome_Metamask
Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn
Chrome_Ton
Google\Chrome\User Data\Default\Local Extension Settings\nphplpgoakhhjchkkhmiggakijnkhfnd
Chrome_XinPay
Google\Chrome\User Data\Default\Local Extension Settings\bocpokimicclpaiekenaeelehdjllofo
Chrome_Mobox
Google\Chrome\User Data\Default\Local Extension Settings\fcckkdbjnoikooededlapcalpionmalo
Chrome_Iconex
Google\Chrome\User Data\Default\Local Extension Settings\flpiciilemghbmfalicajoolhkkenfel
Chrome_Guild
Google\Chrome\User Data\Default\Local Extension Settings\nanjmdknhkinifnkgdcggcfnhdaammmj
Chrome_Equal
Google\Chrome\User Data\Default\Local Extension Settings\blnieiiffboillknjnepogjhkgnoapac
Chrome_Coin98
Google\Chrome\User Data\Default\Local Extension Settings\aeachknmefphepccionboohckonoeemg
Chrome_Bitapp
Google\Chrome\User Data\Default\Local Extension Settings\fihkakfobkmkjojpchpfgcmhfjnmnfpi
Chrome_Binance
Google\Chrome\User Data\Default\Local Extension Settings\fhbohimaelbohpjbbldcngcnapndodjp
Chrome_Google_Authicator
Google\Chrome\User Data\Default\Local Extension Settings\bhghoamapcdpbohphigoooaddinpkbai
Chrome_YOROI_WALLET
Google\Chrome\User Data\Default\Local Extension Settings\ffnbelfdoeiohenkjibnmadjiehjhajb
Chrome_NIFTY
Chrome_MATH
Google\Chrome\User Data\Default\Local Extension Settings\afbcbjpbpfadlkmhmclhkeeodmamcflc
Chrome_COINBASE
Google\Chrome\User Data\Default\Local Extension Settings\hnfanknocfeofbddgcijnmhnfnkdnaad
Chrome_EQUAL
Google\Chrome\User Data\Default\IndexedDB\chrome-extension_blnieiiffboillknjnepogjhkgnoapac_0.indexeddb.leveldb
Chrome_WOMBAT
Google\Chrome\User Data\Default\Local Extension Settings\amkmjjmmflddogmhpjloimipbofnfjih
Chrome_IWALLET
Google\Chrome\User Data\Default\Sync Extension Settings\nlbmnnijcnlegkjjpcfjclmcfggfefdm
Chrome_GUILD1
Google\Chrome\User Data\Default\Sync Extension Settings\nanjmdknhkinifnkgdcggcfnhdaammmj
Chrome_SATURN
Google\Chrome\User Data\Default\Local Extension Settings\nkddgncdjgjfcddamfgcmfnlhccnimig
Chrome_RONIN
Google\Chrome\User Data\Default\Local Extension Settings\fnjhmkhhmkbjkkabndcnnogagogbneec
Chrome_NEOLINE
Google\Chrome\User Data\Default\Local Extension Settings\cphhlgmgameodnhkjdmkpanlelnlohao
Chrome_CLOVER
Google\Chrome\User Data\Default\Local Extension Settings\nhnkbkgjikgcigadomkphalanndcapjk
Chrome_LIQUALITY
Edge_Auvitas
Microsoft\Edge\User Data\Default\Local Extension Settings\klfhbdnlcfcaccoakhceodhldjojboga
Edge_Math
Microsoft\Edge\User Data\Default\Local Extension Settings\dfeccadlilpndjjohbjdblepmjeahlmm
Edge_Metamask
Microsoft\Edge\User Data\Default\Local Extension Settings\ejbalbakoplchlghecdalmeeeajnimhm
Edge_MTV
Microsoft\Edge\User Data\Default\Local Extension Settings\oooiblbdpdlecigodndinbpfopomaegl
Edge_Rabet
Microsoft\Edge\User Data\Default\Local Extension Settings\aanjhgiamnacdfnlfnmgehjikagdbafd
Edge_Ronin
Microsoft\Edge\User Data\Default\Local Extension Settings\bblmcdckkhkhfhhpfcchlpalebmonecp
Edge_Yoroi
Microsoft\Edge\User Data\Default\Local Extension Settings\akoiaibnepcedcplijmiamnaigbepmcb
Edge_Zilpay
Microsoft\Edge\User Data\Default\Local Extension Settings\fbekallmnjoeggkefjkbebpineneilec
Edge_Exodus
Microsoft\Edge\User Data\Default\Local Extension Settings\jdiccldimpdaibmpdkjnbmckianbfold
/
\FileZilla\recentservers.xml
\FileZilla\sitemanager.xml
\FileZilla
FTP/
Profiles
key3.db
key4.db
cookies.sqlite
moz_cookies
formhistory.sqlite
moz_formhistory
Browser Data/Cookies_
[
].txt

Browser Data/AutoFills_

logins.json
encryptedUsername
encryptedPassword
hostname
[^ -]
1
metaData
password
2A864886F70D010C050103
ISO-8859-1
password-check
2A864886F70D01050D
nssPrivate
*.ini
global-salt
Version
User Data
1.0.0.0
Local State
Network
Cookies
cookies
Web Data
autofill
Login Data
logins
credit_cards
Local Storage
leveldb
CreditCards.txt
Profile*
Default
Authenticator
bhghoamapcdpbohphigoooaddinpkbai
EOS Authenticator
oeljdldpnmdbchonielidgobddffflal
BrowserPass
naepdomgkenhinolocfifgehidddafch
MYKI
bmikpgodpkclnkgmnpphehdgcimmided
Splikity
jhfjfclepacoldmjmkmdlmganfaalklb
CommonKey
chgfefjpcobfbnpmiokfjjaglahmnded
Zoho Vault
igkpcodhieompeloncfnbekccinhapdb
Norton Password Manager
admmjipmmciaobhojoghlmleefbicajg
Avira Password Manager
caljgklbbfbcjjanaijlacgncafpegll
Trezor Password Manager
imloifkgjagghnncjkhggdhalmcnfklk
MetaMask
nkbihfbeogaeaoehlefnkodbefgpgknn
ibnejdfjmmkpcnlpebklmnkoeoihofec
BinanceChain
fhbohimaelbohpjbbldcngcnapndodjp
Coin98
aeachknmefphepccionboohckonoeemg
iWallet
kncchdigobghenbbaddojjnnaogfppfj
Wombat
amkmjjmmflddogmhpjloimipbofnfjih
MEW CX
nlbmnnijcnlegkjjpcfjclmcfggfefdm
NeoLine
cphhlgmgameodnhkjdmkpanlelnlohao
Terra Station
aiifbnbfobpmeekipheeijimdpnlpgpp
dmkamcknogkgcdfhhbddcghachkejeap
Sollet
fhmfendgdocmcbmfikdcogofphimnkno
ICONex
flpiciilemghbmfalicajoolhkkenfel
KHC
hcflpincpppdclinealmandijcmnkbgn
TezBox
mnfifefkajgofkcjkemidiaecocnkjeh
Byone
nlgbhdfgdhgbiamfdfmbikcdghidoadd
OneKey
ilbbpajmiplgpehdikmejfemfklpkmke
Trust Wallet
pknlccmneadmjbkollckpblgaaabameg
MetaWallet
pfknkoocfefiocadajpngdknmkjgakdg
Guarda Wallet
fcglfhcjfpkgdppjbglknafgfffkelnm
idkppnahnmmggbmfkjhiakkbkdpnmnon
Jaxx Liberty
mhonjhhcgphdphdjcdoeodfdliikapmj
Atomic Wallet
bhmlbgebokamljgnceonbncdofmmkedg
hieplnfojfccegoloniefimmbfjdgcgp
Mycelium
pidhddgciaponoajdngciiemcflpnnbg
Coinomi
blbpgcogcoohhngdjafgpoagcilicpjh
GreenAddress
gflpckpfdgcagnbdfafmibcmkadnlhpj
Edge
doljkehcfhidippihgakcihcmnknlphh
BRD
nbokbjkelpmlgflobbohapifnnenbjlh
Samourai Wallet
apjdnokplgcjkejimjdfjnhmjlbpgkdi
Copay
ieedgmmkpkbiblijbbldefkomatsuahh
Bread
jifanbgejlbcmhbbdbnfbfnlmbomjedj
Airbitz
KeepKey
dojmlmceifkfgkgeejemfciibjehhdcl
Trezor
jpxupxjxheguvfyhfhahqvxvyqthiryh
Ledger Live
pfkcfdjnlfjcmkjnhcbfhfkkoflnhjln
Ledger Wallet
hbpfjlflhnmkddbjdchbbifhllgmmhnm
Bitbox
ocmfilhakdbncmojmlbagpkjfbmeinbd
Digital Bitbox
dbhklojmlkgmpihhdooibnmidfpeaing
YubiKey
mammpjaaoinfelloncbbpomjcihbkmmc
Google Authenticator
khcodhlfkpmhibicdjjblnkgimdepgnd
Microsoft Authenticator
bfbdnbpibgndpjfhonkflpkijfapmomn
Authy
gjffdbjndmcafeoehgdldobgjmlepcal
Duo Mobile
eidlicjlkaiefdbgmdepmmicpbggmhoj
OTP Auth
bobfejfdlhnabgglompioclndjejolch
FreeOTP
elokfmmmjbadpgdjmgglocapdckdcpkn
Aegis Authenticator
ppdjlkfkedmidmclhakfncpfdmdgmjpm
LastPass Authenticator
cfoajccjibkjhbdjnpkbananbejpkkjb
Dashlane
flikjlpgnpcjdienoojmgliechmmheek
Keeper
gofhklgdnbnpcdigdgkgfobhhghjmmkj
RoboForm
hppmchachflomkejbhofobganapojjol
KeePass
lbfeahdfdkibininjgejjgpdafeopflb
KeePassXC
kgeohlebpjgcfiidfhhdlnnkhefajmca
Bitwarden
inljaljiffkdgmlndjkdiepghpolcpki
NordPass
njgnlkhcjgmjfnfahdmfkalpjcneebpl
LastPass
gabedfkgnbglfbnplfpjddgfnbibkmbb
Local Extension Settings
Browser Data/Extensions/
_
Module Info Cache
Last Version
*cord*
FileGrabber
IP:
query
Country:
country
countryCode
City:
city
Postal:
zip
MAC:
Username:
Windows name:
x32
x64
Hardware ID:
GPU:

{0,-25}
CPU:
RAM:
Passwords:
Cookies:
Credit Cards:
AutoFills:
Extensions
Wallets:
Files:

Passwrods Tags:
, 
Cookies Tags:
Antivirus products:
File Location:
unknown
Information.txt
TTTTT
\.
Unknown
(
)
-Nightingale-Report.zip
http://ip-api.com/json/?fields=11827
root\SecurityCenter2
e
displayName
X2
:
Memory
Available Bytes
e
Name
e
e
TotalPhysicalMemory
0
Win32_Processor
ProcessorId
Win32_DiskDrive
SerialNumber
e
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion
ProductName
user32.dll
GetDC
gdi32.dll
GetDeviceCaps
Screenshot.png
*ssfn*
\config
*.vdf
Steam/
HKEY_CURRENT_USER\Software\Valve\Steam
SteamPath
root\CIMV2
yyyy-MM-dd h:mm:ss tt
HKEY_CLASSES_ROOT\tg\DefaultIcon
tdata
s
usertag
settings
key_data
prefix
Messengers/TGgoods/
file
filename
filedescription
POST
----------------------------
x
multipart/form-data; boundary=
Content-Disposition: form-data; name="
"; filename="
"
Content-Type: application/octet-stream
Invalid IP address or port number. Unable to send the data.
Invalid argument format. Unable to send the data.
.zip
https://api.telegram.org/bot{0}/sendDocument
document
chat_id
parse_mode
MarkdownV2
caption
wireshark
httpdebbugerui
VirtualBox
VBox
VMware Virtual
VMware
Hyper-V Video
ru-RU
uk-UA
kk-KZ
ro-MD
uz-UZ
be-BY
az-Latn-AZ
hy-AM
ky-KG
tg-Cyrl-TJ
SOFTWARE\Microsoft\Windows\CurrentVersion\Run
System
cmd
/k start /b powershell -inputformat none -outputformat none -NonInteractive -Command Add-MpPreference -ExclusionPath 
 & exit
/k start /b powershell -inputformat none -outputformat none -NonInteractive -Command Add-MpPreference -ExclusionExtension .exe & exit
schtasks.exe
/create /tn {0} /tr "{1}" /sc MINUTE /mo {2} /ru "System" /F
/create /tn 
 /tr "
" /sc ONLOGON /ru "System" /F
TGgoods
{0}	{1}	{2}	{3}	{4}	{5}	{6}
Name: 

Value: 
Hostname: 

Username: 

Password: 

Browser: 
 v
 (
Number: {0}
Placeholder: {1}
Expiration: {2}/{3}
Browser: {4} v{5} ({6})
*.ldb
encrypted_key
DPAPI
roblox.com
steampowered.com
genshin
epicgames.com
fortnite.com
GAMES
qiwi
tinkoff
yoomoney
sberbank
BANK
facebook
FACEBOOK
funpay
paypal
americanexpress
amazon
MONEY
spotify
music.apple
MUSIC
deadcode
celka
nursultan
akrien
expenisve
wexside
x.synapse
synapse
neverlose
gamesense
nixware
primordial
interium
xone
CHEATS
dQw4w9WgXcQ:[^"]*
dQw4w9WgXcQ:
e
ParentProcessId
UNIQUE
Writing is not allowed
v1
bcrypt.dll
BCryptDecrypt
BCryptDestroyKey
BCryptCloseAlgorithmProvider
AES
Microsoft Primitive Provider
ChainingModeGCM
BCryptOpenAlgorithmProvider
BCryptSetProperty
ChainingMode
AuthTagLength
BCryptImportKey
ObjectLength
KeyDataBlob
BCryptGetProperty
crypt32.dll
CryptUnprotectData
algorithm
Algorithm cannot be null.
Password cannot be null.
salt
Salt cannot be null.
Derived key too long.
SEQUENCE {
{0:X2}
	INTEGER 
	OCTETSTRING 
	OBJECTIDENTIFIER 
}
00061561
```

# Part 4 - Nightingale Stealer vs Phemedrone Stealer

At the beginning of this article, we noticed that the `Nightingale Stealer` sample was labeled as `Phemedrone Stealer` by crowdsourced YARA rules. In this section, we'll explore why this identification occurred.

To achieve this, we will obtain the source code of Phemedrone Stealer. Subsequently, we will systematically `compare each extracted string from Nightingale Stealer with the source code of Phemedrone Stealer`. This comparative analysis will provide insights into the extent of similarity between the two.

To minimize the chances of false positive matches, we initiated the process by compiling a list of strings with `three or more characters`. Following this, we implemented a Bash script designed for the comparative analysis.

```bash
#!/bin/bash

declare -A matchedStrings

while IFS= read -r line; do
    if grep -qr --include="*" "$line" Phemedrone-Stealer-master/; then
        if [ -z "${matchedStrings[$line]}" ]; then
            echo "Matched: '${line}'"
            matchedStrings[$line]=1
        fi
    fi
done < strings.txt
```

Upon executing the script, we identified a total of `328` matching strings present in both Nightingale Stealer and Phemedrone Stealer.

Matched strings;

```bash
Matched: '*.dat'
Matched: '*.ini'
Matched: '*.ldb'
Matched: '*.mafile'
Matched: '*.txt'
Matched: '*.vdf'
Matched: '*cord*'
Matched: '*seed*'
Matched: '*ssfn*'
Matched: '00061561'
Matched: '1.0.0.0'
Matched: '2A864886F70D01050D'
Matched: '2A864886F70D010C050103'
Matched: '8.8.8.8'
Matched: 'Aegis Authenticator'
Matched: 'Airbitz'
Matched: 'Algorithm cannot be null.'
Matched: 'Antivirus products:'
Matched: 'Armory'
Matched: 'Atomic'
Matched: 'Atomic Wallet'
Matched: 'AuthTagLength'
Matched: 'Authenticator'
Matched: 'Authy'
Matched: 'AutoFills:'
Matched: 'Available Bytes'
Matched: 'Avira Password Manager'
Matched: 'BCryptCloseAlgorithmProvider'
Matched: 'BCryptDecrypt'
Matched: 'BCryptDestroyKey'
Matched: 'BCryptGetProperty'
Matched: 'BCryptImportKey'
Matched: 'BCryptOpenAlgorithmProvider'
Matched: 'BCryptSetProperty'
Matched: 'BinanceChain'
Matched: 'Bitbox'
Matched: 'Bitwarden'
Matched: 'Bread'
Matched: 'Browser Data/AutoFills_'
Matched: 'Browser Data/Cookies_'
Matched: 'Browser Data/Extensions/'
Matched: 'Browser: '
Matched: 'BrowserPass'
Matched: 'Byone'
Matched: 'Bytecoin'
Matched: 'CHEATS'
Matched: 'Catalyst'
Matched: 'ChainingMode'
Matched: 'ChainingModeGCM'
Matched: 'Chat ID'
Matched: 'City:'
Matched: 'Coin98'
Matched: 'Coinomi'
Matched: 'CommonKey'
Matched: 'Coninomi'
Matched: 'Content-Type: application/octet-stream'
Matched: 'Cookies'
Matched: 'Cookies Tags:'
Matched: 'Cookies:'
Matched: 'Copay'
Matched: 'Country:'
Matched: 'Credit Cards:'
Matched: 'CreditCards.txt'
Matched: 'CryptUnprotectData'
Matched: 'DPAPI'
Matched: 'Dashlane'
Matched: 'Default'
Matched: 'Derived key too long.'
Matched: 'Digital Bitbox'
Matched: 'Duo Mobile'
Matched: 'EOS Authenticator'
Matched: 'Electrum'
Matched: 'Exodus'
Matched: 'Extensions'
Matched: 'File Location:'
Matched: 'FileGrabber'
Matched: 'Files:'
Matched: 'FreeOTP'
Matched: 'GAMES'
Matched: 'GetDC'
Matched: 'GetDeviceCaps'
Matched: 'Google Authenticator'
Matched: 'GreenAddress'
Matched: 'Guarda'
Matched: 'Guarda Wallet'
Matched: 'Hardware ID:'
Matched: 'Hostname: '
Matched: 'Hyper-V Video'
Matched: 'ICONex'
Matched: 'ISO-8859-1'
Matched: 'Information.txt'
Matched: 'Jaxx Liberty'
Matched: 'KeePass'
Matched: 'KeePassXC'
Matched: 'KeepKey'
Matched: 'Keeper'
Matched: 'Keplr'
Matched: 'KeyDataBlob'
Matched: 'Last Version'
Matched: 'LastPass'
Matched: 'LastPass Authenticator'
Matched: 'Ledger Live'
Matched: 'Ledger Wallet'
Matched: 'Local Extension Settings'
Matched: 'Local State'
Matched: 'Local Storage'
Matched: 'Login Data'
Matched: 'MEW CX'
Matched: 'MONEY'
Matched: 'MUSIC'
Matched: 'MarkdownV2'
Matched: 'Memory'
Matched: 'MetaMask'
Matched: 'MetaWallet'
Matched: 'Microsoft Authenticator'
Matched: 'Microsoft Primitive Provider'
Matched: 'Module Info Cache'
Matched: 'Mycelium'
Matched: 'Name: '
Matched: 'NeoLine'
Matched: 'Network'
Matched: 'NordPass'
Matched: 'Norton Password Manager'
Matched: 'OTP Auth'
Matched: 'ObjectLength'
Matched: 'OneKey'
Matched: 'Panel'
Matched: 'ParentProcessId'
Matched: 'Password cannot be null.'
Matched: 'Password.txt'
Matched: 'Password: '
Matched: 'Passwords:'
Matched: 'Postal:'
Matched: 'ProcessorId'
Matched: 'ProductName'
Matched: 'Profile*'
Matched: 'Profiles'
Matched: 'RoboForm'
Matched: 'SEQUENCE {'
Matched: 'Salt cannot be null.'
Matched: 'Samourai Wallet'
Matched: 'Screenshot.png'
Matched: 'SerialNumber'
Matched: 'Sollet'
Matched: 'Splikity'
Matched: 'Steam/'
Matched: 'SteamPath'
Matched: 'System'
Matched: 'Telegram'
Matched: 'Terra Station'
Matched: 'TezBox'
Matched: 'Token'
Matched: 'TotalPhysicalMemory'
Matched: 'Trezor'
Matched: 'Trezor Password Manager'
Matched: 'TronLink'
Matched: 'Trust Wallet'
Matched: 'UNIQUE'
Matched: 'Unknown'
Matched: 'User Data'
Matched: 'Username:'
Matched: 'Username: '
Matched: 'VMware'
Matched: 'VMware Virtual'
Matched: 'Value: '
Matched: 'Version'
Matched: 'VirtualBox'
Matched: 'Wallets/'
Matched: 'Wallets:'
Matched: 'Web Data'
Matched: 'Win32_DiskDrive'
Matched: 'Win32_Processor'
Matched: 'Windows name:'
Matched: 'Wombat'
Matched: 'Writing is not allowed'
Matched: 'YubiKey'
Matched: 'Zoho Vault'
Matched: '[^ -]'
Matched: '\FileZilla'
Matched: '\config'
Matched: '].txt'
Matched: 'admmjipmmciaobhojoghlmleefbicajg'
Matched: 'aeachknmefphepccionboohckonoeemg'
Matched: 'aiifbnbfobpmeekipheeijimdpnlpgpp'
Matched: 'akrien'
Matched: 'algorithm'
Matched: 'amazon'
Matched: 'americanexpress'
Matched: 'amkmjjmmflddogmhpjloimipbofnfjih'
Matched: 'apjdnokplgcjkejimjdfjnhmjlbpgkdi'
Matched: 'autofill'
Matched: 'az-Latn-AZ'
Matched: 'bcrypt.dll'
Matched: 'be-BY'
Matched: 'bfbdnbpibgndpjfhonkflpkijfapmomn'
Matched: 'bhghoamapcdpbohphigoooaddinpkbai'
Matched: 'bhmlbgebokamljgnceonbncdofmmkedg'
Matched: 'blbpgcogcoohhngdjafgpoagcilicpjh'
Matched: 'bmikpgodpkclnkgmnpphehdgcimmided'
Matched: 'bobfejfdlhnabgglompioclndjejolch'
Matched: 'bytecoin'
Matched: 'caljgklbbfbcjjanaijlacgncafpegll'
Matched: 'caption'
Matched: 'celka'
Matched: 'cfoajccjibkjhbdjnpkbananbejpkkjb'
Matched: 'chat_id'
Matched: 'chgfefjpcobfbnpmiokfjjaglahmnded'
Matched: 'cmd.exe'
Matched: 'cookies'
Matched: 'cookies.sqlite'
Matched: 'country'
Matched: 'countryCode'
Matched: 'cphhlgmgameodnhkjdmkpanlelnlohao'
Matched: 'credit_cards'
Matched: 'crypt32.dll'
Matched: 'dQw4w9WgXcQ:'
Matched: 'dQw4w9WgXcQ:[^"]*'
Matched: 'dbhklojmlkgmpihhdooibnmidfpeaing'
Matched: 'displayName'
Matched: 'dmkamcknogkgcdfhhbddcghachkejeap'
Matched: 'document'
Matched: 'dojmlmceifkfgkgeejemfciibjehhdcl'
Matched: 'doljkehcfhidippihgakcihcmnknlphh'
Matched: 'eidlicjlkaiefdbgmdepmmicpbggmhoj'
Matched: 'elokfmmmjbadpgdjmgglocapdckdcpkn'
Matched: 'encryptedPassword'
Matched: 'encryptedUsername'
Matched: 'encrypted_key'
Matched: 'epicgames.com'
Matched: 'false'
Matched: 'fcglfhcjfpkgdppjbglknafgfffkelnm'
Matched: 'fhbohimaelbohpjbbldcngcnapndodjp'
Matched: 'fhmfendgdocmcbmfikdcogofphimnkno'
Matched: 'filedescription'
Matched: 'filename'
Matched: 'flikjlpgnpcjdienoojmgliechmmheek'
Matched: 'flpiciilemghbmfalicajoolhkkenfel'
Matched: 'formhistory.sqlite'
Matched: 'funpay'
Matched: 'gabedfkgnbglfbnplfpjddgfnbibkmbb'
Matched: 'gamesense'
Matched: 'gdi32.dll'
Matched: 'genshin'
Matched: 'gflpckpfdgcagnbdfafmibcmkadnlhpj'
Matched: 'gjffdbjndmcafeoehgdldobgjmlepcal'
Matched: 'global-salt'
Matched: 'gofhklgdnbnpcdigdgkgfobhhghjmmkj'
Matched: 'hbpfjlflhnmkddbjdchbbifhllgmmhnm'
Matched: 'hcflpincpppdclinealmandijcmnkbgn'
Matched: 'hieplnfojfccegoloniefimmbfjdgcgp'
Matched: 'hostname'
Matched: 'hppmchachflomkejbhofobganapojjol'
Matched: 'http://ip-api.com/json/?fields=11827'
Matched: 'httpdebbugerui'
Matched: 'hy-AM'
Matched: 'iWallet'
Matched: 'ibnejdfjmmkpcnlpebklmnkoeoihofec'
Matched: 'idkppnahnmmggbmfkjhiakkbkdpnmnon'
Matched: 'ieedgmmkpkbiblijbbldefkomatsuahh'
Matched: 'igkpcodhieompeloncfnbekccinhapdb'
Matched: 'ilbbpajmiplgpehdikmejfemfklpkmke'
Matched: 'imloifkgjagghnncjkhggdhalmcnfklk'
Matched: 'inljaljiffkdgmlndjkdiepghpolcpki'
Matched: 'interium'
Matched: 'jhfjfclepacoldmjmkmdlmganfaalklb'
Matched: 'jifanbgejlbcmhbbdbnfbfnlmbomjedj'
Matched: 'jpxupxjxheguvfyhfhahqvxvyqthiryh'
Matched: 'key3.db'
Matched: 'key4.db'
Matched: 'key_data'
Matched: 'kgeohlebpjgcfiidfhhdlnnkhefajmca'
Matched: 'khcodhlfkpmhibicdjjblnkgimdepgnd'
Matched: 'kk-KZ'
Matched: 'kncchdigobghenbbaddojjnnaogfppfj'
Matched: 'ky-KG'
Matched: 'lbfeahdfdkibininjgejjgpdafeopflb'
Matched: 'leveldb'
Matched: 'logins'
Matched: 'logins.json'
Matched: 'mammpjaaoinfelloncbbpomjcihbkmmc'
Matched: 'metaData'
Matched: 'mhonjhhcgphdphdjcdoeodfdliikapmj'
Matched: 'mnfifefkajgofkcjkemidiaecocnkjeh'
Matched: 'moz_cookies'
Matched: 'moz_formhistory'
Matched: 'multipart/form-data; boundary='
Matched: 'music.apple'
Matched: 'naepdomgkenhinolocfifgehidddafch'
Matched: 'nbokbjkelpmlgflobbohapifnnenbjlh'
Matched: 'neverlose'
Matched: 'nixware'
Matched: 'njgnlkhcjgmjfnfahdmfkalpjcneebpl'
Matched: 'nkbihfbeogaeaoehlefnkodbefgpgknn'
Matched: 'nlbmnnijcnlegkjjpcfjclmcfggfefdm'
Matched: 'nlgbhdfgdhgbiamfdfmbikcdghidoadd'
Matched: 'nssPrivate'
Matched: 'nursultan'
Matched: 'ocmfilhakdbncmojmlbagpkjfbmeinbd'
Matched: 'oeljdldpnmdbchonielidgobddffflal'
Matched: 'parse_mode'
Matched: 'password'
Matched: 'password-check'
Matched: 'paypal'
Matched: 'pfkcfdjnlfjcmkjnhcbfhfkkoflnhjln'
Matched: 'pfknkoocfefiocadajpngdknmkjgakdg'
Matched: 'pidhddgciaponoajdngciiemcflpnnbg'
Matched: 'pknlccmneadmjbkollckpblgaaabameg'
Matched: 'ppdjlkfkedmidmclhakfncpfdmdgmjpm'
Matched: 'prefix'
Matched: 'query'
Matched: 'ro-MD'
Matched: 'ru-RU'
Matched: 'sberbank'
Matched: 'settings'
Matched: 'spotify'
Matched: 'steampowered.com'
Matched: 'tdata'
Matched: 'tg-Cyrl-TJ'
Matched: 'tinkoff'
Matched: 'uk-UA'
Matched: 'unknown'
Matched: 'user32.dll'
Matched: 'usertag'
Matched: 'uz-UZ'
Matched: 'wallet.dat'
Matched: 'wireshark'
Matched: 'yoomoney'
Matched: '{0:X2}'
```

**Our analysis strongly suggests that Nightingale Stealer is, in essence, an edited version of Phemedrone Stealer. It appears that the threat actor behind Nightingale Stealer made minimal alterations, primarily changing a few strings to 'Nightingale' and customizing certain features.**

**This discovery helps clarify why crowdsourced YARA rules initially identified this sample as Phemedrone Stealer, despite the presence of 'Nightingale' strings within it.**

# Part 5 - Yara Rule

After an extensive analysis, it has become evident that `Nightingale Stealer` is, in fact, a variant of `Phemedrone Stealer`. Given this discovery, rather than creating new YARA rules for essentially the same malware source code, we can leverage the crowdsourced YARA rules originally designed for Phemedrone Stealer.

```php
import "pe"

rule MALWARE_Win_PhemedroneStealer
{
	meta:
		author = "ditekSHen"
		description = "Detects Phemedrone Stealer infostealer"
		os = "windows"
		filetype = "executable"

	strings:
		$p1 = /\{ file = \{(0|file)\}, data = \{(1|data)\} \}/ ascii wide
		$p2 = "{ <>h__TransparentIdentifier0 = {0}, match = {1} }" wide
		$p3 = "{ <>h__TransparentIdentifier1 = {0}, encrypted = {1} }" wide
		$p4 = "{<>h__TransparentIdentifier0}, match = {match} }" ascii
		$p5 = "{<>h__TransparentIdentifier1}, encrypted = {encrypted} }" ascii
		$s1 = "<KillDebuggers>b__" ascii
		$s2 = "<ParseExtensions>b__" ascii
		$s3 = "<ParseDiscordTokens>b__" ascii
		$s4 = "<IsVM>b__" ascii
		$s5 = "<Key3Database>b__" ascii
		$s6 = "masterPass" ascii
		$s7 = "rootLocation" ascii
		$s8 = "rgsServiceNames" ascii
		$s9 = "rgsFilenames" ascii

	condition:
		uint16(0)==0x5a4d and (( all of ($p*) and 3 of ($s*)) or (3 of ($p*) and 4 of ($s*)) or (7 of ($s*)))
}
```

# Part 6 - IOCs

```
0cc6d724ac017163b40866c820fd67df6ac89924a623490ec1de2ecacf1d0219
1fdd63b4b1db9637871a4f574c746980977accf2a0f6c3ceaef82b6641a3e9e7
kinggru.duckdns.org
```

# References

- [https://twitter.com/suyog41/status/1751930165230469619](https://twitter.com/suyog41/status/1751930165230469619)
- [https://hackforums.net/showthread.php?tid=6258265](https://hackforums.net/showthread.php?tid=6258265)
- [https://github.com/kid0604/yara-rules/blob/e6adc1c81e0698b6c349e78148bffa78c5ed7c5b/executable_windows/4334482e8e93d3407716ad54a0a3988e60a02eb6.yar](https://github.com/kid0604/yara-rules/blob/e6adc1c81e0698b6c349e78148bffa78c5ed7c5b/executable_windows/4334482e8e93d3407716ad54a0a3988e60a02eb6.yar)

**I utilized AI assistance to fine-tune certain sentences in this post, enhancing clarity and precision.**