---
title: Hunt and Analysis - Hornet Stealer
author: Tufan Gungor
date: 2024-01-30 00:00:00 +0800
categories: [Reverse Engineering,Malware Hunting]
tags: [reverse engineering,malware hunting]
math: true
mermaid: true
---


# Part 1 - Hornet Stealer

![Untitled](assets/img/hornet/0.png)

On January 24th, the Twitter account [@spamhaus](https://twitter.com/spamhaus/status/1750170178493526350/photo/1) posted a tweet regarding a newly discovered C2  panel. Based on the panel's logo and name, they have identified this malware as `Hornet Stealer`.

![Untitled](assets/img/hornet/1.png)

According to [@spamhaus](https://twitter.com/spamhaus/status/1750170181710602474)'s tweets, `Hornet Stealer`, which is downloaded via `Smokeloader`, is written in `Golang`. It targets several applications, such as `browsers`, `wallets`, `Steam`, `Telegram`, among others. The malware decrypts strings using `Fernet` with a hardcoded key, then encrypts the acquired data using `AES GCM`, and finally transmits this encrypted data to a server via `TCP connection`.

In this article, we aim to discover and analyze the earliest known sample of the `Hornet Stealer` malware.

# Part 2 - **Dissecting the First Hornet Stealer Sample**

## 1. Tracing the Origins of the Hornet Stealer

To locate the initial sample of the `Hornet Stealer`, we can examine the IP address relationships mentioned in [@spamhaus](https://twitter.com/spamhaus/status/1750170181710602474)'s tweet on VirusTotal.

Upon searching for the IP address `185.221.198.118` and navigating to the Relations tab on VirusTotal, one can observe a file under the 'Communicating Files' section. This file appears to be malicious, indicated by its high `detection score of 42 out of 71`.

![Untitled](assets/img/hornet/2.png)

Navigating to the Details tab of this file reveals that it is programmed in Golang, and its initial submission date of `January 23, 2024`, suggests that it's a recent addition. These details strongly point to it being the `Hornet Stealer` sample we're investigating.

![Untitled](assets/img/hornet/3.png)

**SHA256: *bc3ee10c21cb07bc0dd6b84a6eaf8efbd0af889467ab7ef647acf60f8c188e83***

Prior to analyzing this file, it's worthwhile to investigate its potential connection with `Smokeloader`. However, the `Relations` tab in `VirusTotal` doesn't display any links to `Smokeloader`. A quick Google search using the file's hash led to a result from `Unpacme`, revealing that this file is hosted on the transfer.sh website with a name `setup.exe`.

![Untitled](assets/img/hornet/4.png)

**Link: *https://transfer.sh/get/q4ccSmjmTB/setup.exe***

A search on VirusTotal using this link reveals a `Crowdsourced Context` note stating `Activity related to SMOKELOADER`. However, it doesn't provide an associated sample.

## 2. Deep Dive into the Hornet Stealer’s First Sample

**SHA256: *bc3ee10c21cb07bc0dd6b84a6eaf8efbd0af889467ab7ef647acf60f8c188e83***

Aware that this sample contains encrypted strings and utilizes `Fernet` for runtime decryption, we can proceed by loading the sample into IDA. This will allow us to closely examine its string decryption routine.

Given that the sample's symbolic information is not stripped, IDA has been able to rename all functions, thereby facilitating an easier analysis.

![Untitled](assets/img/hornet/5.png)

The presence of meaningful function names simplifies our task to reading the code. Nonetheless, the challenge lies in the encryption of crucial strings. To uncover how they are decrypted, we concentrate on the first function call, following the path: `main.main` > `setup_utils_AntiCIS` > `setup_utils_GetkeyboardLayoutList` > `setup_utils_DecryptString`. This path leads us to identify `setup_utils_DecryptString` as the key function for string decryption.

![Untitled](assets/img/hornet/6.png)

The recurring use of a string at the offset `off_70CC10` before every call to `setup_utils_DecryptString` suggested to us that this might be the decryption key.

Although [@spamhaus](https://twitter.com/spamhaus/status/1750170178493526350)'s tweet already indicated the use of Fernet, we can confirm this by examining `setup_utils_DecryptString` more closely.

![Untitled](assets/img/hornet/7.png)

With the algorithm, decryption key, and encrypted data at hand, we have the opportunity to use `Python` for decrypting a string, which will validate the correctness of our approach.

```
>>> from cryptography.fernet import Fernet
>>> key = 'MpQzH0ne3b-TkBgkJ0tbdALxiCiJuLBleGUlEoIGQoo='
>>> encrypted_data = 'gAAAAABlsBIs-I3FZyAavfZo8FAeeSmwVqn5DHwjQGrATv5Mz3jzjEk9KD9LBJiTzKDvGmb-RFX1Z-jBO4x5JUIy-ZD6Zf103A=='
>>> fernet = Fernet(key)
>>> decrypted_data = fernet.decrypt(encrypted_data)
>>> decrypted_data
**b'user32.dll'**
>>> decrypted_data.decode()
**'user32.dll'**
```

The effectiveness of our method was proven when our Python code decrypted a string into `user32.dll`. Henceforth, I will decrypt and annotate every string in the functions with their decrypted counterparts as comments. Furthermore, at the end of this article, a `custom string extractor` for this malware sample will be introduced.

Armed with this knowledge, let's delve into analyzing some key functionalities of the `Hornet Stealer`, starting with the `setup_utils_init` function.

### setup_utils_init Function

We begin our analysis with the `setup_utils_init` function, which is executed even before the main function. It plays a crucial role in decrypting several important strings, one of which is the C2 address.

![Untitled](assets/img/hornet/8.png)

### setup_Grabber_init Function

The `setup_Grabber_init` function, executing prior to the main function, decrypts several crucial strings, including a list of wallet applications. The utilization of these decrypted strings will be explored in a later part of our analysis.

![Untitled](assets/img/hornet/9.png)

First decrypted string;

```
Exodus || exodus || Partitions || cache || dictionar
Atomic || atomic || cache || IndexedDB
JaxxLiberty || com.liberty.jaxx || cache
Coinomi || Coinomi\Coinomi\wallets || null-
Electrum || Electrum\wallets || null-
Electrum-LTC || Electrum-LTC\wallets || null-
ElectronCash || ElectronCash\wallets || null-
Guarda || Guarda || cache || IndexedDB
MyMonero || MyMonero || cache
Monero || Monero\\wallets || null-
Wasabi || WalletWasabi\\Client || tor || log
TokenPocket || TokenPocket || cache
Ledger Live || Ledger Live || cache || dictionar || sqlite
Binance || Binance || cache || null-
```

Second decrypted string;

```
fhbohimaelbohpjbbldcngcnapndodjp || BinanceChain
fnjhmkhhmkbjkkabndcnnogagogbneec || Ronin
kjmoohlgokccodicjjfebfomlbljgfhk || Ronin
nkbihfbeogaeaoehlefnkodbefgpgknn || MetaMask
ejbalbakoplchlghecdalmeeeajnimhm || MetaMask
ibnejdfjmmkpcnlpebklmnkoeoihofec || TronLink
egjidjbpglichdcondbcbdnbeeppgdph || TrustWallet
bfnaelmomeimhlpmgjnjophhpkkoljpa || Phantom
hnfanknocfeofbddgcijnmhnfnkdnaad || Coinbase
odbfpeeihdkbihmopkbjmoonfanlbfcl || Brave
cgeeodpfagjceefieflmdfphplkenlfk || TON
aeachknmefphepccionboohckonoeemg || Coin98
mcohilncbfahbmgdjkbpemcciiolgcge || MetaX
hmeobnfnfcmdkdcmlblgagmfpfboieaf || XDEFI
lpilbniiabackdjcionkobglmddfbcjo || WavesKeeper
bhhhlbepdkbapadjdnnojkbgioiodbic || Solflare
acmacodkjbdgmoleebolmdjonilkdbch || Rabby
dkdedlpgdmmkkfjabffeganieamfklkm || CyanoWallet
cnmamaachppnkjgnildpdmkaakejnhae || AuroWallet
hcflpincpppdclinealmandijcmnkbgn || KHC
mnfifefkajgofkcjkemidiaecocnkjeh || TezBox
ookjlbkiijinhpmnjffcofjonbfbgaoc || Temple
flpiciilemghbmfalicajoolhkkenfel || ICONex
fhmfendgdocmcbmfikdcogofphimnkno || Sollet
nhnkbkgjikgcigadomkphalanndcapjk || CloverWallet
jojhfeoedkpkglbfimdfabpdfjaoolaf || PolymeshWallet
cphhlgmgameodnhkjdmkpanlelnlohao || NeoLine
dmkamcknogkgcdfhhbddcghachkejeap || Keplr
ajkhoeiiokighlmdnlakpjfoobnjinie || TerraStation
aiifbnbfobpmeekipheeijimdpnlpgpp || TerraStation
kpfopkelmapcoipemfendmdcghnegimn || Liquality
nkddgncdjgjfcddamfgcmfnlhccnimig || SaturnWallet
nanjmdknhkinifnkgdcggcfnhdaammmj || GuildWallet
jnkelfanjkeadonecabehalmbgpfodjm || Goby
nphplpgoakhhjchkkhmiggakijnkhfnd || TON
fpkhgmpbidmiogeglndfbkegfdlnajnf || Cosmostation
jiidiaalihmmhddjgbnbgdfflelocpak || BitKeep
pgiaagfkgcbnmiiolekcfmljdagdhlcm || Stargazer
cjelfplplebdjjenllpjcblmjkfcffne || JaxxLiberty
kkpllkodjeloidieedojogacfhpaihoh || Enkrypt
pkkjjapmlcncipeecdmlhaipahfdphkd || GameStopWallet
aholpfdialjgjfhomihkjbmgjidlcdno || ExodusWeb3Wallet
nngceckbapebfimnlniiiahkandclblb || Bitwarden
efbglgofoippbgcjepnhiblaibcnclgk || MartianAptos
jnlgamecbpmbajjfhmmmlhejkemejdma || Braavos
mcohilncbfahbmgdjkbpemcciiolgcge || OKX
phkbamefinggmakgklpkljjmgibohnba || PontemAptos
epapihdplajcdnnkdeiahlgigofloibg || SenderWallet
gjagmgiddbbciopjhllkdnddhcglnemk || Hashpack
cgeeodpfagjceefieflmdfphplkenlfk || EVER
cjmkndjhnagcfbpiemnkdpomccnjblmj || Finnie
aijcbedoijmgnlmjeegjaglmepbmpkpi || LeapTerra
ejjladinnckdgjemekebdpeokbikhfci || PetraAptos
kmhcihpebfmpgmihbkipmjlmmioameka || Eternl
bgpipimickeadkjlklgciifhnalhdjhe || GeroWallet
lpfcbjknijpeeillifnkikgncikgfhdo || NamiWallet
pocmplpaccanhmnllbbkpgfliimjljgo || SlopeWallet
ffnbelfdoeiohenkjibnmadjiehjhajb || Yoroi
afbcbjpbpfadlkmhmclhkeeodmamcflc || Math
hpglfhgfnhbgpjdenjgmdgoeiappafln || Guarda
kncchdigobghenbbaddojjnnaogfppfj || iWallet
amkmjjmmflddogmhpjloimipbofnfjih || Wombat
nlbmnnijcnlegkjjpcfjclmcfggfefdm || MEWCX
nknhiehlklippafakaeklbeglecifhad || NaboxWallet
jnmbobjmhlngoefaiojfljckilhhlhcj || OneKey
pdadjkfkgcafgbceimcpbkalnfnepbnk || KardiaChainWallet
```

### setup_utils_AntiCIS Function

In the `main` function screenshot, we see that the first call made by the malware is to `setup_utils_AntiCIS`. This function begins by decrypting and utilizing `user32.dll` and `GetKeyboardLayoutList`. It then invokes `GetKeyboardLayoutList` and compares the obtained keyboard layouts with a preset list. From its name and behavior, it's clear that this function is designed to check for keyboard layouts typical of the `CIS region countries`, and if a match is detected, the malware promptly exits without executing further.

![Untitled](assets/img/hornet/10.png)

Interestingly, one of the hex values, `443h`, does not have a corresponding keyboard identifier in Microsoft's official documentation on [Windows keyboard layouts](https://learn.microsoft.com/en-us/globalization/windows-keyboard-layouts).

The `AntiCIS` function uniquely targets devices based on their geographic location, specifically halting execution on those with CIS region keyboard layouts. This is a common tactic in malware, typically to avoid affecting systems in the developers' own region, possibly due to legal or ethical considerations.

### setup_utils_Connection Function

The `setup_utils_Connection` function straightforwardly initiates a `TCP` connection between the C2 server (***185.221.198.118:8080***) and the infected device. Should it fail to establish this connection to the C2 address, the function will terminate the process.

![Untitled](assets/img/hornet/11.png)

Once this connection is successfully established, the malware initiates its data collection process.

### main_launchUserInfo Function

The `main_launchUserInfo` function initially creates a folder named `\logs\MainFolderLog`, then proceeds to gather various system details like `CPU`, `GPU`, `RAM`, `OS`, `TimeZone`, `Language`, and `Architecture`, storing this information in `\logs\MainFolderLog\UserInformation.txt`. It also compiles a list of `installed applications`, saving it in `\logs\MainFolderLog\InstalledSoftware.txt`' Finally, it encrypts this data with AES GCM and transmits it to the C2 server. The specifics of C2 traffic encryption will be addressed later in our analysis.

![Untitled](assets/img/hornet/12.png)

Data format;

```
Tags: %s
BuildId: %s
UserName: %s
CPU: %s
GPU: %s
RAM: %s
OS: %s
Current date: %s
TimeZone: %s
Language: %s
Architecture: %s
Screen: %s
HWID: %s
```

### main_launchDesktopwallet Function

The `main_launchDesktopwallet` function scans for the decrypted wallet folder names within the `\AppData\Roaming` directory. Upon finding a match, it encrypts the relevant data and transmits it to the C2 server.

![Untitled](assets/img/hornet/13.png)

Wallet list;

```
Exodus || exodus || Partitions || cache || dictionar
Atomic || atomic || cache || IndexedDB
JaxxLiberty || com.liberty.jaxx || cache
Coinomi || Coinomi\Coinomi\wallets || null-
Electrum || Electrum\wallets || null-
Electrum-LTC || Electrum-LTC\wallets || null-
ElectronCash || ElectronCash\wallets || null-
Guarda || Guarda || cache || IndexedDB
MyMonero || MyMonero || cache
Monero || Monero\\wallets || null-
Wasabi || WalletWasabi\\Client || tor || log
TokenPocket || TokenPocket || cache
Ledger Live || Ledger Live || cache || dictionar || sqlite
Binance || Binance || cache || null-
```

### main_launchwallet Function

Functioning in a recursive manner, `main_launchwallet` explores both the `\AppData\Roaming` and `\AppData\Local` directories, targeting the previously decrypted names of wallet browser extensions located in the various browsers' `Extensions` folders.

![Untitled](assets/img/hornet/14.png)

Wallet Extension List;

```
fhbohimaelbohpjbbldcngcnapndodjp || BinanceChain
fnjhmkhhmkbjkkabndcnnogagogbneec || Ronin
kjmoohlgokccodicjjfebfomlbljgfhk || Ronin
nkbihfbeogaeaoehlefnkodbefgpgknn || MetaMask
ejbalbakoplchlghecdalmeeeajnimhm || MetaMask
ibnejdfjmmkpcnlpebklmnkoeoihofec || TronLink
egjidjbpglichdcondbcbdnbeeppgdph || TrustWallet
bfnaelmomeimhlpmgjnjophhpkkoljpa || Phantom
hnfanknocfeofbddgcijnmhnfnkdnaad || Coinbase
odbfpeeihdkbihmopkbjmoonfanlbfcl || Brave
cgeeodpfagjceefieflmdfphplkenlfk || TON
aeachknmefphepccionboohckonoeemg || Coin98
mcohilncbfahbmgdjkbpemcciiolgcge || MetaX
hmeobnfnfcmdkdcmlblgagmfpfboieaf || XDEFI
lpilbniiabackdjcionkobglmddfbcjo || WavesKeeper
bhhhlbepdkbapadjdnnojkbgioiodbic || Solflare
acmacodkjbdgmoleebolmdjonilkdbch || Rabby
dkdedlpgdmmkkfjabffeganieamfklkm || CyanoWallet
cnmamaachppnkjgnildpdmkaakejnhae || AuroWallet
hcflpincpppdclinealmandijcmnkbgn || KHC
mnfifefkajgofkcjkemidiaecocnkjeh || TezBox
ookjlbkiijinhpmnjffcofjonbfbgaoc || Temple
flpiciilemghbmfalicajoolhkkenfel || ICONex
fhmfendgdocmcbmfikdcogofphimnkno || Sollet
nhnkbkgjikgcigadomkphalanndcapjk || CloverWallet
jojhfeoedkpkglbfimdfabpdfjaoolaf || PolymeshWallet
cphhlgmgameodnhkjdmkpanlelnlohao || NeoLine
dmkamcknogkgcdfhhbddcghachkejeap || Keplr
ajkhoeiiokighlmdnlakpjfoobnjinie || TerraStation
aiifbnbfobpmeekipheeijimdpnlpgpp || TerraStation
kpfopkelmapcoipemfendmdcghnegimn || Liquality
nkddgncdjgjfcddamfgcmfnlhccnimig || SaturnWallet
nanjmdknhkinifnkgdcggcfnhdaammmj || GuildWallet
jnkelfanjkeadonecabehalmbgpfodjm || Goby
nphplpgoakhhjchkkhmiggakijnkhfnd || TON
fpkhgmpbidmiogeglndfbkegfdlnajnf || Cosmostation
jiidiaalihmmhddjgbnbgdfflelocpak || BitKeep
pgiaagfkgcbnmiiolekcfmljdagdhlcm || Stargazer
cjelfplplebdjjenllpjcblmjkfcffne || JaxxLiberty
kkpllkodjeloidieedojogacfhpaihoh || Enkrypt
pkkjjapmlcncipeecdmlhaipahfdphkd || GameStopWallet
aholpfdialjgjfhomihkjbmgjidlcdno || ExodusWeb3Wallet
nngceckbapebfimnlniiiahkandclblb || Bitwarden
efbglgofoippbgcjepnhiblaibcnclgk || MartianAptos
jnlgamecbpmbajjfhmmmlhejkemejdma || Braavos
mcohilncbfahbmgdjkbpemcciiolgcge || OKX
phkbamefinggmakgklpkljjmgibohnba || PontemAptos
epapihdplajcdnnkdeiahlgigofloibg || SenderWallet
gjagmgiddbbciopjhllkdnddhcglnemk || Hashpack
cgeeodpfagjceefieflmdfphplkenlfk || EVER
cjmkndjhnagcfbpiemnkdpomccnjblmj || Finnie
aijcbedoijmgnlmjeegjaglmepbmpkpi || LeapTerra
ejjladinnckdgjemekebdpeokbikhfci || PetraAptos
kmhcihpebfmpgmihbkipmjlmmioameka || Eternl
bgpipimickeadkjlklgciifhnalhdjhe || GeroWallet
lpfcbjknijpeeillifnkikgncikgfhdo || NamiWallet
pocmplpaccanhmnllbbkpgfliimjljgo || SlopeWallet
ffnbelfdoeiohenkjibnmadjiehjhajb || Yoroi
afbcbjpbpfadlkmhmclhkeeodmamcflc || Math
hpglfhgfnhbgpjdenjgmdgoeiappafln || Guarda
kncchdigobghenbbaddojjnnaogfppfj || iWallet
amkmjjmmflddogmhpjloimipbofnfjih || Wombat
nlbmnnijcnlegkjjpcfjclmcfggfefdm || MEWCX
nknhiehlklippafakaeklbeglecifhad || NaboxWallet
jnmbobjmhlngoefaiojfljckilhhlhcj || OneKey
pdadjkfkgcafgbceimcpbkalnfnepbnk || KardiaChainWallet
```

### main_launchBrowser Function

Serving as a typical stealer function, `main_launchBrowser` is dedicated to harvesting browser data, including `login details` and `cookies`. After gathering this data, the function encrypts it and then sends it off to the C2.

![Untitled](assets/img/hornet/15.png)

### main_launchTelegram Function

The `main_launchTelegram` function targets the `\AppData\Roaming\Telegram Desktop\tdata` directory, extracting critical files such as `key_data` and `usertag`. Following the theft, it encrypts this data and dispatches it to the C2 server.

![Untitled](assets/img/hornet/16.png)

### main_launchSteam Function

The `main_launchSteam` function is designed to gather data from the `Steam` desktop application, including `auto-login` information, `game lists`, and `statuses`. This stolen data is compiled into `SteamInfo.txt`, encrypted, and then transmitted to the C2 server.

![Untitled](assets/img/hornet/17.png)

### main_launchScreenshot Function

As its name suggests, the `main_launchScreenshot` function captures screenshots of the current windows, saving them with the naming format `ScreenShot (%d_%dx%d).png`. After saving, it encrypts these screenshots and transmits them to the C2 server.

![Untitled](assets/img/hornet/18.png)

### main_launchDiscord Function

The `main_launchDiscord` function searches through the `\AppData\Local` and `\AppData\Roaming` directories to locate leveldb files associated with the Discord Desktop app. After collecting this data, it compiles it into 'Tokens.txt', encrypts the file, and sends it to the C2 server.

![Untitled](assets/img/hornet/19.png)

### setup_utils_Send Function

The `setup_utils_Send` function initially stores the stolen data files in the `\logs` folder. It then decrypts a string for use in the traffic encryption routine, generates a nonce for `AES GCM` encryption, and calculates the `MD5` of previously decrypted string to serve as the `AES GCM` encryption key. Finally, it encrypts the data and transmits it to the C2 server.

Decrypted string;

![Untitled](assets/img/hornet/20.png)

Calculating MD5 and starts AES GCM;

![Untitled](assets/img/hornet/21.png)

The encrypted traffic can be decrypted using Python, as demonstrated by the following code snippet.

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from binascii import unhexlify

def decrypt(cipher_hex, key):
    cipher_bytes = unhexlify(cipher_hex)

    nonce_size = 12
    tag_size = 16
    nonce = cipher_bytes[:nonce_size]
    tag = cipher_bytes[-tag_size:]
    cipher_text = cipher_bytes[nonce_size:-tag_size]

    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag),
        backend=default_backend()
    ).decryptor()

    return decryptor.update(cipher_text) + decryptor.finalize()

key = b'7b1da832deb12b2dd4065c7c43aec101'
encrypted_hex = ''
decrypted_text = decrypt(encrypted_hex, key)
print("Decrypted text:", decrypted_text)
```

To maintain the confidentiality of my VM's specifics, I've truncated and randomized the decrypted data, but the representation below illustrates how it appears.

```
Decrypted text: b'G\xff\x81\x03\x01\x01\x07FileObj\x01\xff\x82\x00\x01\x04\x01\x08FileName\x01\x0c\x00\x01\x08IsFolder\x01\x02\x00\x01\x08FileByte\x01\n\x00\x01\x05Files\x01\xff\x84\x00\x00\x00\x1e\xff\x83\x02\x01\x01\x0f[]utils.FileObj\x01\xff\x84\x00\x01\xff\x82\x00\x00\xfe\x07\xdc\xff\x82\x01\rMainFolderLog\x01\x01\x02\x02\x01\x13UserInformation.txt\x02\xfe\x01NTags: Installs\nBuildId: Installs\nUserName: WIN10\\admin\nCPU: 14th Gen Intel(R) Core(TM) i15-15200 (1 cores)\nGPU: VMware SVGA 3D\nRAM: 8190 MB\nOS: Microsoft Windows 10 Enterprise\nCurrent date: 2099.08.29 00:05:04\nTimeZone: UTC +2 Hours\nLanguage: en-US\nArchitecture: x64-based PC\nScreen: 3238 x 1274\nHWID: 3782542AB18F411BC42897C0D3D0FB3E\n\n\x00\x01\x15InstalledSoftware.txt\x02\xfe\x06B%!(EXTRA string=\t7-Zip 18.01 (x64)\n\tExplorer Suite IV\n\tHxD Hex Editor 2.5\n\tIDA Freeware 8.3\n\t\n)\x00\x00'
```

The presence of non-ASCII characters in the decrypted data suggests the possibility of serialized object usage.

# Part 3 - C2 Panel

While all traffic between the malware and the C2 server is encrypted and sent via `TCP` to the server's port `8080`, [@spamhaus](https://twitter.com/spamhaus/status/1750170178493526350)'s tweet also indicates the existence of an HTTP web application used for the C2 panel.

![Untitled](assets/img/hornet/22.png)

As of the time of writing this article, the C2 server shared by [@spamhaus](https://twitter.com/spamhaus/status/1750170178493526350) is currently inaccessible.

Guided by [@spamhaus](https://twitter.com/spamhaus/status/1750170178493526350)'s tweet, which identifies the malware as `Hornet Stealer` based on the `panel logo` and `name`, we can conduct targeted Censys searches using queries like;

```
services.http.response.body:"Welcome back!" AND services.http.response.body:"Happy to see you again!" AND services.http.response.body:"Username" AND services.http.response.body:"Password" AND services.port:8080

services.http.response.body:"Hornet Stealer"

services.http.response.body:"Hornet" AND services.http.response.body:"Stealer"
```

However, none of these queries succeeded in finding a new C2 address.

# Part 4 - Yara Rule and String Extractor

## Yara Rule

In the Yara Rule section of our article, considering the encryption of most strings, we will concentrate on certain key aspects and plaintext strings for crafting our Yara rule. This includes focusing on encryption methods utilized by the malware, such as `Fernet` and `AES-GCM`, as well as unique user code function names.

```php
rule HornetStealer_Golang {
	meta:
		author = "tufan - @tufan_gngr"
		description = "Detects Hornet stealer non-stripped samples"
		date = "2024-01-30"
		references = "https://tufan-gungor.github.io/"
		references = "https://twitter.com/spamhaus/status/1750170178493526350"
		hash = "bc3ee10c21cb07bc0dd6b84a6eaf8efbd0af889467ab7ef647acf60f8c188e83"
	strings:
		$s1 = "main"
		$s2 = "setup/utils"
		$s3 = "crypto/cipher.NewGCM"
		$s4 = "fernet"

		$a1 = "launchBrowser"
		$a2 = "launchDesktopWallet"
		$a3 = "launchDiscord"
		$a4 = "launchSteam"
		$a5 = "launchTelegram"
		$a6 = "launchWallet"
		$a7 = "launchUserInfo"
	condition:
		uint16(0) == 0x5a4d and 
		(5 of ($a*)) or
		(#s1 > 10 and #s2 > 20 and $s3 and $s4)
}
```

The Yara searches conducted on `Unpacme` and `VirusTotal` did not yield any new samples, only returning the one we already possess.

In addition to our Yara rule, other string searches, as listed below, also failed to yield any results.

```php
C:/Users/admin/Desktop/GOAdmin
main.launchDesktopwallet
setup/utils.Send
```

## String Extractor / Decryptor

In the String Extractor/Decryptor segment, we now focus on developing a Python decryptor for the malware's encrypted strings, given that we have the necessary tools at hand. A notable difficulty, however, lies in the Golang structure, where the lack of `null bytes` between strings complicates their extraction without causing breaks.

Consequently, we will employ Mandiant's tool known as [FLOSS (FLARE Obfuscated String Solver)](https://github.com/mandiant/flare-floss) for extracting strings from the Golang binary. As of December 12, 2023, FLOSS has included support for Golang string extraction.

Our first step is to execute `FLOSS` on the `Hornet Stealer`, and then we will capture and store the resulting output in an `output.txt` file.”

```powershell
.\floss.exe .\hornet.exe > output.txt
```

Subsequently, our string decryptor will process each line from the `output.txt` file, decrypting them with the `Fernet` key. Successful decryptions will result in the decrypted text being printed.

Here is our Python code;

```python
from cryptography.fernet import Fernet

def decrypt_line(line, key):
    fernet = Fernet(key)
    try:
        decrypted_data = fernet.decrypt(line.encode())
        return decrypted_data.decode()
    except Exception as e:
        return None

def decrypt_file(filename, key):
    with open(filename, 'r', errors='ignore') as file:
        for line in file:
            line = line.strip()
            if line and len(line) > 10:
                decrypted_data = decrypt_line(line, key)
                if decrypted_data:
                    print("Decrypted Data:", decrypted_data)

if __name__ == "__main__":
    filename = 'output.txt'
    key = 'MpQzH0ne3b-TkBgkJ0tbdALxiCiJuLBleGUlEoIGQoo='
    decrypt_file(filename, key)
```

Output:

```
Decrypted Data: Tags: %s
BuildId: %s
UserName: %s
CPU: %s
GPU: %s
RAM: %s
OS: %s
Current date: %s
TimeZone: %s
Language: %s
Architecture: %s
Screen: %s
HWID: %s

Decrypted Data: user32.dll
Decrypted Data: usertag
Decrypted Data: False
Decrypted Data: Tokens.txt
Decrypted Data: LocalFree
Decrypted Data: Kernel32.dll
Decrypted Data: Language
Decrypted Data: SteamInfo.txt
Decrypted Data: leveldb
Decrypted Data: Wallet
Decrypted Data: Login Data
Decrypted Data: MainFolderLog
Decrypted Data: key_data
Decrypted Data: .ldb
Decrypted Data: DisplayName
Decrypted Data: Web Data
Decrypted Data: vdf
Decrypted Data: False
Decrypted Data: cookies.sqlite
Decrypted Data: Telegram
Decrypted Data: Installs
Decrypted Data: Desktop Wallets
Decrypted Data: Running
Decrypted Data: Installs
Decrypted Data: logins.json
Decrypted Data: ssfn
Decrypted Data: Installed
Decrypted Data: .log
Decrypted Data: Local State
Decrypted Data: Updating
Decrypted Data: SteamPath
Decrypted Data: AutoLoginUser
Decrypted Data: tdata
Decrypted Data: False
Decrypted Data: Crypt32.dll
Decrypted Data: settings
Decrypted Data: Extensions
Decrypted Data: UserInformation.txt
Decrypted Data: GetKeyboardLayoutList
Decrypted Data: InstalledSoftware.txt
Decrypted Data: CryptUnprotectData
Decrypted Data: Software\\Valve\\Steam
Decrypted Data: discord\\Local Storage\\leveldb
Decrypted Data: os_crypt.encrypted_key
Decrypted Data: Software\\Valve\\Steam\\Apps\\
Decrypted Data: AutoLogin: %s\nLanguage: %s\n\n
Decrypted Data: 185.221.198.118:8080
Decrypted Data: Software\\Valve\\Steam\\Apps
Decrypted Data: JAGSDiusuidsgdisbdhb32te72hqbsilydfg1
Decrypted Data: discordptb\\Local Storage\\leveldb
Decrypted Data: discordcanary\\Local Storage\\leveldb
Decrypted Data: [\w-]{24}\.[\w-]{6}\.[\w-]{25,110}
Decrypted Data: 5hKEw9TAVDZPA6CblkDK86Dhd9HF1E5B
Decrypted Data: SELECT ExecutablePath FROM Win32_Process WHERE Name =
Decrypted Data: SELECT Caption, MUILanguages FROM win32_operatingsystem
Decrypted Data: SELECT Name, NumberOfCores, ProcessorId FROM Win32_Processor
Decrypted Data: SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall
Decrypted Data: SELECT VolumeSerialNumber FROM Win32_LogicalDisk WHERE DeviceID =
Decrypted Data: Select Model, SystemType, TotalPhysicalMemory, CurrentTimeZone From Win32_ComputerSystem
Decrypted Data: SELECT Name, CurrentHorizontalResolution, CurrentVerticalResolution  FROM Win32_VideoController
Decrypted Data: Application %s\n\tGameID: %s\n\tInstalled: %s\n\tRunning: %s\n\tUpdating: %s\n\n
Decrypted Data: Telegram Desktop
Decrypted Data: Tags: %s
BuildId: %s
UserName: %s
CPU: %s
GPU: %s
RAM: %s
OS: %s
Current date: %s
TimeZone: %s
Language: %s
Architecture: %s
Screen: %s
HWID: %s

Decrypted Data: Exodus || exodus || Partitions || cache || dictionar
Atomic || atomic || cache || IndexedDB
JaxxLiberty || com.liberty.jaxx || cache
Coinomi || Coinomi\Coinomi\wallets || null-
Electrum || Electrum\wallets || null-
Electrum-LTC || Electrum-LTC\wallets || null-
ElectronCash || ElectronCash\wallets || null-
Guarda || Guarda || cache || IndexedDB
MyMonero || MyMonero || cache
Monero || Monero\\wallets || null-
Wasabi || WalletWasabi\\Client || tor || log
TokenPocket || TokenPocket || cache
Ledger Live || Ledger Live || cache || dictionar || sqlite
Binance || Binance || cache || null-
Decrypted Data: fhbohimaelbohpjbbldcngcnapndodjp || BinanceChain
fnjhmkhhmkbjkkabndcnnogagogbneec || Ronin
kjmoohlgokccodicjjfebfomlbljgfhk || Ronin
nkbihfbeogaeaoehlefnkodbefgpgknn || MetaMask
ejbalbakoplchlghecdalmeeeajnimhm || MetaMask
ibnejdfjmmkpcnlpebklmnkoeoihofec || TronLink
egjidjbpglichdcondbcbdnbeeppgdph || TrustWallet
bfnaelmomeimhlpmgjnjophhpkkoljpa || Phantom
hnfanknocfeofbddgcijnmhnfnkdnaad || Coinbase
odbfpeeihdkbihmopkbjmoonfanlbfcl || Brave
cgeeodpfagjceefieflmdfphplkenlfk || TON
aeachknmefphepccionboohckonoeemg || Coin98
mcohilncbfahbmgdjkbpemcciiolgcge || MetaX
hmeobnfnfcmdkdcmlblgagmfpfboieaf || XDEFI
lpilbniiabackdjcionkobglmddfbcjo || WavesKeeper
bhhhlbepdkbapadjdnnojkbgioiodbic || Solflare
acmacodkjbdgmoleebolmdjonilkdbch || Rabby
dkdedlpgdmmkkfjabffeganieamfklkm || CyanoWallet
cnmamaachppnkjgnildpdmkaakejnhae || AuroWallet
hcflpincpppdclinealmandijcmnkbgn || KHC
mnfifefkajgofkcjkemidiaecocnkjeh || TezBox
ookjlbkiijinhpmnjffcofjonbfbgaoc || Temple
flpiciilemghbmfalicajoolhkkenfel || ICONex
fhmfendgdocmcbmfikdcogofphimnkno || Sollet
nhnkbkgjikgcigadomkphalanndcapjk || CloverWallet
jojhfeoedkpkglbfimdfabpdfjaoolaf || PolymeshWallet
cphhlgmgameodnhkjdmkpanlelnlohao || NeoLine
dmkamcknogkgcdfhhbddcghachkejeap || Keplr
ajkhoeiiokighlmdnlakpjfoobnjinie || TerraStation
aiifbnbfobpmeekipheeijimdpnlpgpp || TerraStation
kpfopkelmapcoipemfendmdcghnegimn || Liquality
nkddgncdjgjfcddamfgcmfnlhccnimig || SaturnWallet
nanjmdknhkinifnkgdcggcfnhdaammmj || GuildWallet
jnkelfanjkeadonecabehalmbgpfodjm || Goby
nphplpgoakhhjchkkhmiggakijnkhfnd || TON
fpkhgmpbidmiogeglndfbkegfdlnajnf || Cosmostation
jiidiaalihmmhddjgbnbgdfflelocpak || BitKeep
pgiaagfkgcbnmiiolekcfmljdagdhlcm || Stargazer
cjelfplplebdjjenllpjcblmjkfcffne || JaxxLiberty
kkpllkodjeloidieedojogacfhpaihoh || Enkrypt
pkkjjapmlcncipeecdmlhaipahfdphkd || GameStopWallet
aholpfdialjgjfhomihkjbmgjidlcdno || ExodusWeb3Wallet
nngceckbapebfimnlniiiahkandclblb || Bitwarden
efbglgofoippbgcjepnhiblaibcnclgk || MartianAptos
jnlgamecbpmbajjfhmmmlhejkemejdma || Braavos
mcohilncbfahbmgdjkbpemcciiolgcge || OKX
phkbamefinggmakgklpkljjmgibohnba || PontemAptos
epapihdplajcdnnkdeiahlgigofloibg || SenderWallet
gjagmgiddbbciopjhllkdnddhcglnemk || Hashpack
cgeeodpfagjceefieflmdfphplkenlfk || EVER
cjmkndjhnagcfbpiemnkdpomccnjblmj || Finnie
aijcbedoijmgnlmjeegjaglmepbmpkpi || LeapTerra
ejjladinnckdgjemekebdpeokbikhfci || PetraAptos
kmhcihpebfmpgmihbkipmjlmmioameka || Eternl
bgpipimickeadkjlklgciifhnalhdjhe || GeroWallet
lpfcbjknijpeeillifnkikgncikgfhdo || NamiWallet
pocmplpaccanhmnllbbkpgfliimjljgo || SlopeWallet
ffnbelfdoeiohenkjibnmadjiehjhajb || Yoroi
afbcbjpbpfadlkmhmclhkeeodmamcflc || Math
hpglfhgfnhbgpjdenjgmdgoeiappafln || Guarda
kncchdigobghenbbaddojjnnaogfppfj || iWallet
amkmjjmmflddogmhpjloimipbofnfjih || Wombat
nlbmnnijcnlegkjjpcfjclmcfggfefdm || MEWCX
nknhiehlklippafakaeklbeglecifhad || NaboxWallet
jnmbobjmhlngoefaiojfljckilhhlhcj || OneKey
pdadjkfkgcafgbceimcpbkalnfnepbnk || KardiaChainWallet
```

# Part 5 - IOCs

```
bc3ee10c21cb07bc0dd6b84a6eaf8efbd0af889467ab7ef647acf60f8c188e83
185.221.198.118:8080
```

# References

- [https://twitter.com/spamhaus/status/1750170178493526350](https://twitter.com/spamhaus/status/1750170178493526350)
- [https://github.com/mandiant/flare-floss](https://github.com/mandiant/flare-floss)

**I utilized AI assistance to fine-tune certain sentences in this post, enhancing clarity and precision.**