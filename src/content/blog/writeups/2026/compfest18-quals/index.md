---
title: "Compfest 18 Quals"
description: "Write ups from the challenge that I solved alongside with collaboration of my team HiB - ANTECH ANTECH ASYNC in Qualifications of Compfest 18"
pubDate: "2026-08-29"
heroImage: "./assets/hero.webp"
---

Complete write-ups of challenge that I solved in Compfest 18 Qualification held by University of Indonesia.


## Forensic
### save the water (491 pts) — First Blood

#### Description

My AI agent is running slowly; it keeps loading and never finishes.

The challenge attachment contains active malware. The organizers require analysis in an isolated environment.

Connection: `nc 34.1.203.129 7000`

The challenge provided a PCAP and a sequence of questions.

What is the IP Address of the victim?
 Format: IPAddress

I opened the capture in Wireshark and identified the victim’s IP address.

![save the water (491 pts) — First Blood — investigation evidence](./assets/wu-11-image1.png)

What is the complete versioning artifact exposed by the initiator during the very first phase of the session?
Format: X.X.XXXXX.XXXX

Following the first TCP stream exposed the PowerShell version used by the attacker.

![save the water (491 pts) — First Blood — investigation evidence](./assets/wu-11-image8.png)

What are the first 4 bytes (magic bytes) in hexadecimal format sent to authenticate the connection?
Format: xx-xx-xx-xx

I initially was not sure which bytes the question meant. Before stream 1, I found an `AUTH_SUCCESS` marker beside bytes that were not readable as UTF-8. Switching to the raw view revealed `deadbeef`. Submitting `de-ad-be-ef` was accepted.

![save the water (491 pts) — First Blood — investigation evidence](./assets/wu-11-image14.png)

What is the 32-bit synchronization source identifier tracking the heavy multimedia datagram stream?
Format: decimal digits

GPT suggested looking for the SSRC of an RTP stream. Wireshark had not identified RTP automatically, so I looked for the largest UDP flow. It pointed to destination port 1234.

```text
$ tshark -r public.pcap -Y udp \
  -T fields -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -e udp.length |
awk '{bytes[$1 ":" $2 " -> " $3 ":" $4]+=$5} END {for (x in bytes) print bytes[x], x}' |
sort -nr | head
2003020 192.168.100.20:44407 -> 192.168.100.10:1234
20780 192.168.100.10,192.168.100.20:44407 -> 192.168.100.20,192.168.100.10:1234
627 192.168.100.10:138 -> 192.168.100.255:138
252 192.168.100.20:44408 -> 192.168.100.10:1235
36 192.168.100.10,192.168.100.20:44408 -> 192.168.100.20,192.168.100.10:1235
```

I decoded that traffic as RTP and converted its SSRC to decimal.

```text
$ tshark -r public.pcap \
  -d udp.port==1234,rtp \
  -Y rtp \
  -T fields \
  -e frame.number \
  -e ip.src \
  -e udp.srcport \
  -e rtp.ssrc
8791    192.168.100.20  44407   0x82e7d63a
8792    192.168.100.20  44407   0x82e7d63a
…
$ printf '%d\n' $((16#82e7d63a))
2196231738
```

The attacker hid a secret string without inserting it into the data payload. What is the secret string?
Format: 34 character string

Before the questions were released, I had already investigated ICMP traffic containing an exfiltrated minidump and decrypted the `.enc` file. Returning to the ICMP traffic for this question, I found `BEACON` and `END_BEACON` markers after the `EXFIL` packets. With GPT’s help, I identified a timing channel in the intervals between beacon packets and used the following script to recover the string.

```python
import subprocess

cmd = [
    "tshark", "-r", "public.pcap",
    "-Y", 'icmp && ip.src==192.168.100.20 && frame contains "BEACON"',
    "-T", "fields", "-e", "frame.time_epoch"
]

p = subprocess.check_output(cmd, text=True)
t = [float(x) for x in p.splitlines() if x.strip()]

gaps = [b-a for a,b in zip(t,t[1:])]

# ~1 sec => 0, ~2 sec => 1
bits = ''.join('1' if g > 1.5 else '0' for g in gaps)

print("beacons :", len(t))
print("bits    :", len(bits))
print("bits    :", bits)

# byte decode
data = bytes(
    int(bits[i:i+8], 2)
    for i in range(0, len(bits)-7, 8)
)

print("bytes   :", data)
try:
    print("text    :", data.decode())
except UnicodeDecodeError:
    print("hex     :", data.hex())


$ python3 5.py
beacons : 281
bits    : 280
bits    : 0110010000110000011011100111010001011111011100100111010101001110010111110111010001101000001100110101111101101101001101000110110001110111001101000111001000110011010111110111100100110100011010000110100001011111001110000011001000110001001100010011011101100011011000010110000100110101
bytes   : b'd0nt_ruN_th3_m4lw4r3_y4hh_82117caa5'
text    : d0nt_ruN_th3_m4lw4r3_y4hh_82117caa5
# take only the 34 bytes
```

That was a password snippet for private.676767. Append '512de1cc679e2acb37092e10a6111c22' to the end of that string. what is the MD5 checksum of the reconstructed massive payload fragmented across thet traffic?
Format: MD5

To reconstruct the minidump, I used the `EXFIL` marker to identify the relevant ICMP payloads. GPT helped write the extraction script below.

```text
from scapy.all import rdpcap, ICMP

pcap = rdpcap("challenge.pcap")

chunks = []

for pkt in pcap:
    if not pkt.haslayer(ICMP):
        continue

    icmp = pkt[ICMP]

    # Only Echo Request
    if icmp.type != 8:
        continue

    payload = bytes(icmp.payload)

    if not payload.startswith(b"EXFIL"):
        continue

    seq = icmp.seq

    # Remove the custom EXFIL marker
    data = payload[5:]

    chunks.append((seq, data))

print(f"[+] Found {len(chunks)} EXFIL packets")

chunks.sort(key=lambda x: x[0])

# Check sequence continuity
seqs = [x[0] for x in chunks]

for a, b in zip(seqs, seqs[1:]):
    if b != a + 1:
        print(f"[!] Sequence gap: {a} -> {b}")

with open("dump.dmp", "wb") as f:
    for seq, data in chunks:
        f.write(data)

print("[+] Written dump.dmp")

$ python3 e.py
[+] Found 32221 EXFIL packets
[+] Written dump.mdmp

$ md5sum dump.mdmp
c61e123e24a6025bc1aac86391385070  dump.mdmp
```

What is the string of the AES Key left in the memory?
Format: AES Key_IV

I recovered a candidate AES key with `bulk_extractor` and decoded the bytes in its AES-key output as ASCII. Searching the dump for nearby IV data did not help. I then looked for similar byte-string values in the `strings` output and found `y0u_g0t_tr4pp3d!`, which the challenge accepted as the IV.

```text
# BANNER FILE NOT PROVIDED (-b option)
# BULK_EXTRACTOR-Version: 2.1.1
# Feature-Recorder: aes_keys
# Filename: dump.mdmp
# Feature-File-Version: 1.1
1077858    62 64 37 62 66 37 38 38 64 36 32 62 64 65 63 39 63 32 31 39 33 31 36 64 61 34 34 38 37 33 31 34    AES256

$ printf '\x62\x64\x37\x62\x66\x37\x38\x38\x64\x36\x32\x62\x64\x65\x63\x39\x63\x32\x31\x39\x33\x31\x39\x33\x31\x36\x64\x61\x34\x34\x38\x37\x33\x31\x34'
bd7bf788d62bdec9c219319316da4487314
```

![save the water (491 pts) — First Blood — investigation evidence](./assets/wu-11-image13.png)

What is the multi-digit authorization code revealed on the evidence?
Format: decimal digit

The HTTP traffic contained `video.enc`. I exported it and used the recovered key and IV to attempt AES-CBC decryption with the script below.

![save the water (491 pts) — First Blood — investigation evidence](./assets/wu-11-image11.png)

```text
from Crypto.Cipher import AES

key = b"bd7bf788d62bdec9c219316da4487314"
iv = b"y0u_g0t_tr4pp3d!"

data = open("video.enc", "rb").read()
pt = AES.new(key, AES.MODE_CBC, iv).decrypt(data)

open("f.dec", "wb").write(pt)


$ python3 d.py

$ file f.dec
f.dec: Zip archive data, at least v2.0 to extract, compression method=deflate

$ unzip -x f.dec
Archive:  f.dec
  inflating: video.mp4
```

The decrypted file was a ZIP archive. I extracted it and watched the MP4 to recover the authorization code.

![save the water (491 pts) — First Blood — investigation evidence](./assets/wu-11-image4.png)

What is the SHA256 hash value of the malware?
Format: SHA256

I initially overlooked the earlier question’s password instructions and spent time searching for the password to `private.676767`. The required value was `d0nt_ruN_th3_m4lw4r3_y4hh_82117caa512de1cc679e2acb37092e10a6111c22`. Extracting it produced another encrypted archive, whose password was the number shown in the video.

```text
$ 7z x private.676767

7-Zip 26.00 (x64) : Copyright (c) 1999-2026 Igor Pavlov : 2026-02-12
 64-bit locale=en_US.UTF-8 Threads:16 OPEN_MAX:10240, ASM

Scanning the drive for archives:
1 file, 76424168 bytes (73 MiB)

Extracting archive: private.676767
--
Path = private.676767
Type = zip
Physical Size = 76424168


Enter password (will not be echoed):
Everything is Ok

Size:       75400304
Compressed: 76424168

$ 7z x fastAI.zip

7-Zip 26.00 (x64) : Copyright (c) 1999-2026 Igor Pavlov : 2026-02-12
 64-bit locale=en_US.UTF-8 Threads:16 OPEN_MAX:10240, ASM

Scanning the drive for archives:
1 file, 75400304 bytes (72 MiB)

Extracting archive: fastAI.zip
--
Path = fastAI.zip
Type = zip
Physical Size = 75400304


Enter password (will not be echoed):
Everything is Ok

Size:       74408861
Compressed: 75400304

$ sha256sum fastloader.exe
be69c8c00b73aadbb26ca44707ec1d489f891d2e848dd7e834b8f881bcdeb33d  fastloader.exe
```

What are the hexadecimal values of the starting point (Offset) and the data block length (Size) required?
Format: Offset_Size

I used GPT to help identify the PE overlay offset and size. A later hint clarified that the answer required raw hexadecimal values in the specified format.

![save the water (491 pts) — First Blood — investigation evidence](./assets/wu-11-image9.png)

What is the name of the original developer of the privilege escalation utility program smuggled inside this malware archive?
Format: FirstName_LastName

While investigating the previous question, I noticed that the executable could be extracted as an archive. It contained `app-64.7z`, which in turn contained `elevate.exe`. I inspected that executable with ExifTool to identify its developer.

```text
$ 7z x fastloader.exe -oout_exe

7-Zip 26.00 (x64) : Copyright (c) 1999-2026 Igor Pavlov : 2026-02-12
 64-bit locale=en_US.UTF-8 Threads:16 OPEN_MAX:10240, ASM

Scanning the drive for archives:
1 file, 74408861 bytes (71 MiB)

Extracting archive: fastloader.exe
--
Path = fastloader.exe
Type = Nsis
Physical Size = 74408861
Method = Deflate
Solid = -
Headers Size = 39734
Embedded Stub Size = 38400
SubType = NSIS-3 Unicode

Everything is Ok

Files: 4
Size:       74619253
Compressed: 74408861

$ cd out_exe/\$PLUGINSDIR/

$ 7z x app-64.7z -oout_app

$ tree out_app/
out_app/
├── chrome_100_percent.pak
├── chrome_200_percent.pak
├── d3dcompiler_47.dll
├── ffmpeg.dll
├── icudtl.dat
├── Installer.exe
├── libEGL.dll
├── libGLESv2.dll
├── LICENSE.electron.txt
├── LICENSES.chromium.html
├── locales
│   ├── af.pak
│   ├── am.pak
│   ├── ar.pak
│   ├── bg.pak
│   ├── bn.pak
│   ├── ca.pak
│   ├── cs.pak
│   ├── da.pak
│   ├── de.pak
│   ├── el.pak
│   ├── en-GB.pak
│   ├── en-US.pak
│   ├── es-419.pak
│   ├── es.pak
│   ├── et.pak
│   ├── fa.pak
│   ├── fil.pak
│   ├── fi.pak
│   ├── fr.pak
│   ├── gu.pak
│   ├── he.pak
│   ├── hi.pak
│   ├── hr.pak
│   ├── hu.pak
│   ├── id.pak
│   ├── it.pak
│   ├── ja.pak
│   ├── kn.pak
│   ├── ko.pak
│   ├── lt.pak
│   ├── lv.pak
│   ├── ml.pak
│   ├── mr.pak
│   ├── ms.pak
│   ├── nb.pak
│   ├── nl.pak
│   ├── pl.pak
│   ├── pt-BR.pak
│   ├── pt-PT.pak
│   ├── ro.pak
│   ├── ru.pak
│   ├── sk.pak
│   ├── sl.pak
│   ├── sr.pak
│   ├── sv.pak
│   ├── sw.pak
│   ├── ta.pak
│   ├── te.pak
│   ├── th.pak
│   ├── tr.pak
│   ├── uk.pak
│   ├── ur.pak
│   ├── vi.pak
│   ├── zh-CN.pak
│   └── zh-TW.pak
├── resources
│   ├── app
│   │   ├── main.js
│   │   ├── package.json
│   │   └── resource.dat
│   └── elevate.exe
├── resources.pak
├── snapshot_blob.bin
├── v8_context_snapshot.bin
├── vk_swiftshader.dll
├── vk_swiftshader_icd.json
└── vulkan-1.dll

4 directories, 75 files

$ cd out_app/resources/

$ exiftool elevate.exe
ExifTool Version Number         : 13.50
File Name                       : elevate.exe
Directory                       : .
File Size                       : 108 kB
File Modification Date/Time     : 2026:07:18 05:55:16+07:00
File Access Date/Time           : 2026:08:30 20:08:48+07:00
File Inode Change Date/Time     : 2026:08:30 20:07:59+07:00
File Permissions                : -rwxrwxrwx
File Type                       : Win32 EXE
File Type Extension             : exe
MIME Type                       : application/octet-stream
Machine Type                    : Intel 386 or later, and compatibles
Time Stamp                      : 2016:04:08 21:35:16+07:00
Image File Characteristics      : Executable, 32-bit
PE Type                         : PE32
Linker Version                  : 14.0
Code Size                       : 70656
Initialized Data Size           : 38912
Uninitialized Data Size         : 0
Entry Point                     : 0x1a6c
OS Version                      : 6.0
Image Version                   : 0.0
Subsystem Version               : 6.0
Subsystem                       : Windows command line
File Version Number             : 1.0.0.2894
Product Version Number          : 1.0.0.2894
File Flags Mask                 : 0x0017
File Flags                      : (none)
File OS                         : Win32
Object File Type                : Executable application
File Subtype                    : 0
Language Code                   : Neutral
Character Set                   : Unicode
Comments                        : Tool for elevating applications on the command line
Company Name                    : Johannes Passing
File Description                : Elevate
File Version                    : 1, 0, 0, 2894
Internal Name                   : Elevate
Legal Copyright                 : Copyright (C) 2007
Original File Name              : Elevate.exe
Product Name                    : Elevate Application
Product Version                 : 1, 0, 0, 2894
PDB Modify Date                 : 2016:04:08 21:35:16+07:00
PDB Age                         : 16
PDB File Name                   : C:\Dev\elevate\bin\x86\Release\Elevate.pdb
```

`s.py`

```python
from pwn import *
p = remote('34.1.203.129', 7000)
print(p.recvuntil(b'Answer: ').decode())
answers = [
    '192.168.100.10',
    '5.1.26100.8521',
    'de-ad-be-ef',
    '2196231738',
    "d0nt_ruN_th3_m4lw4r3_y4hh_82117caa",
    'c61e123e24a6025bc1aac86391385070',
    'bd7bf788d62bdec9c219316da4487314_y0u_g0t_tr4pp3d!',
    '16031115',
    'be69c8c00b73aadbb26ca44707ec1d489f891d2e848dd7e834b8f881bcdeb33d',
    '00009600_046ecd9d',
    'Johannes_Passing'
]
for answer in answers:
    p.sendline(answer.encode())
    response = p.recv().decode(errors='replace')  # <-- was .decode()
    print(response)
print(p.recvall().decode(errors='replace'))
```

#### Flag

```text
COMPFEST18{b0r05_41r_vv0y_j4n64n_p3cu7_p3cu7_41_mu1u_adfhjfdhaasda}
```

#### AI Disclosure

1. https://chatgpt.com/share/6a9242bf-114c-83ec-9bdc-f2fdd2993d21

2. https://chatgpt.com/share/6a9247b2-22c0-83ec-99ab-729f18b87074

3. https://chatgpt.com/share/6a92848a-e8a8-83ec-8a2b-e91f32e91468

4. https://chatgpt.com/share/6a924d95-d3a0-83ec-b9b9-fb754c74c3f5

5. https://chatgpt.com/share/6a929bc9-fe78-83ec-b775-d2de53ca7f7f

Despite the large set of attachments, most of my progress came from analyzing the PCAP.

![save the water (491 pts) — First Blood — investigation evidence](./assets/wu-11-image7.png)

![save the water (491 pts) — First Blood — investigation evidence](./assets/wu-11-image12.png)

### The Apex Affair (UPSOLVE)
#### Description
Northbridge Industrial Solutions is preparing a confidential acquisition when Finance Manager Edward reports that the important document on his workstation have become inaccessible. Initial findings suggest the compromise may have begun with a phishing message, but investigators have not identified which one or how it led to the attack. Analyze the provided forensic artifacts, trace the intrusion, and uncover what happened before the files were encrypted.

password:2cf4554ee26f34801adfbecc222a797e02b179f9887940e1c0343771853d263b

attachment link1 :https://drive.google.com/file//1X-VjdqFVMVZFcpWTcmwqsXL9nFHv6GKx/view?usp=sharing 

attachment alternative_link2 : https://drive.google.com/file/d/1HSJD5rGagEZ61H64r1BoO2f6FwAvYfdH/view?usp=sharing 

attachment alternative_link3 : https://drive.google.com/file/d/1cOPTbNEGWydL1gSHoxe4yJZBcC7uHhJL/view?usp=sharing 

sha256: e1815c3414234c690e5b3fa73dd4cc74c0730b7e5a675d28da198888527625e2

#### Solution
Because the chall is too insane (12 hours with all of the forensic challs is QnA) I can only upsolve this chall but still got the bounty from the probset because I'm the first one that solve it :D. I made this write up because this have interesting insights of DFIR process and so for me to not forget it hehe. Given out a .ad1 and a .dump that happens to be memory dump.

##### Phising Analysis
```bash
Question 1 / 4
Through which application did the victim receive the phishing message that initiated the compromise ?
Format: Application name (e.g., Slack, Discord)
```

First of all, I will check the AppData in the %userprofile%. Because the Chrome History result nothing to answer this question, I move to the Edge History. Upon moving, I notice that there is Olk folder inside the Microsoft/. This Olk folder is being used by New Outlook. Then, we get the answer of Q1: Outlook.

![](./assets/image.png)

```bash
Question 2 / 4
At what timestamp was the first phishing email received by the victim?
Format: YYYY-MM-DD HH:MM:SS
```

Because this is the New Outlook, it data files is store in the Olk/EBWebview then the rest is look like average chromium data. Since this is a chromium based, the data maybe stored in the IndexedDB. The .ldb files can be parsed with dfindexeddb even tho the output is error, it still parse a useful outcome (including subject, date time sent, recieved time, etc). Then we can just grep with `Subject` keyword to ReceivedOrRenewTime then change it to UTC.

```bash
$ dfindexeddb ldb -s "https_outlook.office.com_0.indexeddb.leveldb/000016.ldb" > out_16ldb.txt
```
![](image_1.png)
![](image.png)

```bash
Question 3 / 4
What was the subject of the follow-up email that delivered the malicious installer?  
Format: Email subject
```

When we greppin with `Subject` keyword, the one that appearing for the first time is a subject that tells the victim to download the latest google chrome in it. So we can decided that this is the answer of this current question.

![](image_2.png)

```bash
Question 4 / 4
At what UTC timestamp did the victim execute the malicious MSI installer?
Format: YYYY-MM-DD HH:MM:SS
```

Because ts from prefetch and mac of the .msi file in Downloads is wrong, lets move to the other artifacts. Luckily we got evtx dir within this ad1 dump. And the most interesting is there's Sysmon evtx which's usually installed separately, not built-in windows. This sysmon contain a very rich forensic information such as a deep log of windows system. Lets parse it with EvtxCmd and see it in Timeline Explorer. Next, we can just search with keyword of the msi filename and the ts is there.

![](image_3.png)

##### Malware Execution
```bash
Question 1/8
What embedded binary is referenced by the malicious custom action?
Format: Binary name 
```

Because .msi can be treated as an archive we can check it with 7z or any other archive tools. Inside of it there is 3 binary and we can try each one of it to find a correct answer.

![](image_4.png)

```bash
Question 2/8
What full command line does the DLL use to execute the dropped payload in a new process?
Submit the complete command line.
Format: executable.exe "C:\Path\filename",Export 
```

We can comeback checking the sysmon event again. With keyword `chrome` we can know the command line that has been executed.

![](image_5.png)

```bash
Question 3/8
How many additional executable binaries are deployed by the malicious DLL, and what are their full paths?
The order of the executable paths does not matter.
Format: n|fullpath1|fullpath2_..._fullpathN 
```

Payload Data6 is the parent command line of each executable info, since we know the dll we can search with that as keyword in Payload Data6. It resulting two exe, `C:\Program Files\Google\Chrome\GoogleUpdater.exe` and `C:\Program Files\Google\Chrome\software_reporter_tool.exe`.

![](image_6.png)

```bash
Question 4/8
What are the exact command lines executed by the first deployed binary to modify Microsoft Defender settings?
Submit the four complete command lines in execution order, separated by |.
Format: action1|action2|...|actionN
```

From the previous result, we can know that the GoogleUpdater.exe doing something with security settings and there is exactly four commands.

![](image_7.png)

```bash
Question 5/8
At what UTC timestamp was the malicious Chrome directory added to Microsoft Defender exclusions?
Format: YYYY-MM-DD HH:MM:SS 
```

Because all of the ts in the sysmon is incorrect, let's check Microsoft Defender evtx. With keyword `chrome` there is two result, and we got a new ts which is `2026-08-15 16:48:38`

![](image_8.png)

```bash
Question 6/8
What registry value was configured to redirect the Windows Security tray component launch?
Format: registry_path=value 
```

This freakin shits is givin me hard time, I keep searching both on the Microsoft Defender and Sysmon evtx but result nothing. After compe, I just realized that maybe we can get the answer from the binary, so I just send the binary to claude to reverse it and it actually found it :'). But, upon analyzing the next answer and checking the memdump, I can found the answer much easier by loading the memdump to MemProcFS then extract the SOFTWARE hive and load it with RegistryExplorer.

![](image_9.png)

```bash
Question 7/8
Which MITRE ATT&CK technique corresponds to the persistence mechanism used by the RAT?
Format: TXXXX.XXX   
```

Because the technique is abusing the registry launch keys so the MITRE ATT&CK will be T1547.001.

```bash
Question 8/8
At what UTC timestamp was persistence for the malicious RAT established?
Format: YYYY-MM-DD HH:MM:SS  
```

The ts appears from the sysmon after the victim downloading the malware, `2026-08-15 16:49:32`.

![](image_10.png)

##### C2 Analysis
```bash
Question 1/8
Which legitimate service is abused by the RAT for C2 communication?
Format: Service name
```

I'm too lazy rev ing this malware, so im just sending it to claude to analyze it :D. It appears that this malware is referenced using this https://github.com/MrSaighnal/GCR-Google-Calendar-RAT. Then the answer can be `Google Calendar`.

![](image_11.png)

```bash
Question 2/8
What Google Calendar ID is used by the RAT for C2 communication?
Format: Calendar ID    
```

Okay, since we havent touch the memdump yet lets analyze it. First thing first I extracting things with bulk_extractor and interestingly, it can extract some of json. From the repo before, we know that before executing the C2 it setup a credentials from a json file. Then we can just search in that json.txt with keyword `calendar` and we got the email entry which is the calendar ID.

![](image_12.png)
![](image_13.png)

```bash
Question 3/8
Which two Google Calendar event fields are used to identify the targeted victim and to store the command and execution result?
Format: field1_field2  
```

The repo said that the field that being used to store the command and the result is `summary_description`.

![](image_14.png)

```bash
Question 4/8
What was the first attacker-issued reconnaissance command executed through the RAT?
Format: command  
```

While analyzing the sysmon again, after the ts of malware execution there is cmd.exe appearing. And checking the parent command line, it indeed from `software_reporter_tool.exe`. The command in the first cmd.exe is just a default things from the repo, so the correct command is after that, which is `systeminfo`

![](image_15.png)

```bash
Question 5/8
At what UTC timestamp was the final command executed through the RAT before the current user session ended?
Format: YYYY-MM-DD HH:MM:SS
```

The first session ends at 2026-08-15 17:11:14

![](image_16.png)

```bash
Question 6/8
After the RAT resumed communication on the following day, what command did the attacker use to enumerate running processes on the compromised host?
Submit the complete command exactly as observed.
Format: command 
```

The command appears after the next day which is `"cmd.exe" /c for /f "tokens=1" %%i in ('tasklist /nh') do @echo %%i`

![](image_17.png)

```bash
Question 7/8
What encryption key was recovered from Zoom's DPAPI-protected win_osencrypt_key value?
Format: Base64-encoded key   
```

I think this is the hardest part of the challenge. Before this I know some reference how to decrypt the Zoom's win_osencrypt_key (infosecwriteups.com/decrypting-zoom-team-chat-forensic-analysis-of-encrypted-chat-databases-394d5c471e60). But, in that article it the masterkey is recovered from brute-forcing the windows password. In this challenge, the master key should be recovered from the lsass.exe process dump. Hint after hint and looked up in the google, I found a reference from this comment of linkedin post (https://www.linkedin.com/posts/diyarsaadi_memoryforensics-memprocfs-winpmem-ugcPost-7395033308662906880-NH3P/).

![](image_18.png)

Then after that I ask gpt to give me command to patch the vmm.dll. And here is the script.

```powershell
Copy-Item .\vmm.dll .\vmm_patched.dll

$path = ".\vmm_patched.dll"
$b = [System.IO.File]::ReadAllBytes($path)

$b[0x109e23] = 0xEB
$b[0x109e24] = 0x07

[System.IO.File]::WriteAllBytes($path, $b)
Copy-Item .\vmm.dll .\vmm_original.dll
Copy-Item .\vmm_patched.dll .\vmm.dll -Force
```

After that, load memdump as usual and it will give the process dump (minidump) of lsass.exe. From there we can just obtain the masterkey with pypykatz. There will be several key_guid, to find the correct key_guid just see at `C:\Users\xxx\AppData\Roaming\Microsoft\Protect\<SID>\`. The protected win_osencrypt_key value can be obtain from `C:\Users\xxx\AppData\Roaming\Zoom\data\Zoom.us.ini`, remove the ZWOSKEY marker that's the protected win_osencrypt_key.

![](image_21.png)

```bash
$ pypykatz lsa minidump minidump.dmp
```

![](image_19.png)

![](image_20.png)

Save that masterkey to a separate json file, change the protected win_os_encryptkey to hex value then decrypt it with pypykatz dpapi blob.

```bash
cat > masterkeys.json <<'EOF'
{
  "masterkeys": {
    "8f19e6c9-b1b7-471e-9df2-a6e7bfce331f": "f309c319b847106c356fee73dc684484781e0478777624938b4c3fa23aa56bfc8a6aed77fda135f805c6c1fe8d2d7cd407ac767ef5079b0c20dc7f0bba73b38f"
  },
  "backupkeys": {}
}
EOF
```

![](image_22.png)

```bash
$ pypykatz dpapi blob masterkeys.json keyblob
Error! non-hexadecimal number found in fromhex() arg at position 0
HEX: 4b45717267376b564f3178503242714a4739665a55704d7957626c5a46515775436c765a62304559497a773d
STR: 䕋牱㝧噫ㅏ偸䈲䩱㥇婦灕祍扗婬兆畗汃婶ぢ奅穉㵷
```

![](image_23.png)

```bash
What display name was stored in the victim's encrypted Zoom account profile?
Format: Display name 
```

The zoom account profile can be obtain by decrypting the zoomus.enc.db. With sqlcipher and entering the decrypted win_osencrypt_key we can explore the database.

```bash
$ sqlcipher zoomus.enc.db
SQLite version 3.51.3 2026-03-13 10:38:09 (SQLCipher 4.14.0 community)
Enter ".help" for usage hints.
sqlite> PRAGMA key = 'KEqrg7kVO1xP2BqJG9fZUpMyWblZFQWuClvZb0EYIzw=';
ok
sqlite> PRAGMA cipher_page_size = 1024;
sqlite> PRAGMA kdf_iter = 4000;
sqlite> .schema
CREATE TABLE zoom_conf_zpns_notice_image_cache (image_url text primary key,local_file_path text,uuid text);
CREATE TABLE zoom_kv (key text, value text, section text);
CREATE TABLE zoom_localDBEncryptOrDecryptKey (userId text NOT NULL, moduleId text NOT NULL,version text NOT NULL, mailAccount text DEFAULT 'not_mail' NOT NULL, PRIMARY KEY (userId, moduleId, mailAccount));
CREATE TABLE gg_user_profile_enc (email text primary key, id text, verifiedEmail integer,name text, givenName text, familyName text,picUrl text, gender text, locale text);
CREATE TABLE zoom_user_account_enc (uid text, snsType integer, uname text,zoom_uid text, account_id text, role integer,credential text, credForNOS text, tokenCreateTime integer64,expireInSeconds integer, recommendEmailSubject text, recommendEmailBody text,ggAccessToken text, ggRefreshToken text, FBAccessToken text, zoomRefreshToken text, zoomEmail text, zoomPsw text,bigPicUrl text, smallPicUrl text, localPicPath text,snsID text, userType integer, accountType integer,canUpgrade integer, ssoToken text,rcAccessToken text, rcRefreshToken text, rcPhoneNumber text, rcExt text, rcEmail text,firstName text default '', lastName text default '', reserve1 text default '', reserve2 text default '',asToken text default '',IMkmsToken text default '',IMkmsRefreshToken text default '',zoomJID text default '',pbxOptions integer64,offlineTag integer,offLineEncKey text default '',offlineEncIMKey text default '', googleRefreshTokenUrl text default '', sipIntegration text default'', survivInfo text default '');
...
sqlite> select * from zoom_user_account_enc;
ed.ward12@outlook.com|100|DMDG5OZ6ImHlrLBCNwAAEAAAAEvMoUVY9IkqeJD0pqQP2aXgVUSFafXZxIKu7sBZoLHY|||-1|||0|0|||||||DK5p1qCFJWSd6c3PUwAAGAAAAKfgTQ/uRlsllCaDHTwi4dSEIGUuGWxnAe5fHOHghk6VINTLRzZdDKY=|||||DHS5A6+Rt7kmRPj71wAAGAAAAF+XFDlh1J7e6NYUmrftORaRAZS3VflXp8zlTPN0bL4h1/HAEz7U6+U=|0|0|1|||||||DPa4KV9GCxheegOKaAAACAAAAIfR4b3egeM0GGMQgJnC0AO8V4kxiPfaWA==|DC5MMDmdZn9Bj7zKbQAACAAAAJdHxRaxW3TmPANN5Q/moGXg7PirkYsmjA==|https://us05web.zoom.us|||||DPzmHtURvVGcu7VZCgAAKAAAAMYwC+8feF+axp2kMmdRrrws1mC2UkokWFlJknDTecsyGcDTv/gyzntz4VoXhdpymxhBWXqxKTyP|0|0|||||
```

Then we can decrypt with this script:

```python
import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

main_key = b"KEqrg7kVO1xP2BqJG9fZUpMyWblZFQWuClvZb0EYIzw="

enc = "DMDG5OZ6ImHlrLBCNwAAEAAAAEvMoUVY9IkqeJD0pqQP2aXgVUSFafXZxIKu7sBZoLHY"

raw = base64.b64decode(enc)

key = SHA256.new(main_key).digest()
iv = raw[1:13]
tag = raw[-16:]
data = raw[19:-16]

pt = AES.new(key, AES.MODE_GCM, nonce=iv).decrypt_and_verify(data, tag)

print("plaintext:", pt)
print("display name:", pt.decode("utf-8"))
```

```bash
$ python3 d.py
plaintext: b'Edward Collins10'
display name: Edward Collins10
```

##### Shellcode Analysis
```bash
Question 1/2
Which process was targeted by the suspicious remote thread creation, and at what virtual address did the thread begin execution?
Format: process;address 
```

Analyzing the sysmon evtx again and filter it with keyword `software_reporter_tool.exe` since that's the RAT. On the last second line, there is remote thread creation and that's the answer.

![](image_24.png)

```bash
Question 2/2
What is the SHA-256 hash of the shellcode injected into the targeted process?
Format: 64 hexadecimal characters  
```

Because this is RAT, there must be a traffic recorded within the memdump. We can acquire a pcap from bulk_extractor and parse the traffic there. With this command we can reconstruct the shellcode.

```bash
tshark -r out_bulk_extractor/packets.pcap \
  -Y 'tcp.stream == 0 && ip.src == 192.168.56.1 && tcp.srcport == 80 && tcp.len > 0' \
  -T fields -e tcp.payload |
  tr -d '\n' |
  xxd -r -p > /tmp/stream0_server.bin
```

then we scan the pcap with this script. The result is hit on the stream 17 then we can extract the tcp payload of it

```bash
$ for s in $(tshark -r out_bulk_extractor/packets.pcap \
    -Y 'tcp.port == 80 && ip.addr == 192.168.56.1' \
    -T fields -e tcp.stream | sort -nu); do
    echo "========== STREAM $s =========="
    tshark -r out_bulk_extractor/packets.pcap \
      -q -z follow,tcp,ascii,$s 2>/dev/null |
      grep -aE 'patch\.bin|GET |HTTP/|Content-|POST ' -C 3
done

========== STREAM 0 ==========
========== STREAM 17 ==========
Node 0: 192.168.56.1:80
Node 1: 10.0.2.15:51107
204
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.11.0
Date: Sun, 16 Aug 2026 05:20:18 GMT
Content-type: application/octet-stream
Content-Length: 241260
Last-Modified: Sun, 16 Aug 2026 05:19:20 GMT

$ tshark -r out_bulk_extractor/packets.pcap \
  -Y 'tcp.stream == 17 && ip.src == 192.168.56.1 && tcp.srcport == 80 && tcp.len > 0' \
  -T fields -e tcp.payload |
  tr -d '\n' |
  xxd -r -p > /tmp/stream17.bin

$ python3 - <<'PY'
from pathlib import Path

b = Path('/tmp/stream17.bin').read_bytes()
off = b.find(b'\r\n\r\n')
assert off >= 0

body = b[off + 4:]
print("stream17 body:", len(body))

Path('/tmp/patch_part17.bin').write_bytes(body)
PY
```

Next we just concat that both payload then calculate the sha256sum. The correct order is /tmp/patch_part17.bin then /tmp/stream0.bin.

```bash
$ cat /tmp/patch_part17.bin /tmp/stream0_server.bin > /tmp/patch_a.bin
cat /tmp/stream0_server.bin /tmp/patch_part17.bin > /tmp/patch_b.bin

$ sha256sum /tmp/patch_b.bin /tmp/patch_a.bin
0b47e1fd629ed8229152287b957d0090ffafe6a839655cc78634206671039022  /tmp/patch_b.bin
9e2413e4d0469a25c7840872f5fa98d93c4bb1c2f9a0d184f47eadaf808fefcf  /tmp/patch_a.bin ### answer
```

Next is just rev shits from the shellcode, i just rely on the claude and gpt. But the probset suggest for using Detect It Easy (DIE) or VT then we can know that this shellcode is donut packer. We can unpacked it with [donut decryptor](https://github.com/volexity/donut-decryptor) and rev will be so much more easily.

##### Rev the Shellcode
```bash
Question 1/4
What smart contract address does the ransomware query to retrieve its victim-specific configuration?
Format: Address starting with 0x

Question 2/4
What function selector is used by the ransomware when querying the smart contract? 
Format: 0xXXXXXXXX  

Question 3/4
What encrypted seed, salt, and KDF round count were returned by the smart contract for the compromised victim?
Submit all three values in the specified order.
Format: encryptedSeed;salt;kdfRounds 

Question 4/4
What is the SHA-256 hash of the recovered original document?
Format: 64 hexadecimal characters
```

This is the decryptor of the ransomware

```python
from hashlib import sha256
import hmac
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

enc_seed = bytes.fromhex(
    "a545e0a8c675ce955431882c239e555e2de01b6bf63cd0c84514627cc306481f"
)

salt = bytes.fromhex("7a89a98c355a84e98a3f4ef3045871d4")
victim_id = bytes.fromhex(
    "b4a7e966170bc4c201370a71777fa125903f5e2a76892c123e0fe6b557158ac2"
)
machine_guid = "fd2bcf5a-dee6-408e-bf19-c38028a5f1a6"

# Recover seed
seed = bytes(
    a ^ b
    for a, b in zip(enc_seed, sha256(victim_id + salt).digest())
)

# KDF
key = hmac.new(
    seed,
    machine_guid.encode() + salt,
    sha256
).digest()

for _ in range(4095):
    key = hmac.new(seed, key, sha256).digest()

aes_key = key[:16]

# IV
path = r"C:\Users\edwar\OneDrive\Documents\Workspace\Finance\Executive\Apex_Orion_Acquisition_Proposal.docx"
iv = hmac.new(seed, path.encode(), sha256).digest()[:16]

# Decrypt
with open("Apex_Orion_Acquisition_Proposal.docx.jay", "rb") as f:
    data = f.read()

plain = AES.new(aes_key, AES.MODE_CBC, iv).decrypt(data)
plain = unpad(plain, 16)

with open("decrypted.docx", "wb") as f:
    f.write(plain)

print("Done!")
```

```answer.py
ANSWERS = [
    "Outlook",
    "2026-08-15 08:45:38",
    "Update Your Browser - Download the Latest Google Chrome",
    "2026-08-15 16:42:36",
    "GoogleChromeUpdater",
    r'rundll32.exe "C:\Users\Public\chrome_update.dll",Drop',
    r"2|C:\Program Files\Google\Chrome\GoogleUpdater.exe|C:\Program Files\Google\Chrome\software_reporter_tool.exe",
    r'"C:\Program Files\Google\Chrome\GoogleUpdater.exe" "add-exclusion" "Paths" "C:\Program Files\Google\Chrome"|"C:\Program Files\Google\Chrome\GoogleUpdater.exe" "secengine" "disable"|"C:\Program Files\Google\Chrome\GoogleUpdater.exe" "tp" "off"|"C:\Program Files\Google\Chrome\GoogleUpdater.exe" "rtp" "off"',
    "2026-08-15 16:48:38",
    r'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SecurityHealthSystray.exe\Debugger=systray.exe',
    'T1547.001',
    '2026-08-15 16:49:32',
    'Google Calendar',
    '18a7bdbf39f6baa148901225fa21b72cfe492720379a04f2068e1d364db65457@group.calendar.google.com',
    'summary_description',
    'systeminfo',
    '2026-08-15 17:11:14',
    r'''for /f "tokens=1" %%i in ('tasklist /nh') do @echo %%i''',
    'KEqrg7kVO1xP2BqJG9fZUpMyWblZFQWuClvZb0EYIzw=',
    'Edward Collins10',
    'Notepad.exe;0x00000151C1E20000',
    '9e2413e4d0469a25c7840872f5fa98d93c4bb1c2f9a0d184f47eadaf808fefcf',
    '0x08FE9fc8288Cf5D5EE5f4F69c0e4f774FFA275d4',
    '0x8fe24bdb',
    'a545e0a8c675ce955431882c239e555e2de01b6bf63cd0c84514627cc306481f;7a89a98c355a84e98a3f4ef3045871d4;4096',
    'd33cc7764e98bcdef507065dc96d4b2e5fd2af0ec95d60e9b4e115fa75b2ea5e'
]
```

#### Flag
COMPFEST18{th1s_chall3nges_was_cool_right?_2pNZ51OsixCFvWpY}
