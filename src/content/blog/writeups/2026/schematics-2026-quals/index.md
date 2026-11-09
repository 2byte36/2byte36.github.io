---
title: "Schematics NPC 2026 Quals — Forensics"
description: "Investigating Linux artifacts, a two-case intrusion, prompt-injected invoice data, and a C2 beacon from memory."
pubDate: "2026-10-11"
heroImage: "./assets/schematics-npc-official.svg"
heroColor: "#000000"
---

These are my forensics write-ups from the Schematics NPC 2026 qualification round. The challenges covered Linux disk analysis, email and Windows incident response, prompt-injection artifacts, memory forensics, and malware analysis.

## Ambatuboot

Points: 439

I loaded the supplied Linux disk image into Autopsy and began with the shell histories for both the regular user and root. The user's history contained several red herrings.

![User shell-history artifacts](./assets/schematics-image-19.png)

The root history had been deleted, but Autopsy still indexed the relevant artifacts.

![Deleted root shell history](./assets/schematics-image-38.png)

Reviewing the indexed files led to an interesting Rust source file named `main.rs`.

![Recovered main.rs source file](./assets/schematics-image-33.png)

The encoded value in that file was Base64. Decoding it recovered the flag.

Flag: `SCH26{m4k35ure_u4lw4ys_up2d4t3d5ri}`

## Ratatouille

Points: 394

This challenge contained two related cases and a twelve-question verification sequence.

### Question #1

> What is the share ID of the malicious AI-generated presentation that was used to host the phishing chain?
>
> Format: share ID

I started with the PST files and opened them in GoldFynch's PST Viewer. The case-a mailbox contained a phishing email with an attached PDF. Inspecting the PDF structure revealed the share ID `d-8fk2qmvx`.

![Share ID recovered from the phishing attachment](./assets/schematics-image-12.png)

### Question #2

> After the stolen session cookie was replayed, from which IP address did the attacker access the mailbox?
>
> Format: IPv4 address

The Entra sign-in records identified `45.148.10.77` as the suspicious source address.

![Suspicious address in the Entra sign-in records](./assets/schematics-image-43.png)

### Question #3

> From which website did the victim download the malicious software?
>
> Format: website domain

In case-b, the malicious email directed the victim to `software.аnwei.cn`.

![Malicious domain in the second mailbox](./assets/schematics-image-16.png)

### Question #4

> From which cloud storage bucket did the malware download its payload files?
>
> Format: bucket hostname

I continued with `sysmon.xml` and searched the events in Visual Studio Code. The setup process accessed a cloud-storage URL under the bucket:

```text
1259834217.cos.ap-chengdu.myqcloud.com
```

The activity involved `C:\Users\elshe\AppData\Local\Temp\RatSetup\Setup.exe`.

![Cloud bucket and setup activity](./assets/schematics-image-32.png)

### Question #5

> Which ZIP archive did the victim download, and into which directory did the dropper stage its payloads?
>
> Format: ZIP filename, directory path

Searching for the downloaded `Setup.zip` and related drop events revealed the staging directory:

```text
C:\Program Files (x86)\Common Files\System
```

![Registry event exposing the staging directory](./assets/schematics-image-42.png)

### Question #6

> Which DLL did the signed loader sideload from its own directory, and which downloaded payload was it a renamed copy of?
>
> Format: loaded DLL, downloaded payload

The signed executable `douyin.exe` loaded the attacker's DLLs. Correlating its image-load events with the RAT's parent process identified `dbghelp.dll` and `engcore.dll`.

![DLLs loaded by douyin.exe](./assets/schematics-image-50.png)

![Parent process correlation](./assets/schematics-image-41.png)

![Accepted malicious DLL pair](./assets/schematics-image-14.png)

### Question #7

> Into which system process did `winsync.dll` inject its monitoring code, and which Run-key value name did it create for persistence?
>
> Format: process name, Run-key value name

Searching for `winsync.dll` showed that it was loaded by `svchost.exe`. The associated Run-key persistence entry was named `SysHealthMonitor`.

![winsync.dll loaded by svchost.exe](./assets/schematics-image-10.png)

![SysHealthMonitor persistence entry](./assets/schematics-image-34.png)

### Question #8

> Which process was hosting the RAT when memory was acquired, and which process was its parent?
>
> Format: process name, parent process name

The memory image's modification time was 1 October 2026 at 03:54:49. Correlating that time with Sysmon revealed `nslookup.exe` and its parent, `douyin.exe`.

![Processes active around the memory-capture time](./assets/schematics-image-17.png)

![Parent-process relationship in Sysmon](./assets/schematics-image-20.png)

### Question #9

> What is the filename of the second-stage persistence binary created by the RAT-hosting process?
>
> Format: filename

The file created through the `nslookup.exe` activity was `SrvRestart64.exe`.

### Question #10

> What C2 endpoint does the implant contact? Carve it from the implant configuration in memory and confirm it against the traffic capture.
>
> Format: IP address and port

Network events showed the C2 endpoint `203.0.113.24:8443`.

![C2 connection and related process activity](./assets/schematics-image-4.png)

### Question #11

> What group ID is pinned in the implant configuration—the `BEIZHU` remark value—and what password string does its keylog buffer hold?
>
> Format: group ID, password

Searching strings from the memory image for `BEIZHU` recovered the host identifier `finance-sz-04`.

![Host identifier in memory](./assets/schematics-image-7.png)

The nearby C2 and keylogging data contained the account `elsche@anwei.cn` and the value `qg71-4Lw-dKM8@J>`.

![Account data and adjacent value](./assets/schematics-image-35.png)

### Question #12

> Before detection, the intruder used the implant to submit a payment from the victim's own ERP console. What beneficiary account number did the funds go to, and in what amount?
>
> Format: account number, amount

The same memory search exposed the targeted account and amount:

```text
622202023370916, 864200.00
```

![Target account and transaction amount](./assets/schematics-image-29.png)

Flag: `SCH26{4da_t1ku5_d1_b3l4k4n9_tAkut_b9t_tp_l3b1h_t4kut_T1ku5_b3rd45!_c4ca067ca3}`

## Day 1

Points: 381

The challenge supplied an AD1 image containing only the user's directory. PowerShell history pointed to the directory that held the source files.

![Source directory referenced by PowerShell history](./assets/schematics-image-51.png)

Inside the invoice templates, the README contained a prompt injection. The resulting script collected environment variables and sent them to the attacker's domain.

![Prompt injection and exfiltration script](./assets/schematics-image-6.png)

Gemini was the only AI agent on the system. Its chat data was stored beneath `.gemini/tmp`, but the flag did not appear there in plaintext.

![Gemini chat artifacts](./assets/schematics-image-52.png)

The PowerShell history also referenced CSV files. Their logs contained different `key_sha256_12` values, and rows whose `description` field contained a single character formed a noisy, encoded-looking stream.

![CSV key values](./assets/schematics-image-15.png)

![Single-character description rows](./assets/schematics-image-24.png)

I tested the possible groupings by key, amount, and method, sorting each selection by `created_utc` and searching the reconstructed output for the flag prefix.

```python
import csv
import glob

rows = []

for filename in glob.glob("*.csv"):
    with open(filename, encoding="utf-8", errors="replace") as handle:
        for row in csv.DictReader(handle):
            if len((row["description"] or "").strip()) == 1:
                rows.append(row)

def render(selected):
    return "".join(
        (row["description"] or "").strip()
        for row in sorted(selected, key=lambda item: item["created_utc"])
    )

keys = sorted({row["key_sha256_12"] for row in rows})
amounts = sorted({row["amount"] for row in rows})
methods = sorted({row["method"] for row in rows})

for key in keys:
    value = render([row for row in rows if row["key_sha256_12"] == key])
    if "SCH26" in value:
        print(f"FOUND key={key}: {value}")

for amount in amounts:
    value = render([row for row in rows if row["amount"] == amount])
    if "SCH26" in value:
        print(f"FOUND amount={amount}: {value}")

for method in methods:
    value = render([row for row in rows if row["method"] == method])
    if "SCH26" in value:
        print(f"FOUND method={method}: {value}")
```

The reconstructed stream produced the flag.

Flag: `SCH26{r0t4t3d_1s_n0t_r3v0k3d}`

## ConnectBreach

Points: 308

The final challenge provided a memory dump and a packet capture. I loaded the dump into MemProcFS and inspected `ProcessTimeline`, where I found `c2_beacon.exe`. I then dumped that process's executable for analysis.

![c2_beacon.exe in the process timeline](./assets/schematics-image-25.png)

The important routine was `FUN_7ff7609a2160`. It read 0x30 bytes from `0x7ff7609a4160`, XORed each byte with `0x5a`, and appended `a2f}`.

![Flag-decoding routine](./assets/schematics-image-21.png)

I reproduced that routine with a short Python script.

```python
data = bytes.fromhex(
    "09 19 12 68 6c 21 39 2c 3f 05 68 6a 68 6e 05 6b "
    "6d 6a 63 05 3b 2f 2e 32 05 38 23 2a 6e 29 29 05 "
    "39 68 05 37 69 37 05 3e 69 39 28 23 2a 2e 05 62"
)

flag = bytes(byte ^ 0x5A for byte in data) + b"a2f}"
print(flag.decode())
```

Flag: `SCH26{cve_2024_1709_auth_byp4ss_c2_m3m_d3crypt_8a2f}`
