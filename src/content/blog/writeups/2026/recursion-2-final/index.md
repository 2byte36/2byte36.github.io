---
title: "RECURSION 2.0 Final — Forensics"
description: "Recovering evidence from an obfuscated document, Linux and macOS systems, steganographic images, and a keylogging sample."
pubDate: "2026-10-31"
heroImage: "./assets/recursion-ctf-official.svg"
heroColor: "#000000"
---

These are my forensics write-ups from the RECURSION 2.0 Final. The challenges covered document analysis, disk and memory forensics, macOS incident response, steganography, and malware analysis.

## Transkrip Bersejarah

Points: 100

The challenge provided a macro-enabled Word document, `Transkrip_Bersejarah.docm`, and an encrypted file named `evidence.txt`. I began by deobfuscating the document's VBA macros with `olevba`.

```bash
olevba Transkrip_Bersejarah.docm --deobf
```

![Deobfuscated VBA macro](./assets/recursion-image-59.png)

The macro showed that the encryption used a repeating XOR key. That key was assembled from the first character of every non-empty paragraph in the document. I reproduced the process directly from `word/document.xml` and used the result to decrypt the hexadecimal content of `evidence.txt`.

```python
from zipfile import ZipFile
from xml.etree import ElementTree as ET
from pathlib import Path

DOC = Path("Transkrip_Bersejarah.docm")
ENC = Path("evidence.txt")

with ZipFile(DOC) as archive:
    root = ET.fromstring(archive.read("word/document.xml"))

ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
paragraphs = []

for paragraph in root.findall(".//w:p", ns):
    text = "".join(node.text or "" for node in paragraph.findall(".//w:t", ns))
    text = text.strip()
    if text:
        paragraphs.append(text)

key = "".join(paragraph[0].lower() for paragraph in paragraphs).encode()
if not key:
    raise ValueError("Empty XOR key")

ciphertext = bytes.fromhex(ENC.read_text().strip())
plaintext = bytes(byte ^ key[index % len(key)] for index, byte in enumerate(ciphertext))

Path("decrypted_flag.txt").write_bytes(plaintext)
print("[+] Key:", key.decode(errors="replace"))
print("[+] Decrypted:", plaintext)
```

![Recovered plaintext](./assets/recursion-image-5.png)

Flag: `RECURSION{4M5S1213LH412KAM}`

## development

Points: 496

This challenge supplied a Linux disk image and a LiME memory dump. The disk contained a LUKS2-encrypted partition, so the investigation began with the memory image and then used the recovered cryptographic material to unlock the disk.

Running `xxd memory.lime | head` exposed the `LiME` magic bytes. The header also showed that the captured physical memory began at `0x40000000`.

![LiME header and physical start address](./assets/recursion-image-92.png)

The unencrypted Linux volume identified the kernel as `5.15.0-198-generic`.

![Kernel version recovered from the disk](./assets/recursion-image-107.png)

I then inspected the disk layout in bytes. The LUKS2 partition began at byte offset `3275751424`.

```bash
sudo parted -s disk.img unit B print
```

![LUKS2 partition offset](./assets/recursion-image-17.png)

The LUKS UUID was `0ff78882-8e13-4801-88e4-bed91a18894f`. I loaded the LiME dump with MemNixFS and searched memory for `luks2`. The recovered JSON metadata identified the cipher as `aes-xts-plain64`.

![LUKS metadata in memory](./assets/recursion-image-112.png)

![Recovered LUKS2 JSON metadata](./assets/recursion-image-87.png)

Next, I used `bulk_extractor` to recover AES-key candidates from memory. I tested candidate pairs against the LUKS volume until `cryptsetup` accepted the reconstructed master key.

```bash
bulk_extractor -o bulk memory.lime
```

The SHA-256 digest of the accepted master key was:

```text
7b7ace68019e5317441569668aa411481188471572f888c6b5f1bfa40b029d53
```

![Successful master-key recovery](./assets/recursion-image-102.png)

After opening the encrypted partition, I activated the LVM volume in read-only mode and mounted the filesystem without replaying its journal.

```bash
sudo vgchange -ay --devices /dev/mapper/recovered \
  --config 'activation { read_only_volume_list = [ "ubuntu-vg/ubuntu-lv" ] }' \
  ubuntu-vg

sudo mount -t ext4 -o ro,noload,nosuid,nodev,noexec \
  /dev/mapper/ubuntu--vg-ubuntu--lv /mnt/dec
```

![Activated logical volume](./assets/recursion-image-96.png)

![Mounted decrypted filesystem](./assets/recursion-image-55.png)

The Flask log at `/home/pujpuj/app/flask.log` recorded the attacker's address as `192.168.64.42`. It also showed access to Werkzeug's `/console` endpoint.

![Attacker activity in the Flask log](./assets/recursion-image-14.png)

The system release information and kernel version led to the privilege-escalation vulnerability `CVE-2026-31431`.

![Operating-system release information](./assets/recursion-image-88.png)

![Kernel privilege-escalation evidence](./assets/recursion-image-20.png)

Finally, the recovered filesystem contained `/root/flag.png`.

![Flag recovered from the root directory](./assets/recursion-image-83.png)

Challenge flag: `recursion{gg_3z_thank5_ud4h_mamp1r!}`

Remote flag: `RECURSION{a9b45b4fd5b54be0a4b35d57ab992d59}`

## They do, usually when you've finally moved on

Points: 500

This challenge followed a compromise of a macOS host. I began with the victim's Delta Chat database at:

```text
macOS/Users/lyanna/Library/Application Support/DeltaChat/accounts/
a669cbdd-5889-405d-b527-d93d963097a1/dc.db
```

The configuration table identified the victim's address as `l4gszwsty@chat.nuvon.app`, while the contacts table identified the attacker as `tisdzkxci@chatmail.uk`.

![Victim account in the Delta Chat database](./assets/recursion-image-76.png)

![Attacker address in the contacts table](./assets/recursion-image-109.png)

In the packet capture, the HTTP stream containing the trigger was `tcp.stream == 125`. It revealed the trigger value `7d1cdce3381f34ed49c8d0eddab0360c` and the `x-key` session key:

```text
6d726932a45797f18c0637a50a3104421611d9cf4d38cf46ef04a8da807fe6b8
```

![Trigger request in the packet capture](./assets/recursion-image-16.png)

Testing the 256-bit key against the encrypted traffic showed that the payload used AES-256-CBC. To locate the original entry point, I inspected the OpenCode log under `~/.local/share/opencode/log`, where a suspicious script had been executed.

![Suspicious command in the OpenCode log](./assets/recursion-image-44.png)

The script was stored in the hidden `.DsM76` directory under `Application Support`, and its stager was named `c9K1sd.bin`.

![Hidden staging directory](./assets/recursion-image-89.png)

![Stager filename](./assets/recursion-image-64.png)

Strings from the downloaded `WeatherStation` binary referenced `WeatherStation.Btlj.bmp`.

![Embedded bitmap filename](./assets/recursion-image-54.png)

The application's `.syncstate` file contained the identifier `a57d30c606f47457ab963ec38b9b9e8a`.

![WeatherStation sync-state value](./assets/recursion-image-79.png)

Searching the filesystem for `WeatherStation` led to `com.apple.softwareupdate.plist` in the user's `LaunchAgents` directory. The persistence entry installed the binary as `stationsync` and used the label `com.apple.softwareupdate`.

![LaunchAgent persistence entry](./assets/recursion-image-110.png)

![LaunchAgent label](./assets/recursion-image-75.png)

Binary analysis revealed the C2 endpoint `192.168.0.6:61048`. Filtering the capture on that port exposed an outbound archive containing the hardware identifier `290f6adccd830bae66f6f34495611cb275bcff8f88e822d52f656f2048df4a8e`.

![C2 traffic on port 61048](./assets/recursion-image-47.png)

![Hardware identifier recovered from the archive](./assets/recursion-image-32.png)

The operator's first command was `list`. Across the traffic, I found eleven task versions, from `1.0.0` through `1.0.10`. The `1.0.10` key was stored in `halcyon.telemetry.checkin.1.0.38.nupkg`:

```text
CVrNNG7aB/HSexv3uCpJwSObBnw2H9jbprMsY56kOho=
```

![Version 1.0.10 key](./assets/recursion-image-73.png)

The NuGet package name was `halcyon.telemetry.checkin`. Decrypting the exfiltrated content recovered:

```text
I REALLY REALLY MISS HIM, I HOPE HE MISS ME TOO :(
```

![Recovered exfiltrated message](./assets/recursion-image-67.png)

For the result data, the malware derived `K_result` as `HMAC-SHA256(session_key, UTF8("result:" || V))`. The Base64-decoded release notes were arranged as a 12-byte nonce, ciphertext, and a 16-byte tag, then decrypted with AES-256-GCM. The resulting key was:

```text
GcKYo/KjkzBVU2e9y9YpGOCmeVzlQ1DklWSQfOUVqKU=
```

Flag: `RECURSION{738056cb5d124b23ff12e94d86831a38}`

## stegoshit

Points: 100

The challenge provided two images. Running `zsteg` against them revealed MacBinary data and strings containing `__PGEZRO`.

![zsteg output from the supplied images](./assets/recursion-image-48.png)

I extracted the raw payload from each image with `zsteg`.

![Extracted binary fragments](./assets/recursion-image-71.png)

The first fragment stored the offset needed to place the second fragment. I reconstructed the split Mach-O file with the following script.

```python
from pathlib import Path

raw1 = Path("a1.raw").read_bytes()
raw2 = Path("a2.raw").read_bytes()

offset = int.from_bytes(raw1[:4], "little")
part1 = raw1[8:]
part2 = raw2[8:]

total_size = 0x21D0
result = bytearray(total_size)
result[:len(part1)] = part1
result[offset:offset + len(part2)] = part2

Path("reconstructed.macho").write_bytes(result)
```

![Reconstructed Mach-O file](./assets/recursion-image-18.png)

The reconstructed program contained a 40-byte encrypted buffer and a four-byte XOR key. XORing the buffer with `adadee17` and Base64-decoding the result recovered the flag.

Flag: `RECURSION{go0&_9am3!}`

## nguping

Points: 379

This challenge required static analysis of a macOS keylogging sample. Its SHA-256 digest was:

```text
954ce936a22432eeeb78bee3622a6364c9c8b6d6c32391cf03c1e25032294c86
```

![Sample SHA-256 digest](./assets/recursion-image-15.png)

VirusTotal showed that the binary had a single dynamic-library dependency: `/usr/lib/libSystem.B.dylib`.

![Dynamic-library dependency in VirusTotal](./assets/recursion-image-34.png)

The framework-path strings were protected with a single-byte XOR operation. The routine in `FUN_100000944` revealed the key as `0x37`.

![Single-byte XOR routine](./assets/recursion-image-38.png)

Following the calls into `FUN_1000005bc` and decrypting `DAT_1000015b0` revealed the dynamically loaded framework:

```text
/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics
```

![Obfuscated framework-path data](./assets/recursion-image-100.png)

![Decrypted CoreGraphics path](./assets/recursion-image-53.png)

The sample parsed `LC_SYMTAB` to resolve the required symbols. Inside the API hash routine, `FUN_100000a50`, the multiplication factor was `0x5BD1E995`.

![LC_SYMTAB parsing routine](./assets/recursion-image-19.png)

![API hash multiplication factor](./assets/recursion-image-1.png)

The event-capture routine resolved `CGEventTapCreate`, which requires Accessibility permission, and used `CGEventKeyboardGetUnicodeString` to collect keyboard input.

![CGEventTapCreate resolution](./assets/recursion-image-97.png)

![CGEventKeyboardGetUnicodeString usage](./assets/recursion-image-52.png)

The sample stored collected data in a `0x3fc`-byte, or 1020-byte, buffer.

The virtual keycode that triggered encryption and exfiltration was `0x24`.

![Virtual keycode check](./assets/recursion-image-37.png)

![Keylogging buffer size](./assets/recursion-image-57.png)

Before transmission, the captured data was encrypted with Speck64/128: a 64-bit block, a 128-bit key, and 27 rounds. The transmission routine then formatted the encrypted result before sending it.

```text
mAc bLk %zu: v0=0x%08x, v1=0x%08x
```

![Transmission format string](./assets/recursion-image-9.png)

Another routine, `FUN_1000010a8`, contained the RC4 key `M4C0S_K3YD1S_R3PR0`. I used it to decrypt `DAT_100001763`, which yielded the sample's bot token.

![RC4 key material](./assets/recursion-image-29.png)

![Encrypted bot-token buffer](./assets/recursion-image-13.png)

![Decrypted token buffer](./assets/recursion-image-114.png)

These behaviors confirmed that the sample's primary functionality was keylogging.

Flag: `RECURSION{3d8fa239bc3a437aef04c67f85902d66}`
