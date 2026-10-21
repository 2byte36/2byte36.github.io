export const SITE_TITLE = "2byte";
export const SITE_DESCRIPTION =
  `CTF Writeups Archive - Blue Team | CTF Player mainly on Forensics and Reverse Engineering`.trim();

export const KNOWN_TECH =
  `Forensics,Memory-Forensics,Network-Analysis,Malware-Analysis,Steganography,Reverse-Engineering,Binary-Analysis,OSINT,Web-Exploitation,Linux,Python,Bash,Volatility,Wireshark,Ghidra,Autopsy,Docker`.split(
    ",",
  );
export const ABOUT_ME =
  `I’m Bekti Yuda Adi Pratama, also known as 2byte, an Information Technology student at Brawijaya University. My main interests are digital forensics, incident response, threat analysis, and defensive security. I enjoy tracing what happened in a system, understanding how an attack works, and turning that evidence into practical findings.

As a Security Engineer Intern at PT Digital Solusi Grup, I assess web applications and APIs through vulnerability assessments and penetration testing, validate findings, and document remediation recommendations. I also practice responsible vulnerability disclosure, with recognized reports for SSO Kediri Kota and GapuraUB.

Beyond assessments, I compete in CTF and incident response competitions and create challenges in digital forensics, reverse engineering, and web security. I coordinate the Digital Forensics study group at POROS and support cybersecurity and information security practicums as a laboratory assistant at FILKOM. I also build tools such as MetaCrypt, a Python project for encrypting GPS metadata in images.

This portfolio brings together my investigations, competition write-ups, and achievements. I share the reasoning behind each solution so others can follow the process and learn alongside me.`.trim();
export const GITHUB_USERNAME = "2byte36";
export const QUOTE = "Cybersecurity Researcher & CTF Player";
export const NAV_LINKS: Array<{ title: string; href?: string }> = [
  {
    title: "Blog",
  },
  {
    title: "Github",
    href: "//github.com/" + GITHUB_USERNAME,
  },
  {
    title: "Achievements",
    href: "/achievements",
  },
];
