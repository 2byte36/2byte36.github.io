export const SITE_TITLE = "2byte";
export const SITE_DESCRIPTION =
  `CTF Writeups Archive - Blue Team | CTF Player mainly on Forensics and Reverse Engineering`.trim();

export const KNOWN_TECH =
  `Forensics,Memory-Forensics,Network-Analysis,Malware-Analysis,Steganography,Reverse-Engineering,Binary-Analysis,OSINT,Web-Exploitation,Linux,Python,Bash,Volatility,Wireshark,Ghidra,Autopsy,Docker`.split(
    ",",
  );
export const ABOUT_ME =
  `Welcome to my CTF writeups archive. I’m a Capture The Flag (CTF) competitor with interests across a broad range of security domains. This blog serves as a record of my learning and problem-solving process, featuring writeups that emphasize methodology, tooling, and clear reasoning from initial reconnaissance to final solution. You’ll find walkthroughs spanning categories such as web security, cryptography, reverse engineering, binary exploitation, digital forensics, OSINT, and miscellaneous challenges. My goal is to share practical, reproducible approaches that help others learn how to think through security problems`.trim();
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
    title: "Certifications",
    href: "/certifications",
  },
];
