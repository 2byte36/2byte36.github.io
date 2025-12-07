export const SITE_TITLE = "2byte";
export const SITE_DESCRIPTION =
  `CTF Writeups Archive - Blue Team | CTF Player mainly on Forensics and Reverse Engineering`.trim();

export const KNOWN_TECH =
  `Forensics,Memory-Forensics,Network-Analysis,Malware-Analysis,Steganography,Reverse-Engineering,Binary-Analysis,OSINT,Web-Exploitation,Linux,Python,Bash,Volatility,Wireshark,Ghidra,Autopsy,Docker`.split(
    ",",
  );
export const ABOUT_ME =
  `Welcome to my CTF writeups archive. I'm a CTF player with a focus on Blue Team activities, specializing in Forensics and Reverse Engineering challenges. This blog documents my journey through various CTF competitions, sharing detailed writeups and methodologies for solving complex security challenges. Whether it's analyzing memory dumps, investigating network traffic, reverse engineering malware, or uncovering hidden data through steganography, I aim to provide comprehensive solutions and learning resources for the cybersecurity community.`.trim();
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
    title: "About",
    href: "/about",
  },
];
