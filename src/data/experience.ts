// Source: Experiences section of BektiYudaAdiPratama_CV-8.pdf.
// Group by start year; only roles marked Present in the CV are ongoing.
export type Experience = {
  year: number;
  period: string;
  title: string;
  organization: string;
  category: string;
  description: string;
};

export const experiences: Experience[] = [
  {
    year: 2026,
    period: "2026 – Present",
    title: "Security Engineer Intern",
    organization: "PT Digital Solusi Grup",
    category: "Work Experience · Internship",
    description:
      "Conduct vulnerability assessments and penetration testing on web applications and APIs, validate security findings, and document actionable remediation recommendations.",
  },
  {
    year: 2026,
    period: "2026",
    title: "Problem Setter · HoloHack",
    organization: "HOLOGY 9.0 · FILKOM, Brawijaya University",
    category: "Experience · Challenge Development",
    description:
      "Designed and developed digital forensics challenges for HoloHack, the CTF competition within HOLOGY, a national technology competition organized by FILKOM, Universitas Brawijaya.",
  },
  {
    year: 2026,
    period: "2026",
    title: "Cybersecurity Technology Laboratory Assistant",
    organization: "FILKOM · Brawijaya University",
    category: "Work Experience · Teaching",
    description:
      "Facilitated hands-on cybersecurity laboratory sessions covering offensive and defensive security, providing technical guidance and supporting practical security analysis.",
  },
  {
    year: 2026,
    period: "2026",
    title: "Information Security Laboratory Assistant",
    organization: "FILKOM · Brawijaya University",
    category: "Work Experience · Teaching",
    description:
      "Supported information security practicums by explaining technical concepts, guiding students through laboratory exercises, and evaluating practical assignments.",
  },
  {
    year: 2025,
    period: "2025 – Present",
    title: "Core Team · Cybersecurity Division",
    organization: "POROS · Organization of Open Source",
    category: "Experience · Community",
    description:
      "Coordinate the Digital Forensics study group, facilitating knowledge-sharing sessions and hands-on exercises in forensic investigation and artifact analysis.",
  },
  {
    year: 2025,
    period: "2025",
    title: "Problem Setter · CodEX 2025 CTF",
    organization: "CodEX 2025 CTF",
    category: "Experience · Challenge Development",
    description:
      "Designed and authored CTF challenges in web security, digital forensics, and reverse engineering, covering multiple cybersecurity disciplines.",
  },
  {
    year: 2025,
    period: "2025",
    title: "Problem Setter · COSMOS 2025",
    organization: "COSMOS 2025",
    category: "Experience · Challenge Development",
    description:
      "Developed web security challenges featuring vulnerability scenarios aligned with the OWASP Top 10 and prepared remediation guidance to reinforce secure development practices.",
  },
];
