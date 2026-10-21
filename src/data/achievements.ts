// Source: Achievements section of BektiYudaAdiPratama_CV-8.pdf.
// The CV provides years only; entries retain its order within each year.
export type Achievement = {
  title: string;
  organizer: string;
  recognition: string;
  category: string;
  description: string;
  writeup?: string;
};

export const achievementTimeline: { year: number; entries: Achievement[] }[] = [
  {
    year: 2026,
    entries: [
      {
        title: "Rise The Ranger 2",
        organizer: "SATSIBER TNI",
        recognition: "2nd Place",
        category: "Incident Response · Student Category",
        description:
          "Placed second in the student category of a team incident response competition organized by Satuan Siber TNI, investigating incidents, identifying threats, and developing response strategies.",
      },
      {
        title: "Techfest CTF",
        organizer: "HIMTI · Binus University",
        recognition: "3rd Place",
        category: "Capture The Flag · Team Competition",
        description:
          "Placed third overall while representing Universitas Brawijaya, solving challenges across multiple cybersecurity domains as part of a team.",
        writeup: "/blog/techfest-2026-final",
      },
      {
        title: "ZERO DAY CTF",
        organizer: "PT Digital Solusi Grup",
        recognition: "2nd Place",
        category: "Capture The Flag · Scholar Battle",
        description:
          "Placed second in the Scholar Battle category, solving challenges in web exploitation, reverse engineering, digital forensics, cryptography, and other cybersecurity domains.",
      },
    ],
  },
  {
    year: 2025,
    entries: [
      {
        title: "SSO Kediri Kota",
        organizer: "Pemerintah Kota Kediri",
        recognition: "Recognized Disclosure",
        category: "Vulnerability Disclosure",
        description:
          "Recognized for responsibly disclosing a vulnerability in the city's single sign-on service, resulting in remediation and a validated security fix.",
      },
      {
        title: "GapuraUB",
        organizer: "Brawijaya University",
        recognition: "Recognized Disclosure",
        category: "Vulnerability Disclosure",
        description:
          "Recognized for responsibly disclosing a vulnerability in GapuraUB, resulting in remediation and a validated security fix.",
      },
      {
        title: "Cyber Hero Battleground CTF",
        organizer: "Hack It Braw! Community",
        recognition: "1st Place",
        category: "Capture The Flag · Individual Competition",
        description:
          "Placed first in an individual CTF competition, applying analytical problem-solving skills under time constraints.",
        writeup: "/blog/hib-chb-ctf",
      },
      {
        title: "Teknocomp CTF",
        organizer: "Teknokrat University",
        recognition: "2nd Place",
        category: "Capture The Flag",
        description:
          "Placed second overall, solving challenges in binary exploitation, open-source intelligence, and network forensics in a fast-paced competition.",
        writeup: "/blog/teknocom-25",
      },
      {
        title: "NCLP CTF S1",
        organizer: "Noctra Lupra · ID-Networkers",
        recognition: "1st Place",
        category: "Capture The Flag",
        description:
          'Placed first overall after solving more than 50 challenges. Earned the "Specialist" role for standout performance in digital forensics, reverse engineering, and open-source intelligence.',
        writeup: "/blog/nclp-ctf-s1",
      },
    ],
  },
  {
    year: 2023,
    entries: [
      {
        title: "Dekan Cup · PKM-PM",
        organizer: "FILKOM · Brawijaya University",
        recognition: "3rd Place",
        category: "Community Service",
        description:
          'Led a community service team to third place with an e-learning program titled "Cybersecurity Training: Addressing the Dangers of Phishing in the Digital Era for the Community in Jatimulyo Subdistrict."',
      },
    ],
  },
];
