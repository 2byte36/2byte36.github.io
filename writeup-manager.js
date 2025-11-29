#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const POSTS_DIR = path.join(__dirname, 'source', '_posts');

// Pastikan direktori _posts ada
if (!fs.existsSync(POSTS_DIR)) {
  fs.mkdirSync(POSTS_DIR, { recursive: true });
}

// Fungsi untuk format tanggal
function formatDate(date) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  const hours = String(date.getHours()).padStart(2, '0');
  const minutes = String(date.getMinutes()).padStart(2, '0');
  const seconds = String(date.getSeconds()).padStart(2, '0');
  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
}

// Fungsi untuk membuat slug dari judul
function slugify(text) {
  return text
    .toString()
    .toLowerCase()
    .trim()
    .replace(/\s+/g, '-')
    .replace(/[^\w\-]+/g, '')
    .replace(/\-\-+/g, '-');
}

// Fungsi untuk input
function question(query) {
  return new Promise(resolve => rl.question(query, resolve));
}

// CREATE - Buat write-up baru
async function createWriteup() {
  console.log('\n=== CREATE NEW CTF WRITE-UP ===\n');
  
  const title = await question('Challenge Title: ');
  const ctfEvent = await question('CTF Event Name: ');
  const category = await question('Category (Web/Pwn/Crypto/Forensics/Rev/OSINT/Misc): ');
  const difficulty = await question('Difficulty (Easy/Medium/Hard): ');
  const points = await question('Points: ');
  const description = await question('Short Description: ');
  
  const tags = await question('Tags (comma separated, e.g., SQL Injection, XSS): ');
  const tagArray = tags.split(',').map(t => t.trim()).filter(t => t);
  
  const now = new Date();
  const fileName = `${slugify(title)}.md`;
  const filePath = path.join(POSTS_DIR, fileName);
  
  // Template write-up
  const content = `---
title: "${ctfEvent} - ${title}"
date: ${formatDate(now)}
tags: 
  - CTF
  - ${category}
${tagArray.map(tag => `  - ${tag}`).join('\n')}
categories:
  - CTF
  - ${category}
description: "${description}"
cover: false
author: 2byte
sticky: false
toc: true
---

## Challenge Information

- **Challenge Name**: ${title}
- **CTF Event**: ${ctfEvent}
- **Category**: ${category}
- **Difficulty**: ${difficulty}
- **Points**: ${points}
- **Solves**: 
- **Flag**: \`flag{}\`

## Challenge Description

\`\`\`
Paste challenge description here...
\`\`\`

## Initial Reconnaissance

### First Look

Langkah pertama yang saya lakukan adalah...

### Source Code Analysis (if applicable)

\`\`\`python
# Jika ada source code yang diberikan
\`\`\`

## Vulnerability Discovery

### Finding the Weakness

Setelah melakukan analisis, saya menemukan...

### Proof of Concept

\`\`\`bash
# Command atau exploit yang digunakan
\`\`\`

## Exploitation

### Step 1: 

\`\`\`bash
# Detail langkah exploitation
\`\`\`

### Step 2: 

\`\`\`bash
# Commands yang digunakan
\`\`\`

### Step 3: Capturing the Flag

\`\`\`bash
# Final command untuk mendapatkan flag
\`\`\`

## Lessons Learned

Dari challenge ini, saya belajar tentang:

1. 
2. 
3. 

## Mitigation

Untuk mencegah vulnerability ini:

- 
- 
- 

## References

- [Reference 1](https://example.com)
- [Reference 2](https://example.com)

---

**Tags**: ${tagArray.map(t => `#${t.replace(/\s+/g, '')}`).join(' ')}
`;

  fs.writeFileSync(filePath, content);
  console.log(`\n✅ Write-up created successfully: ${fileName}`);
  console.log(`📝 File location: ${filePath}`);
  console.log(`\nYou can now edit the file and add your write-up content.`);
}

// READ - List semua write-up
function listWriteups() {
  console.log('\n=== LIST OF CTF WRITE-UPS ===\n');
  
  const files = fs.readdirSync(POSTS_DIR).filter(f => f.endsWith('.md'));
  
  if (files.length === 0) {
    console.log('No write-ups found.');
    return;
  }
  
  files.forEach((file, index) => {
    const filePath = path.join(POSTS_DIR, file);
    const content = fs.readFileSync(filePath, 'utf-8');
    
    // Extract metadata
    const titleMatch = content.match(/title:\s*"([^"]+)"/);
    const dateMatch = content.match(/date:\s*(.+)/);
    const categoryMatch = content.match(/categories:\s*\n\s*-\s*CTF\s*\n\s*-\s*(.+)/);
    
    console.log(`${index + 1}. ${file}`);
    if (titleMatch) console.log(`   Title: ${titleMatch[1]}`);
    if (dateMatch) console.log(`   Date: ${dateMatch[1]}`);
    if (categoryMatch) console.log(`   Category: ${categoryMatch[1]}`);
    console.log('');
  });
}

// UPDATE - Edit write-up (open in editor)
async function updateWriteup() {
  console.log('\n=== UPDATE CTF WRITE-UP ===\n');
  
  listWriteups();
  
  const fileName = await question('\nEnter filename to edit: ');
  const filePath = path.join(POSTS_DIR, fileName);
  
  if (!fs.existsSync(filePath)) {
    console.log(`❌ File not found: ${fileName}`);
    return;
  }
  
  console.log(`\n📝 Opening ${fileName} in default editor...`);
  console.log(`File location: ${filePath}`);
  console.log(`\nPlease edit the file manually using your preferred text editor.`);
  
  // Untuk auto-open di editor (uncomment jika diperlukan)
  // const { exec } = require('child_process');
  // exec(`${process.env.EDITOR || 'nano'} "${filePath}"`);
}

// DELETE - Hapus write-up
async function deleteWriteup() {
  console.log('\n=== DELETE CTF WRITE-UP ===\n');
  
  listWriteups();
  
  const fileName = await question('\nEnter filename to delete: ');
  const filePath = path.join(POSTS_DIR, fileName);
  
  if (!fs.existsSync(filePath)) {
    console.log(`❌ File not found: ${fileName}`);
    return;
  }
  
  const confirm = await question(`⚠️  Are you sure you want to delete "${fileName}"? (yes/no): `);
  
  if (confirm.toLowerCase() === 'yes' || confirm.toLowerCase() === 'y') {
    fs.unlinkSync(filePath);
    console.log(`✅ Write-up deleted: ${fileName}`);
  } else {
    console.log('❌ Deletion cancelled.');
  }
}

// SEARCH - Cari write-up
async function searchWriteups() {
  console.log('\n=== SEARCH CTF WRITE-UPS ===\n');
  
  const keyword = await question('Enter search keyword (title/category/tag): ');
  const files = fs.readdirSync(POSTS_DIR).filter(f => f.endsWith('.md'));
  
  console.log(`\nSearching for: "${keyword}"\n`);
  
  let found = 0;
  files.forEach((file) => {
    const filePath = path.join(POSTS_DIR, file);
    const content = fs.readFileSync(filePath, 'utf-8');
    
    if (content.toLowerCase().includes(keyword.toLowerCase())) {
      found++;
      const titleMatch = content.match(/title:\s*"([^"]+)"/);
      const categoryMatch = content.match(/categories:\s*\n\s*-\s*CTF\s*\n\s*-\s*(.+)/);
      
      console.log(`${found}. ${file}`);
      if (titleMatch) console.log(`   Title: ${titleMatch[1]}`);
      if (categoryMatch) console.log(`   Category: ${categoryMatch[1]}`);
      console.log('');
    }
  });
  
  if (found === 0) {
    console.log('No matching write-ups found.');
  } else {
    console.log(`Found ${found} write-up(s).`);
  }
}

// Main menu
async function mainMenu() {
  console.log('\n╔════════════════════════════════════════╗');
  console.log('║   CTF WRITE-UP MANAGEMENT SYSTEM      ║');
  console.log('╚════════════════════════════════════════╝\n');
  console.log('1. Create new write-up');
  console.log('2. List all write-ups');
  console.log('3. Update write-up');
  console.log('4. Delete write-up');
  console.log('5. Search write-ups');
  console.log('6. Exit\n');
  
  const choice = await question('Choose an option (1-6): ');
  
  switch(choice) {
    case '1':
      await createWriteup();
      break;
    case '2':
      listWriteups();
      break;
    case '3':
      await updateWriteup();
      break;
    case '4':
      await deleteWriteup();
      break;
    case '5':
      await searchWriteups();
      break;
    case '6':
      console.log('\n👋 Goodbye!\n');
      rl.close();
      process.exit(0);
      return;
    default:
      console.log('\n❌ Invalid option. Please choose 1-6.');
  }
  
  // Kembali ke menu utama
  await mainMenu();
}

// Jalankan program
mainMenu().catch(error => {
  console.error('Error:', error);
  rl.close();
});
