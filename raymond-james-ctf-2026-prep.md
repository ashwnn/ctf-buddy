# Raymond James CTF 2026 - Technical Prep

## Expected Format

- Hybrid CTF with:
  - Mini-Jeopardy technical questions
  - Live attack/defend between teams
- Historically mostly red team with some blue team
- 18 teams expected
- One CTF-connected device per team member

## Likely Challenge Areas

### 1. Forensics and PCAP Analysis
High priority.

Practice:
- Wireshark / tshark
- TCP stream reconstruction
- HTTP, DNS, USB HID traffic
- File carving
- `binwalk`, `foremost`, `strings`, `exiftool`
- Steganography
- Memory and disk triage
- Encodings and data transformations

### 2. Web Exploitation
High priority.

Practice:
- Burp Suite
- SQL injection
- Command injection
- IDOR / access control
- SSRF
- LFI / path traversal
- File upload flaws
- Session/auth weaknesses
- Content and path discovery
- Rapid source-code review

### 3. Reverse Engineering and Malware
Practice:
- Ghidra
- `file`, `strings`, `objdump`, `readelf`
- x86/x64 basics
- GDB / pwndbg
- PowerShell and VBA analysis
- Static malware triage
- IOC/config extraction

### 4. Attack / Defend
Very important for 2026.

Be able to:
- Enumerate an unknown service quickly
- Exploit opposing services
- Identify the vulnerable code path
- Patch your own service without breaking it
- Maintain availability
- Monitor incoming attacks

Useful tools:
- `ss`
- `tcpdump`
- `journalctl`
- `ps`
- `lsof`
- `systemctl`
- `iptables` / `nftables`
- Web/server logs
- `diff`

### 5. Scripting / Automation
Be comfortable writing short Python or Bash scripts quickly.

Focus on:
- Parsing files and PCAP-derived data
- Repeated exploitation
- Brute-force/search tasks
- Parallel execution
- Protocol interaction
- Automating repetitive challenge steps

### 6. Crypto / Encoding
Focus on common CTF primitives:

- XOR
- Base encodings
- Substitution / Vigenere
- Book ciphers
- Hashes
- Weak RSA
- Weak/random key issues
- CyberChef workflows

### 7. Misc / Physical Challenges
Expect unconventional tasks.

Previous Raymond James competitions have included:
- Magnetic-stripe recovery
- Physical-security puzzles
- Unusual protocol analysis
- Programming/automation challenges

## Recommended Local Toolset

Prepare your laptop before the event:

- Kali or equivalent Linux VM
- Burp Suite
- Wireshark / tshark
- Ghidra
- GDB + pwndbg
- CyberChef offline
- jadx / apktool
- oletools
- binwalk
- exiftool
- hashcat / John
- nmap
- ffuf / feroxbuster
- sqlmap
- netcat / socat
- Python
- Local cheatsheets and references

Assume Internet access may be limited or unavailable. Keep tools, wordlists, documentation, and references local.

## Prep Priority

Recommended order:

1. Web exploitation
2. PCAP / forensics
3. Attack/defend service exploitation and patching
4. Reverse engineering / malware
5. Python/Bash automation
6. Crypto / encoding
7. Misc / physical

For your role, focus primarily on:

**Web + network/forensics + attack/defend**
