# WannaCry YARA Static Detection Lab

<p align="center">
  <strong>Creating and Testing a Safe WannaCry-Style YARA Rule on Kali Linux</strong>
</p>

---

## Overview

This lab demonstrates how YARA can be used to identify malware-related indicators through static pattern matching.

Instead of downloading or handling live ransomware, I created a harmless training file containing WannaCry-related strings. I then wrote a custom YARA rule, scanned the training file, confirmed a successful match, and tested the same rule against a clean file to verify that it did not produce a false positive.

> **Safety Notice:** This repository does not contain real WannaCry ransomware or any executable malware. The sample file is harmless text created only to test the YARA rule.

## Lab Objectives

- Install and verify YARA on Kali Linux.
- Create an organized lab directory.
- Write a WannaCry-style YARA rule with four detection patterns.
- Add metadata to document the rule.
- Create a harmless training sample containing the detection strings.
- Run YARA and confirm a successful match.
- Test the rule against a clean file.
- Explain the purpose of YARA strings, modifiers, and conditions.
- Document the lab with screenshots for a cybersecurity portfolio.

## Skills Demonstrated

- Linux command-line navigation
- Package installation with APT
- File creation and editing
- Writing YARA rules
- Static malware detection
- Pattern matching
- Rule validation
- False-positive testing
- Safe malware-analysis practices
- Technical documentation

## Lab Environment

| Component | Details |
|---|---|
| Operating System | Kali Linux |
| Detection Tool | YARA |
| Rule File | `wannacry.yara` |
| Training Sample | `wannacry_training_sample.txt` |
| Clean Test File | `clean_test.txt` |
| Rule Name | `WannaCry_Training_Demo` |
| Working Directory | `~/yara-wannacry-lab` |
| Analysis Type | Static pattern matching |
| Malware Handling | No live malware used |

---

# Detection Patterns

The rule searches for four WannaCry-related strings:

| Identifier | Pattern | Modifier | Purpose |
|---|---|---|---|
| `$pattern1` | `WannaCry` | `nocase` | Detects the WannaCry family name |
| `$pattern2` | `WanaCrypt0r` | `nocase` | Detects a known WannaCry-related name |
| `$pattern3` | `tasksche.exe` | `nocase` | Detects a filename associated with WannaCry activity |
| `$pattern4` | `WNcry@2ol7` | `nocase` | Detects another WannaCry-related string |

The `nocase` modifier allows the strings to match regardless of uppercase or lowercase letters.

---

# Lab Procedure

## Step 1: Install and Verify YARA

I updated the Kali Linux package list and installed YARA:

```bash
sudo apt update
sudo apt install -y yara
```

I verified that YARA installed correctly:

```bash
yara --version
```

<p align="center">
  <img src="https://github.com/user-attachments/assets/79bd3faf-35a6-4ce4-9020-2f77e00c4e73"
       alt="Linux forensic investigation evidence"
       width="800">
</p>

<p align="center">
  <em>Figure 1: YARA installation verified with the `yara --version` command.</em>
</p>

---

## Step 2: Create the Lab Directory

I created a separate folder for the rule and test files:

```bash
mkdir -p ~/yara-wannacry-lab
cd ~/yara-wannacry-lab
pwd
```

The `pwd` command confirmed that I was working inside:

```text
/home/kali/yara-wannacry-lab
```

<p align="center">
  <img src="https://github.com/user-attachments/assets/c6786c56-0d29-4f55-a17f-5cd116965296"
       alt="Linux forensic investigation evidence"
       width="800">
</p>

<p align="center">
  <em>Figure 2: The `yara-wannacry-lab` directory created and opened in Kali Linux.</em>
</p>

---

## Step 3: Create the WannaCry YARA Rule

I created the YARA rule file:

```bash
nano wannacry.yara
```

I added the following rule:

```yara
rule WannaCry_Training_Demo
{
    meta:
        description = "Training rule for WannaCry-related indicators"
        author = "Dontrell"
        date = "2026-07-04"
        purpose = "Safe YARA lab using a harmless test file"

    strings:
        $pattern1 = "WannaCry" nocase
        $pattern2 = "WanaCrypt0r" nocase
        $pattern3 = "tasksche.exe" nocase
        $pattern4 = "WNcry@2ol7" nocase

    condition:
        any of them
}
```

I saved the file in Nano:

```text
Ctrl + X
Y
Enter
```

I then displayed the saved rule:

```bash
cat wannacry.yara
```

<p align="center">
  <img src="https://github.com/user-attachments/assets/de8f11e8-cc75-4916-aeaa-c1dfc1f17e1a"
       alt="Linux forensic investigation evidence"
       width="800">
</p>

<p align="center">
  <em>Figure 3: The custom `WannaCry_Training_Demo` YARA rule containing four detection patterns.</em>
</p>

### Rule Explanation

- `rule WannaCry_Training_Demo` assigns the rule name.
- The `meta` section documents the purpose, author, and date.
- The `strings` section defines the four patterns YARA searches for.
- The `nocase` modifier makes each pattern case-insensitive.
- The condition `any of them` causes the rule to match when at least one pattern is found.

---

## Step 4: Create the Harmless Training Sample

Instead of using real ransomware, I created a text file containing the four detection patterns:

```bash
cat > wannacry_training_sample.txt <<'EOF'
This is a harmless training file for a YARA lab.
It is not malware and it does not execute anything.
WannaCry
WanaCrypt0r
tasksche.exe
WNcry@2ol7
EOF
```

I displayed the file:

```bash
cat wannacry_training_sample.txt
```

<p align="center">
  <img src="https://github.com/user-attachments/assets/261ebf39-25ab-4983-b455-32f6e08cda3c"
       alt="Linux forensic investigation evidence"
       width="800">
</p>

<p align="center">
  <em>Figure 4: The harmless training sample containing the four WannaCry-related strings.</em>
</p>

---

## Step 5: Run the YARA Rule

I scanned the harmless training file:

```bash
yara wannacry.yara wannacry_training_sample.txt
```

The result was:

```text
WannaCry_Training_Demo wannacry_training_sample.txt
```

This confirmed that the YARA rule detected at least one of the defined patterns.

<p align="center">
  <img src="https://github.com/user-attachments/assets/f9cde073-c09f-4cc9-b6e5-e0a8988b91a7"
       alt="Linux forensic investigation evidence"
       width="800">
</p>

<p align="center">
  <em>Figure 5: The `WannaCry_Training_Demo` rule successfully matching the harmless training sample.</em>
</p>

---

## Step 6: Test a Clean File

I created a clean text file that did not contain any of the training indicators:

```bash
echo "This file does not contain the training indicators." > clean_test.txt
```

I scanned it with the same YARA rule:

```bash
yara wannacry.yara clean_test.txt
```

YARA returned no output, which confirmed that the clean file did not match the rule.

<p align="center">
  <img src="https://github.com/user-attachments/assets/f9cde073-c09f-4cc9-b6e5-e0a8988b91a7"
       alt="Linux forensic investigation evidence"
       width="800">
</p>

<p align="center">
  <em>Figure 6: The clean test file producing no YARA match.</em>
</p>

---

# Optional Rule Improvement

The original condition matches when any one of the four patterns is found:

```yara
condition:
    any of them
```

To make the rule stricter, I could require at least two patterns:

```yara
condition:
    2 of ($pattern*)
```
This change would reduce the chance that a file matches because it contains only one common or unrelated string.

<p align="center">
  <img src="https://github.com/user-attachments/assets/dc2c0282-159e-4831-b87e-d336200b7a19"
       alt="Linux forensic investigation evidence"
       width="800">
</p>

<p align="center">
  <em>Figure 7: The WannaCry training rule updated to require at least two of the four defined patterns.</em>
</p>
<br><br>

<p align="center">
  <img src="https://github.com/user-attachments/assets/1d166d8a-105a-4f4b-88df-09b81df47f1b"
       alt="Linux forensic investigation evidence"
       width="800">
</p>

<p align="center">
  <em>Figure 8: The stricter WannaCry YARA rule successfully matching `wannacry_training_sample.txt`.</em>
</p>
<br><br>

<p align="center">
  <img src="https://github.com/user-attachments/assets/a493cf72-be49-4e0e-b1eb-926d08db978a"
       alt="Linux forensic investigation evidence"
       width="800">
</p>

<p align="center">
  <em>Figure 9: The stricter WannaCry YARA rule producing no match when scanning `clean_test.txt`.</em>
</p>

---

# Challenge Question Answers

## Challenge Question 4: Prompt Used to Create the Rule

```text
Create a beginner-friendly WannaCry YARA example for a cybersecurity lab.
Use four string patterns, include a meta section, and make the condition
match if any pattern is found. Do not provide instructions to run malware.
```

This prompt was effective because it requested a specific malware family, four indicators, a complete YARA rule structure, and a safe detection-focused exercise.

## Challenge Question 5: Successful YARA Result

```text
WannaCry_Training_Demo wannacry_training_sample.txt
```

This output means the rule matched the harmless training file because at least one WannaCry-related pattern was present.

---

# Discussion Questions

## How would the prompt be changed for SpyEye?

I would replace the WannaCry family name and indicators with SpyEye-related patterns:

```text
Create a beginner-friendly SpyEye YARA example for a cybersecurity lab.
Use four string patterns related to SpyEye indicators, include a meta section,
and make the condition match if any pattern is found.
Keep it safe and do not include instructions to run malware.
```

## Explain `$pattern1`

```yara
$pattern1 = "WannaCry" nocase
```

- `$pattern1` is the identifier assigned to the first string.
- `"WannaCry"` is the text YARA searches for.
- `nocase` makes the search case-insensitive.
- Because the rule uses `any of them`, finding `$pattern1` alone is enough to trigger a match.

---

# Results

| Test | Expected Result | Outcome |
|---|---|---|
| Verify YARA installation | Version number displayed | Successful |
| Confirm lab directory | `/home/kali/yara-wannacry-lab` | Successful |
| Display the rule | Four patterns visible | Successful |
| Scan training sample | Rule name and file name displayed | Successful |
| Scan clean file | No output | Successful |
| Review safe workflow | No real malware handled | Successful |

---

# Troubleshooting

## `yara: command not found`

```bash
sudo apt update
sudo apt install -y yara
```

## No output after scanning the training file

Check the file contents:

```bash
cat wannacry_training_sample.txt
```

Confirm that at least one rule pattern appears in the file.

## `could not open file`

Confirm the current location and filenames:

```bash
pwd
ls
```

Linux filenames are case-sensitive.

## Syntax error

Open the rule and check:

- Curly braces
- Quotation marks
- The `strings:` section
- The `condition:` section
- `$` before each string identifier

---

# Security Relevance

This lab demonstrates the basic workflow used by malware analysts and threat hunters:

1. Identify useful indicators.
2. Convert those indicators into a YARA rule.
3. Test the rule against a known matching sample.
4. Test the rule against a clean file.
5. Refine the condition to reduce false positives.
6. Document the detection logic and results.

YARA can be used to detect:

- Malware family names
- Suspicious filenames
- Embedded commands
- URLs and IP addresses
- File headers
- Registry paths
- Hexadecimal byte sequences
- Regular-expression patterns
- Combinations of related indicators

# Safety Practices

- Do not download or execute real ransomware on a personal computer.
- Use a harmless training file for portfolio work.
- Do not upload malware samples to GitHub.
- Use disposable, isolated virtual machines when an instructor provides real samples.
- Disable shared folders, drag-and-drop, and shared clipboard before handling live malware.
- Use host-only or isolated networking.
- Revert or delete the VM after a real malware-analysis exercise.
- YARA scanning is static analysis and does not require executing a sample.

---

# Key Takeaways

- YARA detects files by matching defined patterns.
- The `nocase` modifier allows case-insensitive detection.
- `any of them` causes the rule to match when one pattern is present.
- A stricter condition can reduce false positives.
- Testing both matching and nonmatching files is important.
- Safe simulated samples can demonstrate the complete YARA workflow without handling live malware.
- This lab is best described as a static detection and rule-validation exercise.

---

> **Authorized Educational Use:** This repository documents a safe static-detection lab. It contains no ransomware, malicious executable, or instructions to execute malware.
