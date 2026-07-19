# WannaCry Indicator YARA Rule Validation Lab

<p align="center">
  <strong>Creating and Testing a Safe WannaCry-Inspired YARA Rule on Kali Linux</strong>
</p>

---

## Overview

This lab demonstrates how YARA can identify defined malware-related indicators through static pattern matching.

Instead of downloading or handling live ransomware, I created a harmless text file containing strings associated with WannaCry. I then wrote a custom YARA rule, scanned the training file, confirmed a successful match, and tested the same rule against a separate benign file that did not contain the defined indicators.

> **Detection Scope:** This is a beginner rule-validation exercise, not a production malware signature. The rule reports the presence of selected strings but does not prove that a matched file is WannaCry or that it is malicious.

> **Safety Notice:** This repository does not contain WannaCry ransomware, executable malware, or instructions to run malware. The sample files are harmless text files created only to test the YARA rule.

## Lab Objectives

- Install and verify YARA on Kali Linux.
- Create an organized lab directory.
- Write a WannaCry-inspired YARA rule with four static patterns.
- Add metadata to document the rule.
- Create a harmless training sample containing the detection strings.
- Run YARA and confirm a successful match.
- Test the rule against a benign nonmatching file.
- Explain the purpose of YARA strings, modifiers, and conditions.
- Refine the condition to reduce false-positive risk.
- Document the lab with screenshots for a cybersecurity portfolio.

## Skills Demonstrated

- Linux command-line navigation
- Package installation with APT
- File and directory creation
- Writing basic YARA rules
- Static indicator matching
- Case-insensitive text matching
- Rule validation
- Positive and negative testing
- False-positive risk analysis
- Safe malware-analysis practices
- Technical documentation

## Lab Environment

| Component | Details |
|---|---|
| Operating System | Kali Linux |
| Detection Tool | YARA |
| Rule File | `wannacry.yara` |
| Training Sample | `wannacry_training_sample.txt` |
| Benign Test File | `clean_test.txt` |
| Rule Name | `WannaCry_Training_Demo` |
| Working Directory | `~/yara-wannacry-lab` |
| Analysis Type | Static pattern matching |
| Malware Handling | No live malware used |

---

## Detection Patterns

The training rule searches for four strings associated with WannaCry:

| Identifier | Pattern | Modifier | Training Purpose |
|---|---|---|---|
| `$pattern1` | `WannaCry` | `nocase` | Matches a commonly used WannaCry family name |
| `$pattern2` | `WanaCrypt0r` | `nocase` | Matches a name associated with the ransomware and its Registry artifacts |
| `$pattern3` | `tasksche.exe` | `nocase` | Matches a filename associated with documented WannaCry activity |
| `$pattern4` | `WNcry@2ol7` | `nocase` | Matches a string used as the password for an embedded archive in analyzed samples |

The `nocase` modifier allows each text string to match without requiring identical uppercase and lowercase letters.

These strings are useful for demonstrating YARA syntax, but several can also appear in security reports, research notes, or harmless training content. A match should therefore be interpreted as an indicator requiring investigation rather than proof of malware.

---

## Lab Procedure

### Step 1: Install and Verify YARA

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
       alt="Kali Linux terminal showing the installed YARA version"
       width="800">
</p>

<p align="center">
  <em>Figure 1: YARA installation verified with the `yara --version` command.</em>
</p>

---

### Step 2: Create the Lab Directory

I created a separate directory for the rule and test files:

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
       alt="Kali Linux terminal showing creation of the yara-wannacry-lab directory and its full path"
       width="800">
</p>

<p align="center">
  <em>Figure 2: The `yara-wannacry-lab` directory created and opened in Kali Linux.</em>
</p>

---

### Step 3: Create the WannaCry Training Rule

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
       alt="Kali Linux terminal displaying the WannaCry Training Demo YARA rule and its four strings"
       width="800">
</p>

<p align="center">
  <em>Figure 3: The custom `WannaCry_Training_Demo` YARA rule containing four detection patterns.</em>
</p>

#### Rule Explanation

- `rule WannaCry_Training_Demo` assigns the rule name.
- The optional `meta` section documents the purpose, author, and date.
- The `strings` section defines the four text patterns YARA searches for.
- The `nocase` modifier makes each text comparison case-insensitive.
- The required `condition` section determines whether the rule matches.
- `any of them` causes the rule to match when at least one defined string is present.

Because only one string is required, this version is useful for learning and validation but is too broad to treat as a production WannaCry signature.

---

### Step 4: Create the Harmless Training Sample

Instead of using real ransomware, I created a text file containing all four detection patterns:

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
       alt="Kali Linux terminal displaying the harmless training file and its four WannaCry-related strings"
       width="800">
</p>

<p align="center">
  <em>Figure 4: The harmless training sample containing the four WannaCry-related strings.</em>
</p>

---

### Step 5: Run the YARA Rule

I scanned the harmless training file:

```bash
yara wannacry.yara wannacry_training_sample.txt
```

The result was:

```text
WannaCry_Training_Demo wannacry_training_sample.txt
```

This confirmed that the `WannaCry_Training_Demo` rule matched the training file because at least one defined string was present.

<p align="center">
  <img src="https://github.com/user-attachments/assets/f9cde073-c09f-4cc9-b6e5-e0a8988b91a7"
       alt="Kali Linux terminal showing the WannaCry Training Demo rule matching the harmless training file"
       width="800">
</p>

<p align="center">
  <em>Figure 5: The `WannaCry_Training_Demo` rule successfully matching the harmless training sample.</em>
</p>

To display the matching string identifiers, values, and offsets during additional testing, I could also use:

```bash
yara -s wannacry.yara wannacry_training_sample.txt
```

---

### Step 6: Test a Benign Nonmatching File

I created a benign text file that did not contain any of the four defined indicators:

```bash
echo "This file contains ordinary text for a negative YARA test." > clean_test.txt
```

I displayed the file before scanning it:

```bash
cat clean_test.txt
```

I then scanned it with the same YARA rule:

```bash
yara wannacry.yara clean_test.txt
```

YARA returned no match output because the file did not contain any of the defined strings.

This negative test showed that the rule did not match this specific benign file. It did not prove that the rule was free from false positives across other benign files.

> **Screenshot note:** The original README reused the successful-match screenshot for this step. That duplicate image was removed because it did not demonstrate the clean-file result. Add a new screenshot only if it clearly shows the `clean_test.txt` command and the absence of a rule match.

---

## Rule Refinement Test

### Require at Least Two Indicators

The original condition matches when any one of the four strings is found:

```yara
condition:
    any of them
```

To make the rule more selective, I changed the condition to require at least two strings whose identifiers begin with `$pattern`:

```yara
condition:
    2 of ($pattern*)
```

The refined rule became:

```yara
rule WannaCry_Training_Demo
{
    meta:
        description = "Training rule for multiple WannaCry-related indicators"
        author = "Dontrell"
        date = "2026-07-04"
        purpose = "Safe YARA lab using harmless test files"

    strings:
        $pattern1 = "WannaCry" nocase
        $pattern2 = "WanaCrypt0r" nocase
        $pattern3 = "tasksche.exe" nocase
        $pattern4 = "WNcry@2ol7" nocase

    condition:
        2 of ($pattern*)
}
```

Requiring multiple related strings reduces the chance of matching a file that contains only one family name or filename. It still does not make the rule a complete production signature.

<p align="center">
  <img src="https://github.com/user-attachments/assets/dc2c0282-159e-4831-b87e-d336200b7a19"
       alt="Kali Linux terminal displaying the refined YARA rule requiring two pattern matches"
       width="800">
</p>

<p align="center">
  <em>Figure 6: The WannaCry training rule updated to require at least two of the four defined patterns.</em>
</p>

The training file still matched because it contained all four strings:

<p align="center">
  <img src="https://github.com/user-attachments/assets/1d166d8a-105a-4f4b-88df-09b81df47f1b"
       alt="Kali Linux terminal showing the refined two-pattern rule matching the training file"
       width="800">
</p>

<p align="center">
  <em>Figure 7: The refined WannaCry YARA rule successfully matching `wannacry_training_sample.txt`.</em>
</p>

The benign test file still produced no match:

<p align="center">
  <img src="https://github.com/user-attachments/assets/a493cf72-be49-4e0e-b1eb-926d08db978a"
       alt="Kali Linux terminal showing no YARA rule match for clean_test.txt after the condition was refined"
       width="800">
</p>

<p align="center">
  <em>Figure 8: The refined WannaCry YARA rule producing no match when scanning `clean_test.txt`.</em>
</p>

---

## Challenge Question Answers

### Challenge Question 4: Prompt Used to Create the Rule

```text
Create a beginner-friendly WannaCry-inspired YARA example for an authorized
cybersecurity lab. Use four verified static strings, include a meta section,
and make the initial condition match if any pattern is found. Use only a
harmless text sample and do not provide instructions to execute malware.
```

This prompt was effective because it requested a specific threat family, a complete rule structure, multiple static indicators, and a safe detection-focused exercise.

The indicators still need to be validated against reputable technical sources before use outside a classroom exercise.

### Challenge Question 5: Successful YARA Result

```text
WannaCry_Training_Demo wannacry_training_sample.txt
```

This output means the rule matched the harmless training file because the rule's condition was satisfied. It does not mean that the text file is ransomware.

---

## Discussion Questions

### How Would the Prompt Be Changed for SpyEye?

I would replace the WannaCry references with verified SpyEye-related indicators while preserving the harmless testing method:

```text
Create a beginner-friendly SpyEye-inspired YARA example for an authorized
cybersecurity lab. Use four static indicators verified through reputable
technical sources, include a meta section, and require at least two indicators
for a match. Use only a harmless text sample and do not include instructions
to download or execute malware.
```

A rule should not use unverified strings simply because they are labeled as belonging to a malware family.

### Explain `$pattern1`

```yara
$pattern1 = "WannaCry" nocase
```

- `$pattern1` is the identifier assigned to the first text string.
- `"WannaCry"` is the text YARA searches for.
- `nocase` makes the comparison case-insensitive.
- In the original rule, finding `$pattern1` alone was enough to trigger `any of them`.
- In the refined rule, `$pattern1` must be accompanied by at least one other `$pattern*` string.

---

## Results

| Test | Expected Result | Outcome |
|---|---|---|
| Verify YARA installation | Version number displayed | Successful |
| Confirm lab directory | `/home/kali/yara-wannacry-lab` displayed | Successful |
| Display the original rule | Four patterns and `any of them` visible | Successful |
| Scan the training sample | Rule name and file name displayed | Successful |
| Scan the benign test file | No rule-match output | Successful |
| Apply the refined condition | `2 of ($pattern*)` visible | Successful |
| Retest the training sample | Refined rule still matches | Successful |
| Retest the benign file | No rule-match output | Successful |
| Review safe workflow | No live malware handled | Successful |

## Troubleshooting

### `yara: command not found`

Install YARA and verify the installation:

```bash
sudo apt update
sudo apt install -y yara
yara --version
```

### No Output After Scanning the Training File

Check the file contents:

```bash
cat wannacry_training_sample.txt
```

Confirm that at least one string appears when using the original rule or at least two strings appear when using the refined rule.

Check which rule version is currently saved:

```bash
cat wannacry.yara
```

### `could not open file`

Confirm the current location and filenames:

```bash
pwd
ls -l
```

Linux filenames are case-sensitive.

### Syntax Error

Open the rule and check:

- Opening and closing curly braces
- Quotation marks
- The spelling of `meta`, `strings`, and `condition`
- The `$` before each string identifier
- Whether the condition references defined identifiers
- Whether `2 of ($pattern*)` matches the identifier prefix used in the rule
- Whether the file was saved before running YARA

### Too Many Matches

The original `any of them` condition is broad. A file containing only the word `WannaCry` could match even if it were a harmless report.

Possible refinements include:

- Require two or more indicators.
- Add more distinctive strings.
- Use `ascii wide` when appropriate for the expected file format.
- Add file-type or file-size conditions.
- Use PE-module characteristics when scanning Windows executables.
- Test the rule against a larger collection of representative benign files.
- Compare results with trusted threat-intelligence and malware-analysis sources.

---

## Security Relevance

This lab demonstrates a basic rule-development workflow used in malware analysis and threat hunting:

1. Identify indicators from reputable technical analysis.
2. Convert the indicators into a YARA rule.
3. Test the rule against a known matching sample.
4. Test the rule against benign nonmatching files.
5. Review which strings caused the match.
6. Refine the condition to reduce false-positive risk.
7. Document the detection logic, limitations, and results.

YARA can evaluate:

- Malware-family strings
- Suspicious filenames
- Embedded commands
- URLs and IP addresses
- File headers and magic bytes
- Registry paths
- Hexadecimal byte sequences
- Regular-expression patterns
- Import names
- Mutex names
- Combinations of related indicators

A production rule should be tested against known malicious samples and a broad benign dataset. It should also be reviewed whenever the malware family changes or new variants appear.

## Safety Practices

- Do not download or execute ransomware on a personal computer.
- Do not upload malware samples to GitHub.
- Use harmless training files for portfolio demonstrations.
- Use only legally obtained samples in authorized malware-analysis environments.
- Use disposable, isolated virtual machines when an instructor provides real samples.
- Disable shared folders, drag-and-drop, shared clipboard, and unnecessary device sharing before handling live malware.
- Use host-only or otherwise isolated networking unless the exercise specifically requires controlled network access.
- Record hashes and preserve original samples before analysis.
- Revert or destroy the analysis VM according to the lab procedure after handling live malware.
- Remember that YARA scanning is static analysis and does not require executing a sample.

## Key Takeaways

- YARA reports objects that satisfy defined rule conditions.
- The `nocase` modifier makes text matching case-insensitive.
- `any of them` matches when at least one defined string is present.
- `2 of ($pattern*)` requires at least two strings with the matching identifier prefix.
- A successful string match does not prove that a file is malicious.
- Testing one benign file is a useful negative test but is not enough to establish a low false-positive rate.
- Stronger detection requires multiple distinctive indicators and broader validation.
- Safe text samples can demonstrate YARA rule development without handling live malware.
- This lab is best described as a static indicator-matching and rule-validation exercise.

---

> **Authorized Educational Use:** This repository documents a safe static-detection lab. It contains no ransomware, malicious executable, or instructions to execute malware.
