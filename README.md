# Automated-Phishing-Triage-
Users inside small organizations constantly click suspicious links, and internal IT teams lack a fast way to triage or dissect reported phishing emails.
# Automated Phishing Triage and Simulation Pipeline

**A Cyber Ready Clinic Capstone Project**

## Project Overview

Automated Phishing Triage is a Python-based cybersecurity tool designed to help small businesses, nonprofit organizations (NPOs), and their IT service providers investigate suspicious email messages.

Many smaller organizations lack dedicated cybersecurity personnel or sophisticated email security monitoring systems. When employees report suspicious emails, determining whether a message represents a security threat can be time-consuming and technically challenging.

This project addresses that problem by automating the initial examination of suspicious email messages, extracting potential indicators of compromise (IoCs), and producing structured reports to support incident triage and response.

The goal is to provide an accessible, low-cost security assessment tool that can be used by nonprofit leadership, IT support personnel, managed service providers (MSPs), and cybersecurity students.

## The Problem

Phishing remains a common method attackers use to compromise organizational accounts, steal credentials, distribute malware, and initiate business email compromise (BEC).

Small organizations face several challenges:

- Limited cybersecurity staffing and budgets.
- Difficulty analyzing suspicious email headers and hyperlinks.
- Lack of centralized phishing investigation tools.
- Inconsistent reporting and documentation of suspicious messages.
- Dependence on outside IT providers for initial incident investigations.

An organization may have email security protections in place and still receive convincing phishing messages.

**The central question this project addresses is:**

*When an employee reports a suspicious email, how can a small organization quickly determine what makes the message suspicious and what actions should be taken?*

## Project Objectives

The application is designed to:

1. Accept suspicious email messages in `.eml` format.
2. Extract and examine email headers and authentication results.
3. Identify sender and Reply-To address discrepancies.
4. Extract hyperlinks, including misleading or hidden destinations.
5. Identify attachments and calculate SHA-256 cryptographic hashes.
6. Identify potential phishing indicators using local detection rules.
7. Integrate open-source threat intelligence services in future phases.
8. Assign explainable risk scores and generate incident reports.
9. Provide interfaces accessible to technical and nontechnical users.
10. Support cybersecurity awareness training using simulated phishing emails.

## System Architecture

The project uses a shared Python analysis engine that will support both desktop and local browser interfaces.

```text
Suspicious Email (.eml)
         |
         v
   Email Ingestion
         |
         v
   Python Email Parser
         |
         +---- Header Analysis
         |
         +---- Sender / Reply-To Comparison
         |
         +---- URL and Hyperlink Extraction
         |
         +---- Attachment Identification
         |
         +---- SHA-256 Hash Calculation
         |
         v
   Local Detection Rules
         |
         v
   Structured Findings
         |
         v
   JSON Incident Report
         |
         v
   Future Extensions
         |
         +---- Threat Intelligence APIs
         +---- Risk Scoring
         +---- Desktop Interface
         +---- Browser Interface
         +---- SIEM Integration
```

## Phase 1 — Email Analysis Engine

**Status: Initial implementation**

Phase 1 establishes the shared Python analysis engine and command-line interface.

### Current Capabilities

| Capability | Description |
|---|---|
| EML ingestion | Reads suspicious email files |
| Header extraction | Extracts common email headers |
| Authentication inspection | Reads available SPF, DKIM, and DMARC results |
| Reply-To comparison | Flags differences between sender and reply addresses |
| Hyperlink extraction | Identifies URLs embedded in messages |
| Link mismatch detection | Detects differences between displayed URLs and destinations |
| Attachment analysis | Identifies attachments and calculates SHA-256 hashes |
| Local detection | Flags selected suspicious characteristics |
| JSON reporting | Produces structured machine-readable results |
| Automated testing | Tests representative email-analysis behavior |

**Important:** Phase 1 identifies suspicious characteristics. It does not independently establish that an email is malicious.

## Project Directory Structure

```text
automated-phishing-triage/
|
|-- phishing_triage/
|   |-- __init__.py
|   |-- analyzer.py
|   |-- cli.py
|
|-- samples/
|   |-- legitimate_notice.eml
|   |-- suspicious_login.eml
|   |-- invoice_attachment.eml
|
|-- reports/
|
|-- tests/
|   |-- test_analyzer.py
|
|-- desktop/
|-- browser/
|
|-- requirements.txt
|-- .gitignore
|-- README.md
```

## Installation

### Prerequisites

- Windows, Linux, or macOS
- Python 3.10 or newer
- A terminal or PowerShell
- No external API keys required for Phase 1

### 1. Download the Project

Clone the GitHub repository:

```bash
git clone https://github.com/YOUR-USERNAME/automated-phishing-triage.git
```

Or download the repository as a ZIP file and extract it.

Replace `YOUR-USERNAME` with the actual GitHub account name.

### 2. Open the Project Directory

```bash
cd automated-phishing-triage
```

### 3. Verify Python

```bash
python --version
```

### 4. Run a Sample Analysis

```bash
python -m phishing_triage.cli samples/suspicious_login.eml --output reports/suspicious_login.json
```

The program examines the sample email and creates a JSON report in the `reports` directory.

### 5. View the Results

Open:

```text
reports/suspicious_login.json
```

The report contains extracted email information and findings produced by the analysis engine.

### 6. Run Automated Tests

```bash
python -m unittest discover -s tests -v
```

The tests help verify that email parsing and detection features work as intended.

## Example Phishing Investigation

Consider a nonprofit employee receiving an email claiming to be from an organization's IT support provider.

**Subject:** URGENT: Your Microsoft 365 Account Will Be Disabled

**From:** IT Support &lt;support@nonprofit-help.example&gt;

**Reply-To:** verification@external-service.example

**Message:** Your account will be suspended unless you verify your credentials immediately.

The message includes a hyperlink labeled as an account verification page.

The application can examine the message for:

- Differences between the From and Reply-To addresses.
- Misleading hyperlink destinations.
- Available authentication results.
- Embedded URLs and attachments.
- Other locally detectable suspicious patterns.

The findings are documented for review by the organization's IT personnel or managed service provider.

All demonstration messages use fictional or controlled test data.

## Planned Development

### Phase 2 — Threat Intelligence and Risk Scoring

Integrate external intelligence sources such as:

- VirusTotal API for URL and file-hash reputation.
- AbuseIPDB for relevant public IP reputation.
- YARA rules for selected content and attachment patterns.

Develop explainable risk scoring and incident-ticket generation.

### Phase 3 — Graphical User Interfaces

Create two interfaces using the shared Python analysis engine:

**Desktop Interface:** A standalone Windows application for local email analysis.

**Browser Interface:** A local Streamlit application allowing users to upload `.eml` files and review results without using command-line tools.

### Phase 4 — Phishing Simulation and Training

Develop a library of safe simulated phishing messages demonstrating common techniques, including:

- Display-name spoofing.
- Credential harvesting pretexts.
- Misleading hyperlinks.
- Invoice fraud scenarios.
- Suspicious attachments.
- Business email compromise scenarios.

These samples will support awareness training and repeatable testing.

### Phase 5 — Reporting and SIEM Integration

Expand reporting capabilities to include:

- Risk-scored incident tickets.
- Severity classifications.
- Recommended response actions.
- Exportable reports.
- Optional Wazuh or Elastic integration
