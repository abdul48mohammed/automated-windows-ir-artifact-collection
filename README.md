# automated-windows-ir-artifact-collection
Python-based automated incident response framework for collecting Windows forensic artifacts
# Automated Windows Incident Response Artifact Collection

## Overview
This repository contains the implementation of a lightweight automated incident response framework developed as part of an MSc Cybersecurity dissertation.

The framework automates the collection of critical Windows forensic artifacts, including:
- Event logs
- Registry information
- Running processes
- Network connections
- System metadata

It is designed to improve speed, consistency, and evidential reliability during the early stages of incident response.

## Technology
- Python 3
- Windows OS
- SHA-256 hashing for integrity validation

## How to Run

1. Ensure Python 3 is installed on Windows
2. Open Command Prompt as Administrator
3. Navigate to the script directory
4. Run:

   python <script_name>.py

The script will create an output directory containing
forensic artifacts and a hash log.

## Usage
The script is executed locally on a Windows system using the command line.  
All collected artifacts are automatically organised into structured directories, and cryptographic hashes are generated for integrity verification.

## Academic Context
This repository supports the dissertation titled:

**"An Automated Incident Response Framework for Improving Windows Forensic Artifact Collection"**

The code is provided for academic evaluation and demonstration purposes.
