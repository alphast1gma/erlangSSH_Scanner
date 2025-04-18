# erlangSSH_Scanner
Go Scanner for Erlang OTP SSH Exploit

# Erlang/OTP SSH Early Command Execution Vulnerability Scanner

A specialized scanner to detect Erlang/OTP SSH servers vulnerable to CVE-2024-37576, an authentication bypass vulnerability that allows early command execution before authentication.

## Overview

This scanner detects vulnerable Erlang/OTP SSH servers by attempting to execute a benign command that would succeed only if the vulnerability is present. The design focuses on minimal false positives while maintaining high detection rates.

## Features

- **Reliable Detection**: Uses multiple validation methods to minimize false positives
- **Concurrent Scanning**: Scan multiple hosts in parallel
- **Flexible Input**: Scan single IPs, host lists, or entire CIDR ranges
- **Rate Limiting**: Control scan speed to avoid overwhelming networks
- **Output Options**: Generate results in CSV or JSON format

## Requirements

- Go 1.16 or higher

## Installation

Clone the repository and build:

```bash
git clone https://github.com/yourusername/erlScanner.git
cd erlScanner
go build -o erlscanner erlscanner.go
```

## Usage

### Basic Usage

Scan a single host:
```bash
./erlscanner -target 192.168.1.100
```

Scan from a list of hosts:
```bash
./erlscanner -file hosts.txt
```

Scan a CIDR range:
```bash
./erlscanner -cidr 192.168.1.0/24
```

### Options

```
  -all-ssh
        Test all SSH servers, not just Erlang
  -cidr string
        CIDR range to scan (e.g., 192.168.1.0/24)
  -debug
        Enable debug logging (more detailed than verbose)
  -delay int
        Milliseconds to delay between tests (default 300)
  -file string
        File containing list of targets
  -follow-redirects
        Follow IP redirects when scanning
  -json
        Output in JSON format instead of CSV
  -output string
        Output results to file
  -port int
        Port to scan (default 22)
  -retries int
        Number of connection attempts before giving up (default 2)
  -rps int
        Rate limit: requests per second (0 = unlimited)
  -strict
        Use stricter detection to reduce false positives (default true)
  -target string
        Single target to scan (e.g., 192.168.1.1)
  -threads int
        Number of concurrent threads (default 10)
  -timeout int
        Timeout in seconds (default 5)
  -verbose
        Enable verbose output
```

## Understanding Results

The scanner reports hosts as:

- **VULNERABLE**: Confirmed vulnerable to early command execution
- **SECURE**: Confirmed not vulnerable
- **ERROR**: Could not complete scan (connection issues, etc.)

Example output:
```
[VULNERABLE] 192.168.1.100:22 - Erlang SSH server vulnerable to early command execution
[SECURE] 192.168.1.101:22 - Erlang SSH server not vulnerable
```

## Host File Format

When using `-file` option, the host file should contain one IP address per line:
```
192.168.1.100
192.168.1.101
10.0.0.1
```

## Technical Details

The scanner works by:

1. Identifying Erlang SSH servers through banner analysis
2. Attempting key exchange (KEXINIT)
3. Sending a premature channel open request (before authentication)
4. Sending a test command with a unique marker
5. Analyzing the server response for evidence of command execution

The strict mode (default) requires strong confirmation of vulnerability to reduce false positives.

## Remediation

If vulnerable servers are found:

1. Update Erlang/OTP to the latest patched version
2. If immediate updates are not possible, restrict SSH access to trusted IPs
3. Consider using alternative SSH implementations until updates are applied

## License

[Insert your license information here]

## Acknowledgments

Original exploit and vulnerability research by gdbinit in here: https://gist.github.com/gdbinit/e08e95ce77e031cd223c537ef67ed638 .
