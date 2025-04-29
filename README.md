# confhard-DefaultCredChecker
Checks common configuration files (e.g., `config.ini`, `.env`, common database connection files) and running processes for default or weak credentials. Uses a built-in dictionary of common credentials and regular expressions to identify potential vulnerabilities. - Focused on Automates the hardening of system and application configurations based on defined policies. Reads configuration files (e.g., YAML, JSON) and uses predefined rules (e.g., CIS benchmarks) to identify and remediate insecure settings. Provides tools to validate configuration changes and generate reports on compliance. It focuses on automation, not vulnerability detection. It should not alter the system or application without confirmation.

## Install
`git clone https://github.com/ShadowStrikeHQ/confhard-defaultcredchecker`

## Usage
`./confhard-defaultcredchecker [params]`

## Parameters
- `-h`: Show help message and exit
- `-c`: Path to the YAML configuration file.
- `-v`: No description provided

## License
Copyright (c) ShadowStrikeHQ
