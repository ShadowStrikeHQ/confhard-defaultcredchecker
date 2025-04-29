import argparse
import logging
import os
import re
import sys
import yaml
from schema import Schema, SchemaError, Use, Optional

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Default credentials dictionary
DEFAULT_CREDENTIALS = {
    "username": ["admin", "user", "root", "test"],
    "password": ["password", "123456", "admin", "test", "password123", "changeme"]
}

# Configuration file schema
CONFIG_SCHEMA = Schema({
    'files': [Use(str)],
    Optional('processes'): [Use(str)],
    Optional('credentials'): {
        Optional('username'): [Use(str)],
        Optional('password'): [Use(str)]
    },
    Optional('regex'): [Use(str)]
})


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(
        description="Checks configuration files and processes for default/weak credentials."
    )
    parser.add_argument(
        "-c", "--config", help="Path to the YAML configuration file.", required=True
    )
    parser.add_argument(
        "-v", "--verbose", help="Enable verbose output (debug logging).", action="store_true"
    )
    return parser.parse_args()


def load_config(config_file):
    """
    Loads the configuration from a YAML file.
    Validates the configuration file.
    Handles file not found and invalid YAML errors.

    Args:
        config_file (str): Path to the YAML configuration file.

    Returns:
        dict: The configuration data as a dictionary, or None if an error occurred.
    """
    try:
        with open(config_file, "r") as f:
            config = yaml.safe_load(f)

        # Validate the config using the schema
        CONFIG_SCHEMA.validate(config)
        return config
    except FileNotFoundError:
        logging.error(f"Configuration file not found: {config_file}")
        return None
    except yaml.YAMLError as e:
        logging.error(f"Error parsing YAML in {config_file}: {e}")
        return None
    except SchemaError as e:
        logging.error(f"Invalid configuration file: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred loading the config: {e}")
        return None


def check_file_for_credentials(file_path, credentials, regex_patterns):
    """
    Checks a file for default/weak credentials.

    Args:
        file_path (str): The path to the file to check.
        credentials (dict): A dictionary of default credentials to check for.
        regex_patterns (list): A list of regex patterns to search for.

    Returns:
        list: A list of findings (lines containing potential credentials).
    """
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_number, line in enumerate(f, 1):
                for credential_type, credential_values in credentials.items():
                    for credential in credential_values:
                        if credential in line.lower():
                            findings.append(
                                f"File: {file_path}, Line: {line_number}, Credential Type: {credential_type}, Value: {credential.strip()}, Line Content: {line.strip()}"
                            )
                for regex in regex_patterns:
                    if re.search(regex, line, re.IGNORECASE):
                        findings.append(
                            f"File: {file_path}, Line: {line_number}, Regex Match: {regex}, Line Content: {line.strip()}"
                        )
    except FileNotFoundError:
        logging.warning(f"File not found: {file_path}")
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
    return findings


def check_process_for_credentials(process_name, credentials, regex_patterns):
    """
    Checks for the existence of a process by name and if found,
    searches its command line arguments (if accessible) for sensitive information.
    """
    try:
        import psutil
    except ImportError:
        logging.error("psutil is required to check processes.  Please install it with 'pip install psutil'")
        return []

    findings = []
    for proc in psutil.process_iter(['name', 'cmdline']):
        if proc.info['name'] == process_name:
            try:
                cmdline = ' '.join(proc.info['cmdline'])
                for credential_type, credential_values in credentials.items():
                    for credential in credential_values:
                        if credential in cmdline.lower():
                            findings.append(f"Process: {process_name}, Credential Type: {credential_type}, Value: {credential.strip()}, Command Line: {cmdline.strip()}")

                for regex in regex_patterns:
                    if re.search(regex, cmdline, re.IGNORECASE):
                        findings.append(f"Process: {process_name}, Regex Match: {regex}, Command Line: {cmdline.strip()}")

            except psutil.AccessDenied:
                logging.warning(f"Access denied when trying to read command line for process: {process_name}")
            except Exception as e:
                logging.error(f"Error processing process {process_name}: {e}")

    return findings


def main():
    """
    Main function to execute the credential checking tool.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose mode enabled.")

    config = load_config(args.config)
    if not config:
        sys.exit(1)

    files_to_check = config.get("files", [])
    processes_to_check = config.get("processes", [])
    custom_credentials = config.get("credentials", {})
    regex_patterns = config.get("regex", [])

    # Merge default credentials with custom credentials, if provided
    merged_credentials = DEFAULT_CREDENTIALS.copy()
    for cred_type, cred_values in custom_credentials.items():
        if cred_type in merged_credentials:
            merged_credentials[cred_type].extend(cred_values)
        else:
            merged_credentials[cred_type] = cred_values

    all_findings = []

    # Check files
    for file_path in files_to_check:
        logging.info(f"Checking file: {file_path}")
        findings = check_file_for_credentials(file_path, merged_credentials, regex_patterns)
        all_findings.extend(findings)

    # Check processes
    for process_name in processes_to_check:
        logging.info(f"Checking process: {process_name}")
        findings = check_process_for_credentials(process_name, merged_credentials, regex_patterns)
        all_findings.extend(findings)

    if all_findings:
        print("Potential credential exposures found:")
        for finding in all_findings:
            print(finding)
    else:
        print("No potential credential exposures found.")

    if all_findings:
        sys.exit(1)  # Exit with an error code if findings were found
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()