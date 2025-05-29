#!/usr/bin/env python3

import argparse
import logging
import os
import sys
from collections import defaultdict
from typing import Dict, List, Set

try:
    from rich import print  # Optional: for nicer output
except ImportError:
    print = print  # Fallback if rich is not installed


# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def setup_argparse():
    """Sets up the argument parser for the command-line interface."""

    parser = argparse.ArgumentParser(
        description="Identifies users in multiple permission groups, highlighting potential privilege escalation vulnerabilities."
    )

    parser.add_argument(
        "--group-file",
        "-g",
        type=str,
        required=True,
        help="Path to the file containing group membership information.  Each line should be in the format: group_name:user1,user2,...",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        help="Path to the output file to store the analysis results.",
    )
    parser.add_argument(
        "--min-groups",
        type=int,
        default=2,
        help="Minimum number of groups a user must belong to in order to be reported (default: 2).",
    )

    return parser.parse_args()


def parse_group_file(group_file: str) -> Dict[str, List[str]]:
    """
    Parses the group file to extract group memberships.

    Args:
        group_file: Path to the group file.

    Returns:
        A dictionary where keys are group names and values are lists of users.
    """
    group_memberships: Dict[str, List[str]] = {}

    try:
        with open(group_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):  # Skip empty lines and comments
                    continue

                try:
                    group_name, users_str = line.split(":", 1)
                    users = [user.strip() for user in users_str.split(",") if user.strip()]  # Split users, strip whitespace, and remove empty users.
                    group_memberships[group_name.strip()] = users
                except ValueError:
                    logging.error(f"Invalid line format in group file: {line}")
                    continue
    except FileNotFoundError:
        logging.error(f"Group file not found: {group_file}")
        sys.exit(1)  # Exit with an error code

    return group_memberships


def analyze_user_groups(group_memberships: Dict[str, List[str]], min_groups: int) -> Dict[str, List[str]]:
    """
    Analyzes group memberships to identify users in multiple groups.

    Args:
        group_memberships: A dictionary where keys are group names and values are lists of users.
        min_groups: Minimum number of groups a user must belong to in order to be reported.

    Returns:
        A dictionary where keys are users and values are lists of groups they belong to.
    """

    user_to_groups: Dict[str, List[str]] = defaultdict(list)

    # Invert the group membership mapping to create a user-to-groups mapping.
    for group, users in group_memberships.items():
        for user in users:
            user_to_groups[user].append(group)

    # Filter users who belong to at least min_groups groups.
    users_in_multiple_groups: Dict[str, List[str]] = {
        user: groups for user, groups in user_to_groups.items() if len(groups) >= min_groups
    }

    return users_in_multiple_groups


def write_output(user_to_groups: Dict[str, List[str]], output_file: str = None):
    """
    Writes the analysis results to the console and optionally to a file.

    Args:
        user_to_groups: A dictionary where keys are users and values are lists of groups they belong to.
        output_file: Path to the output file.  If None, output is printed to console.
    """

    output_lines = []
    for user, groups in user_to_groups.items():
        output_lines.append(f"User: {user}, Groups: {', '.join(groups)}")

    if output_file:
        try:
            with open(output_file, "w") as f:
                for line in output_lines:
                    f.write(line + "\n")
            logging.info(f"Analysis results written to: {output_file}")
        except IOError as e:
            logging.error(f"Error writing to output file: {e}")
    else:
        for line in output_lines:
            print(line)


def main():
    """Main function to orchestrate the permission group analysis."""
    args = setup_argparse()

    # Input validation: Check if the group file exists
    if not os.path.isfile(args.group_file):
        logging.error(f"Group file does not exist: {args.group_file}")
        sys.exit(1)

    # Input validation: Check if the minimum group number is a positive integer.
    if args.min_groups <= 0:
        logging.error("Minimum groups must be a positive integer.")
        sys.exit(1)

    group_memberships = parse_group_file(args.group_file)
    users_in_multiple_groups = analyze_user_groups(group_memberships, args.min_groups)
    write_output(users_in_multiple_groups, args.output)


if __name__ == "__main__":
    main()

# Example Usage (assuming a group file named 'groups.txt'):
# Create a 'groups.txt' file with the following content:
# admin:user1,user2,user3
# developers:user2,user4
# testers:user3,user4,user5
# support:user1,user5

# Run the script:
# python pa_permission_group_analyzer.py -g groups.txt

# To save the output to a file:
# python pa_permission_group_analyzer.py -g groups.txt -o output.txt

# To find users in at least 3 groups:
# python pa_permission_group_analyzer.py -g groups.txt --min-groups 3