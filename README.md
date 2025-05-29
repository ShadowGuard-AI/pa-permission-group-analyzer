# pa-permission-group-analyzer
Identifies users belonging to multiple permission groups, highlighting potential cumulative privilege escalation vulnerabilities due to overlapping or conflicting group permissions. - Focused on Tools for analyzing and assessing file system permissions

## Install
`git clone https://github.com/ShadowStrikeHQ/pa-permission-group-analyzer`

## Usage
`./pa-permission-group-analyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `--group-file`: Path to the file containing group membership information.  Each line should be in the format: group_name:user1,user2,...
- `--output`: Path to the output file to store the analysis results.
- `--min-groups`: No description provided

## License
Copyright (c) ShadowStrikeHQ
