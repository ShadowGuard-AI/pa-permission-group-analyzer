# pa-permission-group-analyzer
Identifies users belonging to multiple permission groups, highlighting potential cumulative privilege escalation vulnerabilities due to overlapping or conflicting group permissions. - Focused on Tools for analyzing and assessing file system permissions

## Install
`git clone https://github.com/ShadowGuard-AI/pa-permission-group-analyzer`

## Usage
`python3 main.py --group-file FILE [options]`

## Parameters
- `-h`: Show help message and exit
- `--group-file`, `-g`: (required) Path to the file containing group membership information.  Each line should be in the format: group_name:user1,user2,...
- `--output`, `-o`: Path to the output file to store the analysis results.
- `--min-groups`: Minimum number of groups a user must belong to in order to be reported (default: 2).

## Behaviour notes
- A user listed twice in one group counts once for that group. Only distinct groups count toward `--min-groups`.
- If the same group name appears on more than one line, the members are merged and a warning is logged. Earlier members are never silently dropped.
- If the group file is empty or every line is malformed, no valid group lines were parsed: the tool writes no output file, reports that the analysis was not performed, and exits non-zero. A valid file in which no user meets `--min-groups` still produces a normal empty report.
- The output path may not be the group file itself. If the resolved output path equals the input file, the tool refuses and exits 1.
- If writing the output file fails, the tool exits 1.

## License
See LICENSE.
