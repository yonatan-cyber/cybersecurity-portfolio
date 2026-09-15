\# Python Log Analyzer



A Python-based security tool for analyzing Linux `auth.log` files and extracting important authentication and system activity.



\## Features



\- Detects successful sudo commands

\- Identifies failed sudo attempts

\- Monitors `su` session activity

\- Detects user creation and deletion

\- Detects password changes

\- Extracts timestamps, usernames, commands, and relevant event details

\- Generates a structured terminal report with optional colored output

\- Analyzes log files in read-only mode



\## Usage



```bash

python3 log\_analyzer.py /path/to/auth.log

