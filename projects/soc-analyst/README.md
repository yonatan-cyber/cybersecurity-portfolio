\# SOC Analyst Checker



A Bash-based SOC validation tool developed for authorized training environments. The tool generates controlled network activity that can be used to support SOC monitoring, detection, and validation exercises.



\## Features



\- Automatic network and interface detection

\- Local subnet host discovery using Nmap

\- Manual or random target selection

\- RFC1918 private target validation

\- TCP SYN scanning

\- UDP scanning

\- Service and version detection

\- Manual or random scenario selection

\- Pre-execution confirmation and safety controls

\- Structured audit logging

\- Session and execution status tracking



\## Network Scenarios



\### TCP SYN Scan

Performs a limited scan of the 100 most common TCP ports.



\### UDP Scan

Performs a limited scan of the 20 most common UDP ports.



\### Service Detection

Performs service and version detection against 20 common TCP ports.



\## Audit Logging



All executed activities are recorded in:



`/var/log/soc\_checker.log`



Each log entry can include:



\- Session ID

\- Timestamp

\- Activity type

\- Target IP

\- Execution status

\- Exit code



The activity lifecycle is tracked through statuses such as `SELECTED`, `STARTED`, `COMPLETED`, and `FAILED`.



\## Safety Controls



The tool includes several restrictions designed for authorized lab use:



\- Authorization confirmation is required

\- Only RFC1918 private IPv4 targets are accepted

\- The local host cannot be selected as a target

\- The default gateway is excluded from random target selection

\- Automatic network discovery is limited to /24 or smaller networks

\- Final confirmation is required before network activity begins



\## Technologies



\- Bash

\- Linux

\- Nmap

\- TCP/IP

\- Network reconnaissance

\- SOC monitoring and validation

\- Security logging



\## Project Files



\- `soc\_analyst.sh` - Bash source code

\- `soc\_analyst\_report.pdf` - Technical project report, testing, screenshots, and results



\## Training



This project was completed as part of the \*\*SOC Analyst (NX220)\*\* module during my Cyber Defense and Information Security training at John Bryce.



\## Disclaimer



This project was developed and tested exclusively in an authorized private lab environment for educational purposes.

