# Team Working Documentation

This file is for team coordination.
Each person updates only their own section until the project is finished.

Project Lead: Govind Madhav
- Keeps the team organized and does the final review.

## Git Guide

- `git pull` - get the latest changes from GitHub and update your local repo.
	- Example: `git pull origin main`
- `git push` - send your local changes to GitHub.
	- Example: `git push origin main`
- `git fetch` - check GitHub for new changes without applying them.
	- Example: `git fetch origin`
- `git branch` - see the branch you are on and the branches available.
	- Example: `git branch`
- `git checkout main` - switch to the main branch.
	- Example: `git checkout main`
- `git status` - see what files were changed.
	- Example: `git status`

## Rules

1. Do not edit another person's section unless told to.
2. Update your status after each work session.
3. Mention blockers clearly so the team can help.
4. Keep notes short and date-based.
5. Final merge happens only after all sections are marked complete.

## Status Legend

- Not Started
- In Progress
- Blocked
- Complete

## Person 1 - Capture Layer

Owner: Utkarsh

Status: Not Started

Scope:
- Select network interface
- Capture packets
- Pass packet details to the detection layer

Files:
- src/main/java/com/ids/capture/InterfaceSelector.java
- src/main/java/com/ids/capture/PacketCaptureService.java
- src/main/java/com/ids/config/CliArgs.java

Daily Notes:
- YYYY-MM-DD:

Blockers:
- None

## Frontend Layer - Team Owned

Scope:
- Build and improve the React frontend
- Keep the UI clean, simple, and demo-ready
- Match frontend data with the backend alert format
- Show alerts in a clear and readable way

Shared Notes:
- The frontend is handled by the team
- Keep the interface polished and easy to present
- Update this section when UI decisions change

## Person 2 - Detection Layer

Owner: Govind Madhav

Status: In Progress

Scope:
- Build the detection engine
- Add SYN scan detection
- Add ICMP flood detection
- Add risky port detection
- Keep alert data consistent
- Set alert severity correctly
- Prepare alert data for the frontend

Files:
- src/main/java/com/ids/detection/DetectionEngine.java
- src/main/java/com/ids/detection/SynScanDetector.java
- src/main/java/com/ids/detection/IcmpFloodDetector.java
- src/main/java/com/ids/detection/RiskyPortDetector.java
- src/main/java/com/ids/model/AlertEvent.java

Daily Notes:
- YYYY-MM-DD:

Blockers:
- None

## Person 3 - Testing and Reporting

Owner: Dhruvi Bagga

Status: Not Started

Scope:
- Test and run the project
- Report flaws and issues in detail
- Prepare test material and demo inputs
- Document execution results clearly
- Check alert display and logging during tests

Files:
- src/main/java/com/ids/output/AlertLogger.java
- src/main/java/com/ids/config/AppConfig.java
- src/main/java/com/ids/app/Application.java
- .env
- documentions.md

Materials to Prepare:
- Test cases
- Sample packet/demo data
- Execution notes
- Flaw report template

Daily Notes:
- YYYY-MM-DD:

Blockers:
- None

