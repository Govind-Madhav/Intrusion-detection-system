@echo off
REM Startup script for Intrusion Detection System

REM Start backend (Java Spring Boot via Maven)
echo Starting backend...
start cmd /k "mvn spring-boot:run"

REM Start frontend (Vite/React)
echo Starting frontend...
cd frontend
start cmd /k "npm install && npm run dev"
cd ..

echo Both backend and frontend are starting in separate terminals.
pause
