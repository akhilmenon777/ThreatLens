# Windows PowerShell: start backend and frontend dev server in two windows.
$root = Split-Path -Parent $PSScriptRoot
Start-Process powershell -ArgumentList "-NoExit","-Command","cd '$root\backend'; python -m uvicorn app.main:app --reload --port 8000"
Start-Process powershell -ArgumentList "-NoExit","-Command","cd '$root\frontend'; npm run dev"
