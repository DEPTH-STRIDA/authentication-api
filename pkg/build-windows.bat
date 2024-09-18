@echo off
setlocal
set "batch_dir=%~dp0"
echo cd %batch_dir%
timeout /nobreak /t 1 >nul
go build main.go
pause
endlocal
