@echo off
setlocal
set "batch_dir=%~dp0"
echo cd %batch_dir%
timeout /nobreak /t 1 >nul
set GOOS=linux
timeout /nobreak /t 1 >nul
set GOARCH=amd64
timeout /nobreak /t 1 >nul
go build main.go
pause
endlocal
