@echo off
setlocal
set "batch_dir=%~dp0"
cd %batch_dir%
go run main.go
pause
endlocal
