@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul
if errorlevel 1 exit /b 1
cd /d "%~dp0.."
cl /nologo /W3 /Od /Zi /I include /I loader tests\seh_runpe_harness.c /link /OUT:tests\seh_runpe_harness.exe
exit /b %errorlevel%
