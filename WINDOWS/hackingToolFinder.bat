@echo off

findstr "Cain" programfiles.flashed
if %errorlevel%==0 (
echo Cain detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "nmap" programfiles.flashed
if %errorlevel%==0 (
echo Nmap detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "keylogger" programfiles.flashed
if %errorlevel%==0 (
echo Potential keylogger detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "Armitage" programfiles.flashed
if %errorlevel%==0 (
echo Potential Armitage detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "Metasploit" programfiles.flashed
if %errorlevel%==0 (
echo Potential Metasploit framework detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "Shellter" programfiles.flashed
if %errorlevel%==0 (
echo Potential Shellter detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "Wire Shark" programfiles.flashed
if %errorlevel%==0 (
echo Potential Shellter detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "nMap" programfiles.flashed
if %errorlevel%==0 (
echo Potential Shellter detected. Please take note, then press any key.
pause >NUL
)
cls
findstr "John The Ripper" programfiles.flashed
if %errorlevel%==0 (
echo Potential Shellter detected. Please take note, then press any key.
pause >NUL
