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
)
cls
findstr /i "Mimikatz" programfiles.flashed
if %errorlevel%==0 (
    echo Potential Mimikatz detected. Please take note, then press any key.
    pause >NUL
)
findstr /i "Metasploit" programfiles.flashed
if %errorlevel%==0 (
    echo Potential Metasploit detected. Please take note, then press any key.
    pause >NUL
)
findstr /i "CobaltStrike" programfiles.flashed
if %errorlevel%==0 (
    echo Potential Cobalt Strike detected. Please take note, then press any key.
    pause >NUL
)
findstr /i "JohnTheRipper" programfiles.flashed
if %errorlevel%==0 (
    echo Potential John the Ripper detected. Please take note, then press any key.
    pause >NUL
)
findstr /i "Hashcat" programfiles.flashed
if %errorlevel%==0 (
    echo Potential Hashcat detected. Please take note, then press any key.
    pause >NUL
)
findstr /i "Wireshark" programfiles.flashed
if %errorlevel%==0 (
    echo Potential Wireshark detected. Please take note, then press any key.
    pause >NUL
)
findstr /i "DarkComet" programfiles.flashed
if %errorlevel%==0 (
    echo Potential DarkComet detected. Please take note, then press any key.
    pause >NUL
)
findstr /i "njRAT" programfiles.flashed
if %errorlevel%==0 (
    echo Potential njRAT detected. Please take note, then press any key.
    pause >NUL
)
findstr /i "PowerSploit" programfiles.flashed
if %errorlevel%==0 (
    echo Potential PowerSploit detected. Please take note, then press any key.
    pause >NUL
)
findstr /i "Veil" programfiles.flashed
if %errorlevel%==0 (
    echo Potential Veil detected. Please take note, then press any key.
    pause >NUL
)
findstr /i "Empire" programfiles.flashed
if %errorlevel%==0 (
    echo Potential Empire detected. Please take note, then press any key.
    pause >NUL
