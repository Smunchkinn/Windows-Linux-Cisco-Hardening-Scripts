@echo off

color 0A

:Main

echo " /$$      /$$ /$$           /$$                                        "
echo "| $$$    /$$$|__/          | $$                                        "
echo "| $$$$  /$$$$ /$$ /$$$$$$$ | $$$$$$$                                   "
echo "| $$ $$/$$ $$| $$| $$__  $$| $$__  $$                                  "
echo "| $$  $$$| $$| $$| $$  \ $$| $$  \ $$                                  "
echo "| $$\  $ | $$| $$| $$  | $$| $$  | $$                                  "
echo "| $$ \/  | $$| $$| $$  | $$| $$  | $$                                  "
echo "|__/     |__/|__/|__/  |__/|__/  |__/                                  "
echo "                                                                       "                                                  
echo " /$$$$$$$                                            /$$               "
echo "| $$__  $$                                          | $$               "
echo "| $$  \ $$ /$$   /$$ /$$$$$$$   /$$$$$$   /$$$$$$$ /$$$$$$   /$$   /$$ "
echo "| $$  | $$| $$  | $$| $$__  $$ |____  $$ /$$_____/|_  $$_/  | $$  | $$ "
echo "| $$  | $$| $$  | $$| $$  \ $$  /$$$$$$$|  $$$$$$   | $$    | $$  | $$ " 
echo "| $$  | $$| $$  | $$| $$  | $$ /$$__  $$ \____  $$  | $$ /$$| $$  | $$ "
echo "| $$$$$$$/|  $$$$$$$| $$  | $$|  $$$$$$$ /$$$$$$$/  |  $$$$/|  $$$$$$$ "
echo "|_______/  \____  $$|__/  |__/ \_______/|_______/    \___/   \____  $$ "
echo "           /$$  | $$                                         /$$  | $$ "
echo "         |  $$$$$$/                                        |  $$$$$$/  "
echo "          \______/                                          \______/   "

echo add account (1)

echo disable account (2)

echo remove member from group (3)

echo add member to group (4)


set /p ting=Choose Number:

if %ting% == 1 goto :addAcc
if %ting% == 2 goto :disableAcc
if %ting% == 3 goto :removeMember
if %ting% == 4 goto :addMember

goto :Main



:addAcc
cls
net user

set /p "choice=Create User:"

net user %choice% /add

cls
goto :Main



:disableAcc
cls
net user

set /p "choice2=Disable User:"

net user %choice2% /active:no

cls
goto :Main



:removeMember
cls
net localgroup

set /p "group=Which Group:"

cls

net localgroup %group%

set /p "member=Remove User:"

net localgroup %group% %member% /delete

cls
goto :Main



:addMember
cls
net localgroup

set /p "group2=Which Group:"

cls

net localgroup %group2%

set /p "member2=Add User:"

net localgroup %group2% %member2% /add

cls
goto :Main
