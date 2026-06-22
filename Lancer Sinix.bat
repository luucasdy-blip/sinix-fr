@echo off
title Sinix (FR) 1.7 - Lancement
color 0A

echo.
echo  +---------------------------------+
echo  ^|     Sinix (FR) 1.7              ^|
echo  ^|     Demarrage en cours...       ^|
echo  +---------------------------------+
echo.

:: Tuer les anciens process
taskkill /F /IM node.exe >nul 2>&1
taskkill /F /IM ngrok.exe >nul 2>&1

:: Lancer le serveur Node
echo  [1/2] Demarrage du serveur...
start "Sinix Server" cmd /k "node C:\Users\SinixOnTop2\Desktop\site\server.js"

timeout /t 2 /nobreak >nul

:: Lancer ngrok avec le domaine fixe
echo  [2/2] Demarrage du tunnel...
start "Sinix Ngrok" cmd /k "ngrok http --url=junction-pouring-stupor.ngrok-free.dev 3000"

echo.
echo  +--------------------------------------------------+
echo  ^| Site en ligne sur :                             ^|
echo  ^| https://junction-pouring-stupor.ngrok-free.dev ^|
echo  +--------------------------------------------------+
echo.
pause
