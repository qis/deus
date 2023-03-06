@echo off
%~dp0third_party\vc_redist.x64.exe /install /quiet /norestart
sc create deus binPath=%~dp0build\debug\deus.sys type=kernel
