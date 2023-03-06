@echo off
sc create deus binPath=%~dp0build\debug\deus.sys type=kernel
