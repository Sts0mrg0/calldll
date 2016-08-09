@echo off

dub build -a x86_64
copy /y calldll.exe calldll64.exe

dub build