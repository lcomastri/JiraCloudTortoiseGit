@echo off
%WinDir%\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe JiraGit.msbuild /t:Clean
%WinDir%\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe JiraGit.msbuild /t:Compile /p:Configuration=Release /p:Platform=x86
%WinDir%\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe JiraGit.msbuild /t:Compile /p:Configuration=Release /p:Platform=x64
