# DEUS
Windows 10 KMDF driver for memory manipulation.

## Build
1. Install [Windows 11 WDK][wdk].
2. Install [Python 3][py3] to `C:\Python`.
3. Clone this repository to `C:\Workspace\deus`.

```cmd
git clone git@github.com:qis/deus C:/Workspace/deus
cd C:\Workspace\deus
git submodule update --init --depth 1
```

4. Install dependencies using [Conan][conan].

<!--
* Set the system environment variable `CONAN_USER_HOME_SHORT` to `None`.
* Upgrade pip with `python -m pip install --upgrade pip`.
* Upgrade conan with `pip install conan --upgrade`.
-->

```cmd
cd C:\Workspace\deus
conan install . -if third_party -pr conan.profile
```

5. Create a copy of the Microsoft Visual C++ Redistributable.

```cmd
copy "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Redist\MSVC\v143\vc_redist.x64.exe" ^
     "C:\Workspace\deus\third_party\"
```

## Debug
1. Install [SandboxBootkit][sandbox] and run `sandbox.wsb`.

<!--
cd C:\Program Files (x86)\Windows Kits\10\Debuggers\x64
CmDiag DevelopmentMode -On
CmDiag Debug -On -Net
windbg.exe -k net:port=50100,key=cl.ea.rt.ext,target=127.0.0.1 -v
C:\Workspace\deus\sandbox.wsb
-->

2. Execute commands in sandbox `cmd.exe`.

```cmd
rem Start driver.
sc start deus

rem Run tests.
C:\Workspace\deus\build\debug\deus.exe

rem Stop driver.
sc stop deus

rem Query driver.
sc query deus
```

[wdk]: https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
[py3]: https://www.python.org/downloads/windows/
[conan]: https://conan.io/center/
[sandbox]: https://github.com/thesecretclub/SandboxBootkit
