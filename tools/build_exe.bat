@echo off
REM ============================================================
REM  pe_module_scan.py 单文件 EXE 打包脚本（Windows / PyInstaller）
REM  用法：在 tools 目录双击本脚本，或命令行执行 build_exe.bat
REM  产物：dist\pe_module_scan.exe（单文件，双击/命令行可用）
REM ============================================================
setlocal
cd /d "%~dp0"

where pyinstaller >nul 2>&1
if errorlevel 1 (
    echo [提示] 未检测到 pyinstaller，先安装：
    echo        python -m pip install pyinstaller
    python -m pip install pyinstaller
)

REM --onefile 单文件；--console 保留命令行窗口（扫描器是 CLI，需要控制台）
REM 若想要无窗口 GUI 版，把 --console 换成 --windowed（不适合本 CLI）
pyinstaller --onefile --console --noconfirm --clean --name pe_module_scan pe_module_scan.py

if exist dist\pe_module_scan.exe (
    echo.
    echo [完成] 产物：%~dp0dist\pe_module_scan.exe
    echo 用法： pe_module_scan.exe "C:\path\to\app.exe" --report out.md
) else (
    echo [失败] 打包未成功，请把上方报错贴出排查。
)
endlocal
