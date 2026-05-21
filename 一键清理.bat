@echo off
chcp 65001 >nul
title AutoPenX — 一键清理冗余脚本

echo ╔══════════════════════════════════════════╗
echo ║   AutoPenX 一键清理冗余脚本 / 临时文件  ║
echo ╚══════════════════════════════════════════╝
echo.
echo   [1] 清理 ctf_workspace (攻击链临时文件)
echo   [2] 干运行 (仅查看不删除)
echo   [3] 清理整个项目临时文件
echo   [4] 退出
echo.
set /p choice="请输入选项 [1-4]: "

if "%choice%"=="1" goto clean_workspace
if "%choice%"=="2" goto dry_run
if "%choice%"=="3" goto clean_project
if "%choice%"=="4" goto end
echo 无效选项
goto end

:clean_workspace
echo.
echo 正在清理 ctf_workspace ...
python autopnex.py --clean --clean-root ctf_workspace
echo 完成！
pause
goto end

:dry_run
echo.
echo 干运行模式 — 仅显示将要删除的文件...
python autopnex.py --clean --clean-root ctf_workspace --clean-dry-run
echo 完成！
pause
goto end

:clean_project
echo.
echo 正在清理项目中的所有冗余文件...
python autopnex.py --clean --clean-root .
echo 完成！
pause
goto end

:end
