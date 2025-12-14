test@echo off
REM Quick build script for Ghidra PSX Loader (Windows)
REM Just run: build.bat

cd /d "%~dp0"

REM Auto-detect Ghidra if not set
if "%GHIDRA_INSTALL_DIR%"=="" (
    if exist "C:\apps\ghidra\support\buildExtension.gradle" (
        set GHIDRA_INSTALL_DIR=C:\apps\ghidra
        echo Auto-detected Ghidra: C:\apps\ghidra
    )
)

REM Check for GHIDRA_INSTALL_DIR
if "%GHIDRA_INSTALL_DIR%"=="" (
    echo Error: GHIDRA_INSTALL_DIR not set and auto-detection failed
    echo.
    echo Please set it:
    echo   set GHIDRA_INSTALL_DIR=C:\path\to\ghidra
    echo.
    echo Or edit this script to add your Ghidra path
    exit /b 1
)

REM Check if Ghidra directory exists
if not exist "%GHIDRA_INSTALL_DIR%\support\buildExtension.gradle" (
    echo Error: Ghidra directory not found or invalid: %GHIDRA_INSTALL_DIR%
    exit /b 1
)

echo ==========================================
echo Building Ghidra PSX Loader Extension
echo ==========================================
echo Ghidra: %GHIDRA_INSTALL_DIR%
echo.

REM Check for Gradle
where gradle >nul 2>&1
if %errorlevel% equ 0 (
    set GRADLE_CMD=gradle
) else (
    if exist "gradlew.bat" (
        set GRADLE_CMD=gradlew.bat
    ) else (
        echo Error: Gradle not found. Please install Gradle.
        exit /b 1
    )
)

REM Clean and build
echo Running: %GRADLE_CMD% clean buildExtension
echo.
%GRADLE_CMD% clean buildExtension

REM Check for output
echo.
echo ==========================================
if exist "dist\*.zip" (
    echo Build successful!
    echo.
    echo Extension ZIP:
    dir /b dist\*.zip
) else (
    if exist "build\distributions\*.zip" (
        echo Build successful!
        echo.
        echo Extension ZIP:
        dir /b build\distributions\*.zip
    ) else (
        echo Build completed, but no ZIP file found.
        echo Check the output above for errors.
    )
)
echo ==========================================
