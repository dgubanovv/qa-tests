::
:: Packaging script for AtlanticTestbench for further deployment
::
set BATCH_DIR=%~dp0
set P4_SOFTWARE_PATH=%BATCH_DIR%\..\..\..\..\
set TESTBENCH_PATH=%P4_SOFTWARE_PATH%\Software\Test\AtlanticTestbench
set ARTIFACTS_PATH=%BATCH_DIR%\artifacts

set /A RETURN_CODE = 0

:: clean-up previous build
rmdir /s /q %ARTIFACTS_PATH%
mkdir %ARTIFACTS_PATH%
FOR %%i IN (%ARTIFACTS_PATH%) DO IF EXIST %%~si\NUL (
	ECHO %ARTIFACTS_PATH% is a directory
) ELSE (
	ECHO %ARTIFACTS_PATH% is not a directory! Aborting build!
	set /A RETURN_CODE = 1
	goto exit
)

cd %TESTBENCH_PATH%
icmp4 sync -f ./...

if %ERRORLEVEL% NEQ 0 (
	echo Perforce sync failed
	set /A RETURN_CODE = %ERRORLEVEL%
	goto exit
)

set ARCHIVE=AtlanticTestbench.zip

:: zip files
7z a -tzip %ARCHIVE% -r *.py
7z a -tzip %ARCHIVE% -r *.ps1
7z a -tzip %ARCHIVE% -r *.yml
7z a -tzip %ARCHIVE% -r *.yaml
7z a -tzip %ARCHIVE% -r *.json
7z a -tzip %ARCHIVE% -r *.txt
7z a -tzip %ARCHIVE% -r *.cld
7z a -tzip %ARCHIVE% -r *.clx
7z a -tzip %ARCHIVE% -r *.dhex
7z a -tzip %ARCHIVE% -r *.ihex
7z a -tzip %ARCHIVE% -r *.sh
if %ERRORLEVEL%==0 (
	move %ARCHIVE% %ARTIFACTS_PATH%
) ELSE (
	echo 7zip failed
	set /A RETURN_CODE = %ERRORLEVEL%
)

:exit
EXIT /B %RETURN_CODE%
