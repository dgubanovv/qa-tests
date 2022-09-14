@echo off

if "%1" == "" (
    set port=1
) else (
    set port=%1
)

echo Kickstarting Felicity on port %port%
python kickstart.py -p pci%port%.00.0 --phy False --drv_uninstall True

pause
