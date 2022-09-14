#Power control config
#
# 
import subprocess
import os


def powerCycle():
    #runStr = os.path.join('D:/wa/AtlanticTestbench/helpers', 'bin', 'pwrtest.exe /sleep /s:4 /p:30') # r'.\helpers\bin\pwrtest.exe'
    file = os.path.join('D:/wa/AtlanticTestbench/helpers', 'bin', 'pwrtest.exe').replace('\\','/')
    cmd = "{} /sleep /s:4 /p:30".format(file)
    print cmd
    #runStr = runStr.replace('\\','/')
    subprocess.call(cmd,  shell=True)
    

def atlantic_run(**kwargs):
    powerCycle()