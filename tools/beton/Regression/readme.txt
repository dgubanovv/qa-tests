# $File: //depot/icm/proj/Atlantic/rev1.0/software/Software/Test/AtlanticTestbench/Regression/readme.txt $
# $Revision: #3 $
# $DateTime: 2016/04/08 08:55:16 $
# $Author: dgubanov $

I this folder the auto regression tests runners are placed.

The test runners are named after TestRail test numbers.
For example in:
test0000_any_human_readable_name.txt 
Will be associated with TestRail test 0000.
All charactest after the digits and before the dot are ignored by auto test .py script.
They are just for humans.

If you need to create a new auto-test runner you can copy&paste from test0000_any_human_readable_name.txt.
And re-name it.

To create a test you can copy&paste from testSample.txt, rename it and place in the appropriate folders.
It is strongly recommended to place tests in appropriate directory.
For example:
Scripts/Bugs/
Scripts/CliTest/
Scripts/Minimal/
Scripts/Mips/
Scripts/Mngif/
Scripts/Mngif2/
...                   

