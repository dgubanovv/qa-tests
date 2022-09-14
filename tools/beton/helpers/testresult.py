"""
Helper for showing test result
"""
def show_test_result(finalReport):
    if len(finalReport) > 0:
        for str in finalReport:
            print str
        
        print 
        print '[FAILED]'

    else:
        print 
        print '[PASSED]'