from featuresExtractor import extractFeatures

def getTagAndFeatures(target):

    return (target, extractFeatures(target))

if __name__ == "__main__":
    import sys
    testString = "https://test.com"

    if len(sys.argv) > 2:
        testString = sys.argv[1]
    print (getTagAndFeatures(testString))