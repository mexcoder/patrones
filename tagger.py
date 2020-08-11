from featuresExtractor import extractFeatures

def getTagAndFeatures(target):

    return (target, extractFeatures(target))

if __name__ == "__main__":
    testString = "https://test.com"
    print (getTagAndFeatures(testString))