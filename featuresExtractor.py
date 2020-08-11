from features import LenExtractor

extractors = [LenExtractor]


def extractFeatures(target):

    resultingFeatures = {}

    for extractor in extractors:
        resultingFeatures [extractor.getName()] = extractor.getFeature(target)
    
    return resultingFeatures

if __name__ == "__main__":
    testString = "https://test.com"
    print (extractFeatures(testString))