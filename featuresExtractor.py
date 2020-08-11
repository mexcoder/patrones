from features import LenExtractor

extractors = [LenExtractor]

nameMapping = {"Length" : "URL_Length"}


def extractFeatures(target):

    resultingFeatures = {}

    for extractor in extractors:
        name = extractor.getName()

        if name in nameMapping:
            name = nameMapping[name]

        resultingFeatures [name] = extractor.getFeature(target)
    
    return resultingFeatures

if __name__ == "__main__":
    testString = "https://test.com"
    print (extractFeatures(testString))