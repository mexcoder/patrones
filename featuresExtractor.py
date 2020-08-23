from basicFeatures import LenExtractor
from UrlParsedFeatures import AtSymbolExtractor, DashExtractor
from UrlParsedFeatures import HttpsTokenExtractor, IpExtractor
from UrlParsedFeatures import NonStandarPortExtractor, NumberSubdomainsExtractor
from UrlParsedFeatures import RedirectExtractor, UrlShortenedExtractor
from AlexaParsedFeatures import AlexaRankExtractor
from WebClientFeatures import  HttpsStatusExtractor,FavIconStatusExtractor
from WebClientFeatures import  RequestURLExtractor,anchorURLExtractor
from WebClientFeatures import  LinksInMetaExtractor,ServerFromHandlerExtractor
from WebClientFeatures import  MailToInServerFromHandlerExtractor,IframeExtractor


extractors = [LenExtractor, AtSymbolExtractor, DashExtractor,HttpsTokenExtractor,
              IpExtractor, NonStandarPortExtractor, NumberSubdomainsExtractor,
              RedirectExtractor, UrlShortenedExtractor, AlexaRankExtractor,
              HttpsStatusExtractor,FavIconStatusExtractor,RequestURLExtractor,
              anchorURLExtractor,LinksInMetaExtractor,ServerFromHandlerExtractor,
              MailToInServerFromHandlerExtractor, IframeExtractor]

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
    import sys
    
    testString = "https://test.com"

    if len(sys.argv) > 2:
        testString = sys.argv[1]

    print (extractFeatures(testString))