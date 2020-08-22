from CachingWebClient import CachingWebClient
from basicFeatures import FeatureExtractor
from FeatureEnum import Feature
from datetime import timedelta

class WebClientExtractor(FeatureExtractor):
    webClient = CachingWebClient()

    fetchPage = webClient.fetchURL


class HttpsStatusExtractor (WebClientExtractor):

    @staticmethod
    def getName():
        return "having_At_Symbol"

    @staticmethod
    def getFeature(target):

        data = WebClientExtractor.fetchPage(target)
        useHTTPS = data["certificate"] is not None
        certIsValid = data["validSsl"]
        age = data["certificate"]["notAfter"] - data["certificate"]["notBefore"]

        legit = useHTTPS and certIsValid and age >= timedelta(days=365)
        suspicious = useHTTPS and not certIsValid

        return Feature.Legitimate if legit else (
               Feature.Suspicious if suspicious else 
               Feature.Pishing )
if __name__ == "__main__":
        print (HttpsStatusExtractor.getFeature("https://mexcoder.com"))