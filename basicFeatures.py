from FeatureEnum import Feature

class FeatureExtractor(object):

    @staticmethod
    def getName():
        raise NotImplementedError

    @staticmethod
    def getFeature(target):
        raise NotImplementedError

    

class LenExtractor(FeatureExtractor):
    @staticmethod
    def getName():
        return "Length"

    @staticmethod
    def getFeature(target):
        URLLen = len(target)

        return Feature.Legitimate if URLLen < 54 else (
               Feature.Suspicious if URLLen <= 75 else
               Feature.Pishing )