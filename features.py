

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
        return "Lenght"

    @staticmethod
    def getFeature(target):
        return len(target)