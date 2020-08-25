from featuresExtractor import extractFeatures

def getTagAndFeatures(target):

    res = None
    if isinstance(target, list):
        res = []
        for t in target:
            res.append({t: extractFeatures(t)})
    else:
        res = {target: extractFeatures(target)}
    
    return res

if __name__ == "__main__":
    import sys
    from pprint import pprint
    import json
    target = None

    if len(sys.argv) > 2:
        target = sys.argv[1]
    if target == "-f" and len(sys.argv)>=3:
        with open(sys.argv[2]) as f:
            target = f.readlines()
            # remove extra blankspaces that may be there like \n
            target = [t.strip() for t in target]

    if target is not None:
        print (json.dumps(getTagAndFeatures(target)))       
        