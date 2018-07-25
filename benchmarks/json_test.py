import json, ujson
from pprint import pprint

#https://artem.krylysov.com/blog/2015/09/29/benchmark-python-json-libraries/
#https://stackoverflow.com/questions/2835559/parsing-values-from-a-json-file
#http://code.activestate.com/recipes/576644-diff-two-dictionaries/
#https://github.com/seperman/deepdiff
#https://stackoverflow.com/questions/1165352/calculate-difference-in-keys-contained-in-two-python-dictionaries


json_data = """{
    "maps": [
        {
            "id": "blabla",
            "iscategorical": "0"
        },
        {
            "id": "blabla",
            "iscategorical": "0"
        }
    ],
    "masks": {
        "id": "valore"
    },
    "om_points": "value",
    "parameters": {
        "id": "valore"
    }
}"""



with open('data.json', 'w') as outfile:
     ujson.dump(json_data, outfile)

fp = open('data.json')
data = ujson.load(fp)
#d = json.loads(data)
d2 = ujson.loads(data)
v = d2["maps"][0]['id']
pprint(v)
pprint(data)

# with open('data.json') as data_file:
#     data = json.load(data_file)
# pprint(data["maps"][0]["id"])
# AttributeError: module 'json' has no attribute 'load'