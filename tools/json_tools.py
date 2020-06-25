import json

class MyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return {
                "_type": "set",
                "value": list(obj)
            }
        return super(MyEncoder, self).default(obj)


class MyDecoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        json.JSONDecoder.__init__(self, object_hook=self.object_hook, *args, **kwargs)

    def object_hook(self, obj):
        if '_type' not in obj:
            return obj
        type = obj['_type']
        if type == 'set':
            return set(obj['value'])

        return obj