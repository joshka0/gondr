class InMemoryKeyValueStorage:
    def __init__(self, config=None):
        if not isinstance(config, str):
            raise TypeError("config must be the base64 string")
        self.config = config
