class RecordField:
    def __init__(self, field_type=None, value=None):
        self.field_type = field_type
        self.value = value


class RecordCreate:
    def __init__(self, record_type, title):
        self.record_type = record_type
        self.title = title
        self.fields = []
