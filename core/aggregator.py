class Aggregator:
    def __init__(self):
        self.results = {}

    def add(self, module_name, data):
        self.results[module_name] = data

    def get_results(self):
        return self.results
