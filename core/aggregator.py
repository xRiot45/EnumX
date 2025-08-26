class Aggregator:
    def __init__(self):
        self.results = []
    
    def add(self, module_name: str, data: dict):
        self.results.append({"module": module_name, "data": data})
    
    def get_results(self):
        return self.results