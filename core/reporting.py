from utils.file_handler import save_results


class Reporter:
    @staticmethod
    def save(results, output_file, format_type="json"):
        save_results(results, output_file, format_type)
