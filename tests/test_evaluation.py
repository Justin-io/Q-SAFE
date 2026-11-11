import unittest
from qsafe_eval import calculate_metrics


class EvaluationMetricTests(unittest.TestCase):
    def test_confusion_matrix_and_rates(self):
        rows = [
            {"label": "malicious", "prediction": "malicious", "family": "A"},
            {"label": "malicious", "prediction": "benign", "family": "A"},
            {"label": "benign", "prediction": "malicious", "family": ""},
            {"label": "benign", "prediction": "benign", "family": ""},
        ]
        result = calculate_metrics(rows)
        self.assertEqual(result["confusion_matrix"], {
            "true_positive": 1, "false_positive": 1, "true_negative": 1, "false_negative": 1
        })
        self.assertEqual(result["precision"], 0.5)
        self.assertEqual(result["recall"], 0.5)
        self.assertEqual(result["specificity"], 0.5)
        self.assertEqual(result["f1"], 0.5)
        self.assertEqual(result["family_recall"]["A"]["recall"], 0.5)

    def test_empty_dataset_has_zero_metrics(self):
        result = calculate_metrics([])
        self.assertEqual(result["precision"], 0.0)
        self.assertEqual(result["recall"], 0.0)
        self.assertEqual(result["f1"], 0.0)


if __name__ == "__main__":
    unittest.main()
