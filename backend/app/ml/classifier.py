import pickle

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline


class DarkWebClassifier:
    def __init__(self) -> None:
        self._pipeline: Pipeline | None = None

    def train(self, texts: list[str], labels: list[int]) -> None:
        self._pipeline = Pipeline([
            ("tfidf", TfidfVectorizer(max_features=5000, ngram_range=(1, 2))),
            ("lr", LogisticRegression(max_iter=500, class_weight="balanced")),
        ])
        self._pipeline.fit(texts, labels)

    def predict(self, texts: list[str]) -> list[float]:
        if self._pipeline is None:
            raise RuntimeError("Model not trained. Call train() or load() first.")
        return self._pipeline.predict_proba(texts)[:, 1].tolist()

    def save(self, path: str) -> None:
        with open(path, "wb") as f:
            pickle.dump(self._pipeline, f)

    @classmethod
    def load(cls, path: str) -> "DarkWebClassifier":
        obj = cls()
        with open(path, "rb") as f:
            obj._pipeline = pickle.load(f)  # noqa: S301 — internal model file
        return obj
