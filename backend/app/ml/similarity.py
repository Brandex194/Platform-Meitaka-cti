import pickle

import faiss
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer


class IocSimilarityIndex:
    def __init__(self) -> None:
        self._vectorizer: TfidfVectorizer | None = None
        self._index: faiss.Index | None = None
        self._items: list[str] = []

    def add(self, indicators: list[str]) -> None:
        self._vectorizer = TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 4), max_features=1024)
        vecs = self._vectorizer.fit_transform(indicators).toarray().astype(np.float32)
        faiss.normalize_L2(vecs)
        self._index = faiss.IndexFlatIP(vecs.shape[1])
        self._index.add(vecs)
        self._items = list(indicators)

    def search(self, query: str, k: int = 10) -> list[tuple[str, float]]:
        if self._vectorizer is None or self._index is None:
            raise RuntimeError("Index not built. Call add() or load() first.")
        vec = self._vectorizer.transform([query]).toarray().astype(np.float32)
        faiss.normalize_L2(vec)
        k = min(k, len(self._items))
        dists, idxs = self._index.search(vec, k)
        return [(self._items[i], float(d)) for i, d in zip(idxs[0], dists[0]) if i >= 0]

    def save(self, path: str) -> None:
        faiss.write_index(self._index, path)
        with open(path + ".meta", "wb") as f:
            pickle.dump({"vectorizer": self._vectorizer, "items": self._items}, f)

    @classmethod
    def load(cls, path: str) -> "IocSimilarityIndex":
        obj = cls()
        obj._index = faiss.read_index(path)
        with open(path + ".meta", "rb") as f:
            meta = pickle.load(f)  # noqa: S301 — internal index file
        obj._vectorizer = meta["vectorizer"]
        obj._items = meta["items"]
        return obj
