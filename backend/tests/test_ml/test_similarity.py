from app.ml.similarity import IocSimilarityIndex

IOC_CORPUS = [
    "192.168.1.100",
    "192.168.1.101",
    "10.0.0.1",
    "malware.example.com",
    "evil.tor.onion",
]


def test_search_returns_k_results():
    idx = IocSimilarityIndex()
    idx.add(IOC_CORPUS)
    results = idx.search("192.168.1.200", k=3)
    assert len(results) == 3


def test_similar_ip_ranked_first():
    idx = IocSimilarityIndex()
    idx.add(IOC_CORPUS)
    results = idx.search("192.168.1.102", k=2)
    top_value = results[0][0]
    assert "192.168.1" in top_value


def test_save_load_roundtrip(tmp_path):
    idx = IocSimilarityIndex()
    idx.add(IOC_CORPUS)
    idx.save(str(tmp_path / "ioc.index"))
    idx2 = IocSimilarityIndex.load(str(tmp_path / "ioc.index"))
    r1 = idx.search("192.168.1.200", k=1)
    r2 = idx2.search("192.168.1.200", k=1)
    assert r1[0][0] == r2[0][0]
