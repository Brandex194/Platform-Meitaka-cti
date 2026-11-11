from app.ml.classifier import DarkWebClassifier


def test_predict_returns_probabilities():
    clf = DarkWebClassifier()
    clf.train(
        ["buy drugs tor", "financial report q3", "leaked credentials onion"],
        [1, 0, 1],
    )
    scores = clf.predict(["tor market", "quarterly earnings"])
    assert len(scores) == 2
    assert all(0.0 <= s <= 1.0 for s in scores)


def test_predict_darkweb_scores_higher_than_benign():
    clf = DarkWebClassifier()
    clf.train(
        ["darknet market tor hidden", "annual report pdf", "leaked password onion site"],
        [1, 0, 1],
    )
    darkweb = clf.predict(["tor hidden service leak"])[0]
    benign = clf.predict(["quarterly financial report"])[0]
    assert darkweb > benign


def test_save_load_roundtrip(tmp_path):
    path = str(tmp_path / "clf.pkl")
    clf = DarkWebClassifier()
    clf.train(["dark web", "normal text"], [1, 0])
    clf.save(path)
    clf2 = DarkWebClassifier.load(path)
    s1 = clf.predict(["tor leak"])
    s2 = clf2.predict(["tor leak"])
    assert abs(s1[0] - s2[0]) < 0.001
