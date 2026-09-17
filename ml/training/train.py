"""Train a bounded character n-gram HTTP classifier from JSONL records.

Each input line must contain {"text": "...", "label": "..."}. The test
split is held out and never used for model selection.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("dataset", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    rows = [json.loads(line) for line in args.dataset.read_text(encoding="utf-8").splitlines() if line.strip()]
    texts = [str(row["text"])[:65536] for row in rows]
    labels = [str(row["label"]) for row in rows]
    train_x, test_x, train_y, test_y = train_test_split(texts, labels, test_size=0.2, random_state=42, stratify=labels)
    model = Pipeline([("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(3, 5), min_df=1, max_features=100000)), ("classifier", LogisticRegression(max_iter=1000, class_weight="balanced"))])
    model.fit(train_x, train_y)
    prediction = model.predict(test_x)
    print(classification_report(test_y, prediction, zero_division=0))
    print(confusion_matrix(test_y, prediction, labels=sorted(set(labels))))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, args.output)


if __name__ == "__main__":
    main()
