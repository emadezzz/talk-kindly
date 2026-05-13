"""
evaluate.py — Talk Kindly Evaluation Script
============================================
This script tests the offensive language detector against a labelled dataset.
It calculates: Accuracy, Precision, Recall, and F1-Score.

How to run:
    python evaluate.py

Make sure you are in the TalkKindly folder with the venv activated.
"""

import csv
import re
import sqlite3
from datetime import datetime


# ── 1. Preprocessing (same logic as app.py) ──────────────────────────────────

def clean_text(text: str) -> str:
    if not text:
        return ""
    text = text.lower()
    text = re.sub(r'[^\w\s]', ' ', text)
    text = re.sub(r'\d+', '', text)
    text = ' '.join(text.split())
    return text


# ── 2. Load offensive words from the database ────────────────────────────────

def get_offensive_words():
    try:
        conn = sqlite3.connect('talkkindly.db')
        cursor = conn.execute('SELECT word FROM offensive_words')
        words = set(row[0] for row in cursor.fetchall())
        conn.close()
        return words
    except Exception as e:
        print(f"Warning: Could not load words from database ({e})")
        print("Using built-in word list instead.")
        return {
            "idiot", "stupid", "dumb", "moron", "retard", "fool",
            "shit", "ass", "asshole", "bastard", "bitch", "damn", "hell",
            "loser", "hate", "kill", "ugly", "fat", "worthless", "crap",
            "fuck", "fucking", "motherfucker", "dick", "pussy", "cock",
            "whore", "slut", "douchebag", "scumbag", "cunt", "bullshit"
        }


# ── 3. Detection logic (same logic as app.py) ────────────────────────────────

def detect(text: str, offensive_words: set) -> int:
    """Returns 1 if offensive, 0 if safe."""
    if not text or not text.strip():
        return 0

    cleaned = clean_text(text)
    words = cleaned.split()

    # Check direct word match
    found_words = [w for w in words if w in offensive_words]

    # Check obfuscated patterns like f**k, b!tch, a$$
    patterns = [
        r'\b[a-z]{2,}[\*]+[a-z]*\b',
        r'\b[a-z]*[\$\!]+[a-z]+\b',
        r'\b[a-z]+\d+[a-z]*\b',
        r'\b[a-z]*[\*\$\!\d]+[a-z]*[\*\$\!\d]*[a-z]*\b'
    ]
    found_patterns = []
    for pattern in patterns:
        matches = re.findall(pattern, text.lower())
        for match in matches:
            if len(re.sub(r'[\*\$\!\d]', '', match)) >= 2:
                found_patterns.append(match)

    # Check suspicious substrings
    suspicious = []
    for word in words:
        for root in offensive_words:
            if root in word and len(word) >= len(root) - 1:
                if word not in found_words:
                    suspicious.append(word)
                    break

    total = len(found_words) + len(found_patterns) + len(suspicious)
    return 1 if total > 0 else 0


# ── 4. Evaluation metrics ────────────────────────────────────────────────────

def calculate_metrics(results: list) -> dict:
    """
    results: list of (true_label, predicted_label)
    Returns accuracy, precision, recall, F1
    """
    tp = sum(1 for t, p in results if t == 1 and p == 1)  # correctly flagged offensive
    tn = sum(1 for t, p in results if t == 0 and p == 0)  # correctly flagged safe
    fp = sum(1 for t, p in results if t == 0 and p == 1)  # safe flagged as offensive
    fn = sum(1 for t, p in results if t == 1 and p == 0)  # offensive missed

    total = len(results)
    accuracy  = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1        = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

    return {
        "total":     total,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "accuracy":  accuracy,
        "precision": precision,
        "recall":    recall,
        "f1":        f1
    }


# ── 5. Main evaluation ───────────────────────────────────────────────────────

def run_evaluation(dataset_path: str = "test_dataset.csv"):
    print("=" * 55)
    print("  Talk Kindly — Evaluation Report")
    print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 55)

    # Load words
    offensive_words = get_offensive_words()
    print(f"\n✅ Loaded {len(offensive_words)} offensive words from database\n")

    # Load dataset
    results = []
    errors  = []

    try:
        with open(dataset_path, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader, 1):
                text       = row.get('text', '').strip()
                true_label = int(row.get('true_label', 0))
                predicted  = detect(text, offensive_words)
                results.append((true_label, predicted))

                status = "✅" if true_label == predicted else "❌"
                label_text = "OFFENSIVE" if true_label == 1 else "SAFE"
                pred_text  = "OFFENSIVE" if predicted  == 1 else "SAFE"

                if true_label != predicted:
                    errors.append({
                        "row": i,
                        "text": text[:60],
                        "true": label_text,
                        "predicted": pred_text
                    })

    except FileNotFoundError:
        print(f"❌ Dataset file not found: {dataset_path}")
        print("Make sure test_dataset.csv is in the TalkKindly folder.")
        return

    # Calculate metrics
    m = calculate_metrics(results)

    # Print results
    print("─" * 55)
    print(f"  Total examples tested : {m['total']}")
    print(f"  True Positives (TP)   : {m['tp']}  — offensive correctly detected")
    print(f"  True Negatives (TN)   : {m['tn']}  — safe correctly detected")
    print(f"  False Positives (FP)  : {m['fp']}  — safe wrongly flagged")
    print(f"  False Negatives (FN)  : {m['fn']}  — offensive missed")
    print("─" * 55)
    print(f"  Accuracy  : {m['accuracy']  * 100:.1f}%")
    print(f"  Precision : {m['precision'] * 100:.1f}%")
    print(f"  Recall    : {m['recall']    * 100:.1f}%")
    print(f"  F1-Score  : {m['f1']        * 100:.1f}%")
    print("─" * 55)

    if errors:
        print(f"\n⚠️  Misclassified examples ({len(errors)}):\n")
        for e in errors:
            print(f"  Row {e['row']}: \"{e['text']}\"")
            print(f"    True: {e['true']}  →  Predicted: {e['predicted']}\n")
    else:
        print("\n🎉 Perfect score — no misclassifications!")

    print("=" * 55)


if __name__ == "__main__":
    run_evaluation("test_dataset.csv")
