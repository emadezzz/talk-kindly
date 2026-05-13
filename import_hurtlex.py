"""
import_hurtlex.py — Talk Kindly
================================
This script reads the HurtLex lexicon file and adds the English
offensive words into the existing SQLite database.

It MERGES with your current list — it does NOT delete anything.

How to run:
    python import_hurtlex.py

Make sure hurtlex.tsv is in the same TalkKindly folder.
"""

import sqlite3
import csv
from datetime import datetime

# ── Settings ──────────────────────────────────────────────────────────────────

HURTLEX_FILE = "hurtlex.tsv"
DATABASE     = "talkkindly.db"

# HurtLex categories we want to include
# Full list of categories in HurtLex:
# an = animals, at = ableist, cds = derogatory, ddf = disability,
# ddp = disease, dmc = ethnic, dsi = social inequality,
# is = injurious, or = occupational, ps = sexual,
# qas = questionable, re = religion, rci = racial, svp = violence
WANTED_CATEGORIES = {
    "cds",  # general derogatory terms
    "is",   # injurious / hurtful words
    "ps",   # sexual offensive terms
    "rci",  # racial/ethnic slurs
    "svp",  # violence-related
    "dmc",  # ethnic derogatory
    "re",   # religious offensive
}

# Map HurtLex categories to our existing categories
CATEGORY_MAP = {
    "cds": "moderate",
    "is":  "strong",
    "ps":  "strong",
    "rci": "strong",
    "svp": "moderate",
    "dmc": "strong",
    "re":  "moderate",
}

# ── Main script ───────────────────────────────────────────────────────────────

def import_hurtlex():
    print("=" * 55)
    print("  HurtLex Import — Talk Kindly")
    print("=" * 55)

    # Step 1: Read HurtLex file
    words_to_add = []

    try:
        with open(HURTLEX_FILE, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f, delimiter='\t')
            for row in reader:
                category = row.get('category', '').strip()
                lemma    = row.get('lemma', '').strip().lower()

                # Only English words (single words, no spaces)
                if category in WANTED_CATEGORIES and lemma and ' ' not in lemma:
                    mapped_category = CATEGORY_MAP.get(category, 'moderate')
                    words_to_add.append((lemma, mapped_category))

    except FileNotFoundError:
        print(f"\n❌ File not found: {HURTLEX_FILE}")
        print("Make sure hurtlex.tsv is in your TalkKindly folder.")
        print("\nDownload it from:")
        print("https://raw.githubusercontent.com/valeriobasile/hurtlex/master/lexica/EN/1.0/hurtlex_EN.tsv")
        return

    print(f"\n✅ Read {len(words_to_add)} words from HurtLex")

    # Step 2: Connect to database
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
    except Exception as e:
        print(f"\n❌ Could not connect to database: {e}")
        return

    # Step 3: Check current count
    before = conn.execute('SELECT COUNT(*) FROM offensive_words').fetchone()[0]
    print(f"📊 Words in database before import: {before}")

    # Step 4: Insert words (skip duplicates automatically)
    added   = 0
    skipped = 0
    now     = datetime.now().isoformat()

    for word, category in words_to_add:
        try:
            cursor.execute(
                'INSERT OR IGNORE INTO offensive_words (word, category, added_at) VALUES (?, ?, ?)',
                (word, category, now)
            )
            if cursor.rowcount == 1:
                added += 1
            else:
                skipped += 1
        except Exception as e:
            print(f"  Warning: could not insert '{word}': {e}")

    conn.commit()

    # Step 5: Check new count
    after = conn.execute('SELECT COUNT(*) FROM offensive_words').fetchone()[0]
    conn.close()

    # Step 6: Print summary
    print(f"✅ New words added : {added}")
    print(f"⏭️  Already existed : {skipped}")
    print(f"📊 Words in database after import: {after}")
    print("\n✅ Done! Your admin panel will now show all the new words.")
    print("=" * 55)


if __name__ == "__main__":
    import_hurtlex()
