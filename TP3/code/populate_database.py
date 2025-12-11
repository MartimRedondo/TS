import os
import json
from database_manager import DatabaseManager, COMMON_DOMAIN_BASE_NAME
from typing import Optional

KEY_FILE = "encryption_key.json"
BASE_DOMAIN_NAMES = ["Projects", "Operations", "Intelligence", COMMON_DOMAIN_BASE_NAME]

def save_encryption_key(key: bytes):
    key_data = {"key": key.hex(), "note": "This key is required to decrypt files in the database"}
    with open(KEY_FILE, 'w') as f: json.dump(key_data, f, indent=2)
    print(f"Encryption key saved to {KEY_FILE}")

def load_encryption_key() -> Optional[bytes]:
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'r') as f: key_data = json.load(f)
        return bytes.fromhex(key_data["key"])
    return None

def populate_database():
    db_file = "blp_database.json"
    if os.path.exists(db_file):
        os.remove(db_file)
        print(f"Removed existing database: {db_file}")

    existing_key = load_encryption_key()
    db = DatabaseManager(db_file, encryption_key=existing_key)
    if not existing_key:
        save_encryption_key(db.get_encryption_key())
        print(f"Generated new encryption key and saved to {KEY_FILE}")
    else:
        print(f"Using existing encryption key from {KEY_FILE}")
    print(f"Initialized database: {db_file}")
    print("-" * 60)

    try:
        levels_data = [(0, "Top Secret"), (1, "Secret"), (2, "Confidential"), (3, "Public")]
        print("Creating security levels:")
        for val, name in levels_data:
            db.create_level(val, name)
            print(f"  Level {val}: {name} - Created")
        print()

        print("Creating domain configurations (base names per level):")
        for level_val, _ in levels_data:
            level_obj = db.get_level(level_val)
            print(f"  For Level {level_val} ({level_obj['name']}):")
            for base_name in BASE_DOMAIN_NAMES:
                if db.create_domain_config(base_name, level_val):
                    print(f"    Configured: '{base_name}' for L{level_val}")
        print()

        users_data = [
            ("admin", "admin123", 0, BASE_DOMAIN_NAMES, True, True),
            ("director", "topsecret1", 0, ["Intelligence", "Operations"], False, True),
            ("analyst_alpha", "secure456", 0, ["Intelligence"], False, False),
            ("colonel_smith", "military_pass", 1, ["Operations"], False, True),
            ("diplomat_jones", "embassy_pass", 1, ["Projects"], False, False),
            ("hr_manager", "hr_pass", 2, ["Operations"], False, False), # Will also get "General"
            ("researcher_doe", "research_pass", 2, ["Projects", "Intelligence"], False, True),
            ("public_user", "guest_pass", 3, [], False, False), # Will get "General"
            ("intern_alice", "intern_pass", 3, ["Projects"], False, False),
        ]
        print("Creating users (assigned base domain names):")
        for nome, pw, lvl, assigned_bases, adm, trust in users_data:
            try:
                db.create_user(nome, pw, lvl, assigned_bases, adm, trust)
                user_obj = db.get_user(nome)
                print(f"  User '{nome}' (L{lvl}): Created. Assigned base domains (incl. common): {user_obj['domains']}")
            except ValueError as ve:
                print(f"  ERROR Creating User '{nome}': {ve}")
        print()

        sample_files_data = [
            # filename, base_domain_name, file_level, content_bytes
            ("launch_codes.txt", "Intelligence", 0, b"TS Data: Launch codes..."),
            ("agent_roster.txt", "Intelligence", 0, b"TS Data: Agent roster..."),
            ("q1_budget.xlsx", "Projects", 1, b"Secret Data: Q1 Budget..."),
            ("project_phoenix.doc", "Projects", 1, b"Secret Data: Project Phoenix details..."),
            ("employee_reviews.pdf", "Operations", 2, b"Confidential Data: Employee reviews..."),
            ("research_paper_draft.txt", COMMON_DOMAIN_BASE_NAME, 2, b"Confidential Data in General L2"),
            ("public_announcement.txt", COMMON_DOMAIN_BASE_NAME, 3, b"Public info: Announcement..."),
        ]
        print("Creating sample files (associated with base_domain_name and file_level):")
        for fname, b_dom_name, f_lvl, content_b in sample_files_data:
            try:
                if not db.get_domain_config(b_dom_name, f_lvl):
                    print(f"  Skipping file '{fname}': Domain config '{b_dom_name}' for L{f_lvl} missing.")
                    continue
                if db.store_file(fname, b_dom_name, f_lvl, content_b):
                    print(f"  File '{fname}' stored in domain '{b_dom_name}' at L{f_lvl}")
                else:
                    print(f"  File '{fname}' failed to store (likely exists).")
            except Exception as e:
                print(f"  Error storing file '{fname}': {e}")
        print("\n" + "=" * 60 + "\nDATABASE POPULATION COMPLETE\n" + "=" * 60)

    except Exception as e:
        print(f"MAJOR Error during database population: {e}")
        import traceback
        traceback.print_exc()
    finally:
        db.close()

if __name__ == "__main__":
    populate_database()