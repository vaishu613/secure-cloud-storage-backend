
from pathlib import Path
import hashlib

INPUT_DIR = Path("input")
OUTPUT_FILE = Path("output/recovered_file.pdf")


def sha256_file(path):
    digest = hashlib.sha256()

    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def main():
    originals = list(INPUT_DIR.glob("*.pdf"))

    if len(originals) != 1:
        raise ValueError(
            f"Expected exactly one original PDF in input; found {len(originals)}."
        )

    original = originals[0]

    if not OUTPUT_FILE.is_file():
        raise FileNotFoundError(f"Recovered PDF not found: {OUTPUT_FILE}")

    original_hash = sha256_file(original)
    recovered_hash = sha256_file(OUTPUT_FILE)

    print("Original file: ", original.name)
    print("Original size: ", original.stat().st_size, "bytes")
    print("Recovered size:", OUTPUT_FILE.stat().st_size, "bytes")
    print("Original SHA-256: ", original_hash)
    print("Recovered SHA-256:", recovered_hash)

    if original_hash == recovered_hash:
        print("\nSUCCESS: Files are identical. Integrity verified!")
    else:
        print("\nFAILURE: Files differ. Check the split and recovery process.")


if __name__ == "__main__":
    main()
