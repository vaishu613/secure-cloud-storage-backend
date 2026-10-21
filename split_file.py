
from pathlib import Path


def split_file(file_path):
    file_path = Path(file_path)
    output_dir = Path("encrypted_blocks")
    output_dir.mkdir(parents=True, exist_ok=True)

    data = file_path.read_bytes()
    total_size = len(data)
    block_size = (total_size + 3) // 4

    for i in range(4):
        start = i * block_size
        end = min(start + block_size, total_size)
        block_data = data[start:end]

        block_path = output_dir / f"block_{i + 1}.bin"
        block_path.write_bytes(block_data)

        print(f"Created {block_path}")

    print("File split into 4 blocks successfully.")


if __name__ == "__main__":
    input_dir = Path("input")
    files = [p for p in input_dir.iterdir() if p.is_file()]

    if not files:
        raise FileNotFoundError("Put a file inside the input folder first.")

    split_file(files[0])
