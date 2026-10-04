import os


def safe_read_static(filename, base_dir):
    """
    Reads a static file within base_dir.
    A PR is supposed to fix a path traversal vulnerability here.
    """
    # Flawed fix: only checks for '..' but misses Windows backslashes or other bypasses
    if ".." in filename:
        raise ValueError("Potential path traversal detected")

    full_path = os.path.join(base_dir, filename)
    with open(full_path, "r") as f:
        return f.read()
