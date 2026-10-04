"""Locate read-only datasets separately from the writable experiment workspace."""

from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent


def dataset_dir(name: str, workspace_dir: str | Path | None = None) -> Path:
    """Use a workspace dataset when present, otherwise use the bundled dataset."""
    if name not in {"workflows", "scenarios"}:
        raise ValueError(f"Unknown dataset: {name}")
    workspace = Path(workspace_dir) if workspace_dir is not None else Path.cwd()
    for candidate in (workspace / name, workspace / "src/gitinject" / name, workspace / "src/benchmark" / name):
        if candidate.is_dir():
            return candidate.resolve()
    return PACKAGE_DIR / name


def research_dir(workspace_dir: str | Path | None = None) -> Path:
    """Locate the scanner warm-start notes in a workspace, wheel, or source tree."""
    workspace = Path(workspace_dir) if workspace_dir is not None else Path.cwd()
    candidates = (
        workspace / "research/scenarios",
        PACKAGE_DIR / "data/research/scenarios",
        PACKAGE_DIR.parent.parent / "research/scenarios",
    )
    for candidate in candidates:
        if candidate.is_dir():
            return candidate.resolve()
    raise FileNotFoundError("Scanner warm-start research notes are unavailable")
