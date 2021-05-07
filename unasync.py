from pathlib import Path
import re


ROOT: Path = Path(__file__).parents[0]
SOURCE: Path = ROOT / "kryptos"
TESTS: Path = ROOT / "tests"


def compile_substitutions(substitutions: dict) -> dict:
    return {re.compile(r"(^|\b)" + regex + r"($|\b)"): replacement for regex, replacement in substitutions.items()}


_ASYNC_TO_SYNC = compile_substitutions(
    {
        # Base Python
        "__aenter__": "__enter__",
        "__aexit__": "__exit__",
        "__aiter__": "__iter__",
        "__anext__": "__next__",
        "asynccontextmanager": "contextmanager",
        "AsyncIterable": "Iterable",
        "AsyncIterator": "Iterator",
        "AsyncGenerator": "Generator",
        "StopAsyncIteration": "StopIteration",
        "async def": "def",
        "async with": "with",
        "async for": "for",
        "await ": "",
        # Pytest
        "@pytest.mark.asyncio": "",
        # Kryptos
        "kryptos.core": "kryptos.sync",
        # HTTPx
        "async_auth_flow": "auth_flow",
        "httpx.AsyncClient": "httpx.Client",
    }
)


def unasync_line(line: str, replacements: dict) -> str:
    for regex, repl in replacements.items():
        line = re.sub(regex, repl, line)
    return line


def unasync_file(in_path: Path, out_path: Path, replacements: dict):
    with open(in_path, "r") as in_file:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w", newline="") as out_file:
            for line in in_file.readlines():
                line = unasync_line(line, replacements)
                out_file.write(line)


def unasync_dir(from_dir: Path, out_dir: Path, replacements: dict):
    async_to_sync = _ASYNC_TO_SYNC.copy()
    async_to_sync.update(compile_substitutions(replacements))

    for filepath in from_dir.rglob("**/*.py"):
        out_path = str(filepath).replace(str(from_dir), str(out_dir))
        print(filepath, "->", out_path)
        unasync_file(filepath, Path(out_path), replacements=async_to_sync)


if __name__ == "__main__":
    unasync_dir(SOURCE / "core", SOURCE / "sync", replacements={})
    unasync_dir(TESTS / "core", TESTS / "sync", replacements={})
