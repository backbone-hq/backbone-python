from pathlib import Path

PROJECT_ROOT: Path = Path(__file__).parents[0]
KRYPTOS_SOURCE: Path = PROJECT_ROOT / "kryptos"
KRYPTOS_TESTS: Path = PROJECT_ROOT / "tests"
ASYNC_PATH: Path = KRYPTOS_SOURCE / "core"


def build(setup_kwargs: dict):
    import unasync

    unasync.unasync_files(
        fpath_list=[str(path) for path in ASYNC_PATH.rglob("**/*.py")],
        rules=[
            unasync.Rule(
                # Replace /core/ with /sync/ in the path
                "/core/",
                "/sync/",
                additional_replacements={
                    # Changes for HTTPx
                    "AsyncClient": "Client",
                    "async_auth_flow": "auth_flow",
                },
            )
        ],
    )
