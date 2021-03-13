from docopt import docopt
from kryptos import cli
from kryptos.core import __version__


def main():
    arguments = docopt(cli.__doc__, version=f"Kryptos v{__version__}")
    cli.execute(arguments)
