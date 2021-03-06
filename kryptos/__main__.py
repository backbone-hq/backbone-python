"""Kryptos

Usage:
    kryptos config set workspace <workspace>
    kryptos config set token <token>
    kryptos config nuke

    kryptos (authenticate|login) <workspace> <username>

    kryptos entry set <key> <value>
    kryptos entry remove <key>

    kryptos namespace create <key>
    kryptos namespace remove <key>
    kryptos namespace rotate <key>

    kryptos allow <username> <key>
    kryptos deny <username> <key>

    kryptos user create <name> [email] [permissions]...
    kryptos user delete <name>

    kryptos --help
    kryptos --version

Options:
    --help      Display this help message
    --version   Display the Kryptos version
"""

# Adhere to the XDG Directory Spec: http://standards.freedesktop.org/basedir-spec/basedir-spec-latest.html

if __name__ == "__main__":
    exit(0)
