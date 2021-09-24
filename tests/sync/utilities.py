import random
import string


def random_lower(length: int, prefix: str = "") -> str:
    return prefix + "".join(random.choices(string.ascii_lowercase, k=length))
