import random
import string

_greek_alphabet = 'αβγδεζηθικλμνξοπρστυφχψω'


def random_lower(length: int, prefix: str = "") -> str:
    return prefix + "".join(random.choices(string.ascii_lowercase + _greek_alphabet, k=length))
