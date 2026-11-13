"""Read JSON-with-comments configuration as data, preserving string contents."""
import json


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON configuration key")
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError("non-finite JSON configuration value")


def loads(text: str):
    chars = list(text)
    quoted, escaped, index = False, False, 0
    depth = 0
    while index < len(chars):
        char = chars[index]
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in {"{", "["}:
            depth += 1
            if depth > 64:
                raise ValueError("JSON configuration exceeds nesting budget")
        elif char in {"}", "]"}:
            depth -= 1
        elif char == "/" and index + 1 < len(chars) and chars[index + 1] in {"/", "*"}:
            block = chars[index + 1] == "*"
            end = text.find("*/", index + 2) if block else text.find("\n", index + 2)
            if end == -1:
                if block:
                    raise ValueError("unterminated comment")
                end = len(chars)
            elif block:
                end += 2
            for position in range(index, end):
                if chars[position] not in {"\n", "\r"}:
                    chars[position] = " "
            index = end - 1
        index += 1
    # Strip trailing commas only outside quoted strings.
    quoted = escaped = False
    for index, char in enumerate(chars):
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char == ",":
            following = index + 1
            while following < len(chars) and chars[following].isspace():
                following += 1
            if following < len(chars) and chars[following] in {"}", "]"}:
                chars[index] = " "
    return json.loads("".join(chars), object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
