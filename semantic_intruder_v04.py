# -*- coding: utf-8 -*-
"""Semantic Intruder for Burp Suite: Python 2.7/Jython, dependency-free.

Load this file as a Python extension. The pure core also runs on CPython 3
for tests; the Burp interface requires Jython and Burp's Extender API.
"""
from __future__ import unicode_literals

import base64
import copy
import gzip
import hashlib
import io
import json
import re
import sys
import threading
import time
from collections import OrderedDict
from decimal import Decimal

try:
    text_type = unicode
    integer_types = (int, long)
except NameError:
    text_type = str
    integer_types = (int,)

VERSION = "0.4.1"
MAX_REQUEST = 1000000
MAX_RESPONSE = 2000000
MAX_TESTS = 50
MEANINGS = ("Identificador", "Texto", "N\u00famero", "Booleano")
IDENTIFIER, TEXT, NUMBER, BOOLEAN = MEANINGS
JSON_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
WS = " \\t\\r\\n"

# Runtime detection kept deliberately conservative for old/new Burp releases
# that still expose the legacy Extender API through Jython.
try:
    import java  # Jython only
    IS_JYTHON = True
except ImportError:
    IS_JYTHON = False


class ValidationError(ValueError):
    pass


def as_text(value):
    if isinstance(value, text_type):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return text_type(value)


def json_text(value):
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValidationError("N\u00famero n\u00e3o finito.")
        return text_type(value)
    return as_text(json.dumps(value, ensure_ascii=True, allow_nan=False,
                              separators=(",", ":")))


def value_text(value):
    return value if isinstance(value, text_type) else json_text(value)


def ui_text(value):
    """Return an ASCII-safe text representation for old Jython/Swing bridges."""
    value = as_text(value)
    try:
        return value.encode("ascii", "backslashreplace").decode("ascii")
    except Exception:
        return text_type(value)


def pointer_escape(value):
    return value.replace("~", "~0").replace("/", "~1")


def pointer_parts(pointer):
    if pointer == "":
        return []
    if not pointer.startswith("/") or re.search(r"~(?![01])", pointer):
        raise ValidationError("Use JSON Pointer v\u00e1lido, como /meta/requestId.")
    return [p.replace("~1", "/").replace("~0", "~")
            for p in pointer[1:].split("/")]


class JsonDocument(object):
    """Strict JSON reader with exact token spans for surgical mutations."""
    def __init__(self, source):
        self.source = as_text(source)
        if len(self.source) > MAX_REQUEST:
            raise ValidationError("JSON maior que 1 milh\u00e3o de caracteres.")
        self.pos = 0
        self.spans = OrderedDict()
        self.values = OrderedDict()
        self.decoder = json.JSONDecoder()
        self.root = self._value("", 0)
        self._space()
        if self.pos != len(self.source):
            raise ValidationError("Conte\u00fado ap\u00f3s o JSON.")

    def _space(self):
        while self.pos < len(self.source) and self.source[self.pos] in WS:
            self.pos += 1

    def _string(self):
        try:
            value, end = self.decoder.raw_decode(self.source, self.pos)
        except ValueError:
            raise ValidationError("String JSON inv\u00e1lida.")
        if not isinstance(value, text_type):
            raise ValidationError("Chave JSON deve ser texto.")
        self.pos = end
        return value

    def _value(self, pointer, depth):
        if depth > 64:
            raise ValidationError("JSON excede 64 n\u00edveis.")
        self._space()
        begin = self.pos
        if self.pos >= len(self.source):
            raise ValidationError("JSON incompleto.")
        char = self.source[self.pos]
        if char == '"':
            value = self._string()
        elif char in "[{":
            is_object = char == "{"
            end_char = "}" if is_object else "]"
            value = OrderedDict() if is_object else []
            self.pos += 1
            self._space()
            if self.pos < len(self.source) and self.source[self.pos] == end_char:
                self.pos += 1
            else:
                while True:
                    self._space()
                    if is_object:
                        if self.pos >= len(self.source) or self.source[self.pos] != '"':
                            raise ValidationError("Chave JSON inv\u00e1lida.")
                        key = self._string()
                        if key in value:
                            raise ValidationError("Chaves JSON duplicadas n\u00e3o s\u00e3o editadas.")
                        self._space()
                        if self.pos >= len(self.source) or self.source[self.pos] != ":":
                            raise ValidationError("Falta ':' no JSON.")
                        self.pos += 1
                        value[key] = self._value(pointer + "/" + pointer_escape(key), depth + 1)
                    else:
                        value.append(self._value(pointer + "/" + text_type(len(value)), depth + 1))
                    self._space()
                    if self.pos >= len(self.source):
                        raise ValidationError("JSON incompleto.")
                    token = self.source[self.pos]
                    self.pos += 1
                    if token == end_char:
                        break
                    if token != ",":
                        raise ValidationError("Separador JSON inv\u00e1lido.")
        else:
            matched = False
            for literal, result in (("true", True), ("false", False), ("null", None)):
                if self.source.startswith(literal, self.pos):
                    self.pos += len(literal)
                    value = result
                    matched = True
                    break
            if not matched:
                number = JSON_NUMBER.match(self.source, self.pos)
                if number is None:
                    raise ValidationError("Valor JSON inv\u00e1lido.")
                token = number.group(0)
                self.pos = number.end()
                value = Decimal(token) if any(x in token for x in ".eE") else int(token)
        # Only leaves and empty containers are selectable; spans preserve all other bytes.
        if not isinstance(value, (dict, list)) or not value:
            if len(self.values) >= 2000:
                raise ValidationError("JSON excede 2.000 campos.")
            self.spans[pointer] = (begin, self.pos)
            self.values[pointer] = value
        return value

    def replace(self, pointer, value):
        if pointer not in self.spans:
            raise ValidationError("Campo JSON n\u00e3o encontrado.")
        begin, end = self.spans[pointer]
        return self.source[:begin] + json_text(value) + self.source[end:]


def encode_component(value, path=False):
    raw = bytearray(value_text(value).encode("utf-8"))
    allowed = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    safe = set(bytearray(allowed))
    return "".join(chr(c) if c in safe else ("+" if c == 32 and not path else "%%%02X" % c)
                   for c in raw)


def decode_component(value, path=False):
    # Decode UTF-8 strictly; preserve literal '+' in path segments.
    value = as_text(value)
    out = bytearray()
    i = 0
    while i < len(value):
        char = value[i]
        if char == "%":
            if i + 2 >= len(value) or not re.match(r"^[0-9a-fA-F]{2}$", value[i + 1:i + 3]):
                raise ValidationError("Percent-encoding inv\u00e1lido.")
            out.append(int(value[i + 1:i + 3], 16))
            i += 3
        else:
            out.extend((" " if char == "+" and not path else char).encode("utf-8"))
            i += 1
    return out.decode("utf-8")


def replace_pair(source, index, value):
    pairs = source.split("&")
    if index < 0 or index >= len(pairs):
        raise ValidationError("Ocorr\u00eancia do par\u00e2metro n\u00e3o encontrada.")
    name = pairs[index].split("=", 1)[0]
    pairs[index] = name + "=" + encode_component(value)
    return "&".join(pairs)


class Request(object):
    def __init__(self, raw):
        self.raw = raw
        if len(raw) > MAX_REQUEST:
            raise ValidationError("Requisi\u00e7\u00e3o maior que 1 MB.")
        if b"\r\n\r\n" not in raw:
            raise ValidationError("Requisi\u00e7\u00e3o precisa de headers e separador CRLF.")
        head, self.body = raw.split(b"\r\n\r\n", 1)
        self.lines = head.decode("iso-8859-1").split("\r\n")
        start = self.lines[0].split(" ")
        if len(start) != 3 or not start[1].startswith("/") or not re.match(r"^HTTP/(1\.[01]|2(?:\.0)?)$", start[2]):
            raise ValidationError("Use uma requisi\u00e7\u00e3o HTTP com caminho relativo, como GET /api HTTP/1.1.")
        self.method, self.path, self.version = start
        self.route, separator, self.query = self.path.partition("?")
        self.has_query = bool(separator)
        self.headers = []
        for index, line in enumerate(self.lines[1:], 1):
            if ":" not in line or line.startswith((" ", "\t")):
                raise ValidationError("Header inv\u00e1lido ou dobrado em v\u00e1rias linhas.")
            name, value = line.split(":", 1)
            self.headers.append((name, value.strip(" \t"), index))
        if self.header("Transfer-Encoding"):
            raise ValidationError("Normalize Transfer-Encoding da requisi\u00e7\u00e3o no Repeater antes de importar.")
        if len(self.header_entries("Content-Length")) > 1:
            raise ValidationError("Content-Length repetido n\u00e3o suportado.")

    def header_entries(self, name):
        return [h for h in self.headers if h[0].lower() == name.lower()]

    def header(self, name):
        entries = self.header_entries(name)
        return entries[0][1] if entries else ""

    def rebuild(self, path=None, body=None, header_index=None, header_value=None):
        lines = list(self.lines)
        if path is not None:
            if any(ord(c) < 32 or c in " #" for c in path):
                raise ValidationError("Caminho HTTP inv\u00e1lido.")
            lines[0] = "%s %s %s" % (self.method, path, self.version)
        if header_index is not None:
            if any(ord(c) < 32 and c != "\t" for c in header_value):
                raise ValidationError("Valor de header cont\u00e9m caractere de controle.")
            name, previous = lines[header_index].split(":", 1)
            spacing = previous[:len(previous) - len(previous.lstrip(" \t"))]
            lines[header_index] = name + ":" + spacing + header_value
        payload = self.body if body is None else body
        if body is not None:
            lengths = self.header_entries("Content-Length")
            if lengths:
                idx = lengths[0][2]
                lines[idx] = lines[idx].split(":", 1)[0] + ": " + text_type(len(payload))
            else:
                lines.append("Content-Length: " + text_type(len(payload)))
        return ("\r\n".join(lines) + "\r\n\r\n").encode("iso-8859-1") + payload


    def add_header(self, name, value):
        name = as_text(name).strip()
        value = as_text(value)
        if not name or not re.match(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$", name):
            raise ValidationError("Nome de header invalido.")
        if "\r" in value or "\n" in value:
            raise ValidationError("Valor do novo header nao pode conter CR/LF.")
        if self.header_entries(name):
            raise ValidationError("O header '%s' ja existe. Selecione o header existente para testa-lo." % name)
        lines = list(self.lines)
        lines.append(name + ": " + value)
        return ("\r\n".join(lines) + "\r\n\r\n").encode("iso-8859-1") + self.body


class Target(object):
    def __init__(self, location, name, value, index=0, pointer="", codec="json", padded=True):
        self.location, self.name, self.value = location, name, value
        self.index, self.pointer, self.codec, self.padded = index, pointer, codec, padded
        self.typed = location in ("JSON", "HEADER_JSON")

    def label(self):
        return "%s | %s%s" % (self.location, self.name, (" | " + self.pointer) if self.pointer else "")


EXCLUDED_HEADERS = set(("host", "content-length", "transfer-encoding", "connection",
    "authorization", "proxy-authorization", "cookie", "content-type", "content-encoding",
    "accept-encoding", "x-api-key", "x-auth-token"))


def decode_header(value, codec):
    if codec == "json":
        return value.encode("iso-8859-1").decode("utf-8")
    if re.search(r"[^A-Za-z0-9+/=_-]", value) or len(value.rstrip("=")) % 4 == 1:
        raise ValidationError("Base64 inv\u00e1lido.")
    if "=" in value.rstrip("=") or len(value) - len(value.rstrip("=")) > 2:
        raise ValidationError("Padding Base64 inv\u00e1lido.")
    if codec == "base64" and ("-" in value or "_" in value):
        raise ValidationError("Alfabeto Base64url.")
    if codec == "base64url" and ("+" in value or "/" in value):
        raise ValidationError("Alfabeto Base64 padr\u00e3o.")
    padded = (value + "=" * (-len(value) % 4)).encode("ascii")
    data = base64.urlsafe_b64decode(padded) if codec == "base64url" else base64.b64decode(padded)
    return data.decode("utf-8")


def encode_header(value, codec, padded=True):
    if codec == "json":
        return value.encode("utf-8").decode("iso-8859-1")
    raw = value.encode("utf-8")
    out = base64.urlsafe_b64encode(raw) if codec == "base64url" else base64.b64encode(raw)
    value = out.decode("ascii")
    return value if padded else value.rstrip("=")


def discover(request):
    fields, notices = [], []
    for i, segment in enumerate(request.route.split("/")):
        if segment:
            try:
                fields.append(Target("PATH", "segmento " + text_type(i), decode_component(segment, True), i))
            except (ValueError, UnicodeError):
                notices.append("Segmento de path com encoding inv\u00e1lido ignorado.")

    def pairs(source, location):
        for i, part in enumerate(source.split("&")):
            if part:
                name, sep, value = part.partition("=")
                try:
                    fields.append(Target(location, decode_component(name) + " [%d]" % i, decode_component(value), i))
                except (ValueError, UnicodeError):
                    notices.append("Par\u00e2metro com encoding inv\u00e1lido ignorado.")

    pairs(request.query, "QUERY")
    ct = request.header("Content-Type").lower()
    charset = re.search(r"charset\s*=\s*\"?([^;\s\"]+)", ct)
    encoded = request.header("Content-Encoding").lower() not in ("", "identity")
    if encoded or (charset and charset.group(1) != "utf-8"):
        notices.append("Campos do corpo indispon\u00edveis para compress\u00e3o ou charset diferente de UTF-8.")
    elif "application/json" in ct or "+json" in ct:
        try:
            doc = JsonDocument(request.body.decode("utf-8"))
            fields.extend(Target("JSON", "body", value, pointer=p) for p, value in doc.values.items())
        except (ValueError, UnicodeError) as exc:
            notices.append("Corpo JSON n\u00e3o edit\u00e1vel: " + as_text(exc))
    elif "application/x-www-form-urlencoded" in ct:
        try:
            pairs(request.body.decode("utf-8"), "FORM")
        except UnicodeError:
            notices.append("Form sem UTF-8 v\u00e1lido.")
    elif request.body:
        notices.append("Formato do corpo n\u00e3o suportado; campos de path/query/headers continuam dispon\u00edveis.")
    for name, value, index in request.headers:
        if name.lower() in EXCLUDED_HEADERS:
            continue
        if len(request.header_entries(name)) != 1:
            notices.append("Header repetido n\u00e3o editado: " + name)
            continue
        if name.lower() in ("x-charon", "x-charon-params"):
            for codec in ("json", "base64", "base64url"):
                try:
                    doc = JsonDocument(decode_header(value, codec))
                    if not isinstance(doc.root, (dict, list)):
                        continue
                    fields.extend(Target("HEADER_JSON", name, v, index, p, codec, value.endswith("="))
                                  for p, v in doc.values.items())
                    break
                except (ValueError, TypeError, UnicodeError):
                    continue
            else:
                notices.append(name + ": formato desconhecido; suporta JSON e Base64/Base64url de JSON UTF-8.")
        else:
            fields.append(Target("HEADER", name, value, index))
    if len(fields) > 2500:
        raise ValidationError("Requisi\u00e7\u00e3o excede 2.500 campos.")
    return fields, list(OrderedDict.fromkeys(notices))


def mutate(request, target, value):
    if target.location == "PATH":
        parts = request.route.split("/")
        parts[target.index] = encode_component(value, True)
        return request.rebuild(path="/".join(parts) + (("?" + request.query) if request.has_query else ""))
    if target.location == "QUERY":
        return request.rebuild(path=request.route + "?" + replace_pair(request.query, target.index, value))
    if target.location == "FORM":
        return request.rebuild(body=replace_pair(request.body.decode("utf-8"), target.index, value).encode("utf-8"))
    if target.location == "JSON":
        return request.rebuild(body=JsonDocument(request.body.decode("utf-8")).replace(target.pointer, value).encode("utf-8"))
    if target.location == "HEADER":
        wire_value = value_text(value).encode("utf-8").decode("iso-8859-1")
        return request.rebuild(header_index=target.index, header_value=wire_value)
    if target.location == "HEADER_JSON":
        doc = JsonDocument(decode_header(request.header(target.name), target.codec))
        modified = encode_header(doc.replace(target.pointer, value), target.codec, target.padded)
        return request.rebuild(header_index=target.index, header_value=modified)
    raise ValidationError("Local de campo desconhecido.")


def classify(name, value):
    lower = re.sub(r"\s+\[[0-9]+\]$", "", name).lower()
    if lower.endswith("id") or "identifier" in lower or "uuid" in lower:
        return IDENTIFIER
    if isinstance(value, bool) or (isinstance(value, text_type) and value in ("true", "false")):
        return BOOLEAN
    if isinstance(value, integer_types + (Decimal, float)):
        return NUMBER
    if isinstance(value, text_type):
        if re.match(r"^[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$", value):
            return IDENTIFIER
        if re.match(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$", value):
            return NUMBER
    return TEXT


class TestCase(object):
    def __init__(self, name, value, authorization=False):
        self.name, self.value, self.authorization = name, value, authorization


def canonical(value):
    if value is None:
        return ("null",)
    if isinstance(value, bool):
        return ("boolean", value)
    if isinstance(value, integer_types + (Decimal, float)):
        return ("number", Decimal(text_type(value)))
    if isinstance(value, dict):
        return ("object", tuple(sorted((k, canonical(v)) for k, v in value.items())))
    if isinstance(value, list):
        return ("array", tuple(canonical(v) for v in value))
    return ("string", value)


def plan(meaning, target, alternatives="", validation=True):
    tests = []
    if meaning not in MEANINGS:
        raise ValidationError("Significado desconhecido.")
    if meaning == IDENTIFIER:
        lines = [v.strip() for v in alternatives.splitlines() if v.strip()]
        if len(lines) > MAX_TESTS:
            raise ValidationError("Informe at\u00e9 50 IDs por rodada.")
        for line in lines:
            if len(line) > 512:
                raise ValidationError("Identificador excede 512 caracteres.")
            value = line
            if target.typed and isinstance(target.value, integer_types + (Decimal, float)) and not isinstance(target.value, bool):
                if not re.match(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$", line):
                    raise ValidationError("O campo JSON \u00e9 num\u00e9rico; informe IDs num\u00e9ricos.")
                value = Decimal(line)
            tests.append(TestCase("Autoriza\u00e7\u00e3o: massa alternativa", value, True))
    if validation:
        tests.append(TestCase("Valor vazio", ""))
        if target.typed:
            tests.extend((TestCase("Nulo JSON", None), TestCase("Objeto no lugar do valor", {}), TestCase("Lista no lugar do valor", [])))
        if meaning == IDENTIFIER:
            tests.append(TestCase("Formato inv\u00e1lido", "invalid-id!"))
        elif meaning == TEXT:
            tests.extend((TestCase("Espa\u00e7o em branco", " "), TestCase("Texto Unicode", "a\u00e7\u00e3o_\u65e5\u672c"), TestCase("Texto com 256 caracteres", "A" * 256)))
            if target.typed:
                tests.append(TestCase("N\u00famero no lugar do texto", 1))
        elif meaning == NUMBER:
            for value in ("-1", "0", "1.5", "2147483648"):
                tests.append(TestCase("Limite/tipo num\u00e9rico: " + value, Decimal(value) if target.typed else value))
            tests.append(TestCase("Texto no lugar do n\u00famero", "not-a-number"))
        elif meaning == BOOLEAN:
            tests.extend((TestCase("Booleano verdadeiro", True if target.typed else "true"), TestCase("Booleano falso", False if target.typed else "false"), TestCase("Coer\u00e7\u00e3o num\u00e9rica", 1 if target.typed else "1")))
            if target.typed:
                tests.append(TestCase("Booleano como texto", "true"))
    seen, output = set(), []
    for test in tests:
        key = (test.authorization, canonical(test.value))
        if canonical(test.value) != canonical(target.value) and key not in seen:
            output.append(test)
            seen.add(key)
    if not output:
        raise ValidationError("Nenhum teste gerado. Informe IDs alternativos ou habilite valida\u00e7\u00e3o.")
    if len(output) > MAX_TESTS:
        raise ValidationError("M\u00e1ximo de 50 testes; reduza a massa alternativa.")
    return output


def normalized(body, ignored):
    root = JsonDocument(body.decode("utf-8")).root
    for pointer in ignored:
        parts = pointer_parts(pointer)
        if not parts:
            raise ValidationError("A raiz inteira n\u00e3o pode ser ignorada.")
        node = root
        try:
            for part in parts[:-1]:
                node = node[int(part)] if isinstance(node, list) else node[part]
            last = int(parts[-1]) if isinstance(node, list) else parts[-1]
            if isinstance(node, list) and not 0 <= last < len(node):
                continue
            if isinstance(node, dict) and last not in node:
                continue
            node[last] = "<campo ignorado>"
        except (KeyError, ValueError, TypeError, IndexError):
            pass
    return root


def flatten(value, pointer="", output=None):
    output = {} if output is None else output
    if isinstance(value, dict) and value:
        for key, child in value.items():
            flatten(child, pointer + "/" + pointer_escape(key), output)
    elif isinstance(value, list) and value:
        for index, child in enumerate(value):
            flatten(child, pointer + "/" + text_type(index), output)
    else:
        output[pointer] = canonical(value)
    return output


def compare(base, response, authorization=False, ignored=()):
    try:
        left, right = normalized(base.body, ignored), normalized(response.body, ignored)
        same = canonical(left) == canonical(right)
        left_paths, right_paths = flatten(left), flatten(right)
        missing = object()
        changes = [p or "(raiz)" for p in sorted(set(left_paths) | set(right_paths))
                   if left_paths.get(p, missing) != right_paths.get(p, missing)][:30]
    except (ValueError, UnicodeError):
        same = base.body == response.body
        changes = [] if same else ["Corpo diferente; diff JSON indispon\u00edvel"]
    code = response.status
    if not 200 <= base.status < 300:
        conclusion = "Inconclusivo: baseline sem sucesso"
    elif code >= 500:
        conclusion = "Revisar: erro de servidor"
    elif code in (401, 403):
        conclusion = "Acesso recusado; confirmar regra esperada"
    elif code == 404:
        conclusion = "N\u00e3o encontrado ou ocultado; inconclusivo"
    elif 300 <= code < 400:
        conclusion = "Redirecionamento; inconclusivo"
    elif authorization and 200 <= code < 300:
        conclusion = "Revisar autoriza\u00e7\u00e3o: 2xx com ID alternativo (n\u00e3o confirma IDOR)"
    elif code >= 400:
        conclusion = "Entrada recusada; confirmar contrato"
    elif 200 <= code < 300:
        conclusion = "Entrada aceita; validar contrato e efeito"
    else:
        conclusion = "Inconclusivo"
    return {"same": same, "changes": changes, "conclusion": conclusion}


def dechunk(raw):
    chunks, pos, total = [], 0, 0
    while True:
        end = raw.find(b"\r\n", pos)
        if end < 0:
            raise ValidationError("Resposta chunked incompleta.")
        size_text = raw[pos:end].split(b";", 1)[0]
        if not re.match(b"^[0-9a-fA-F]+$", size_text):
            raise ValidationError("Tamanho chunked inv\u00e1lido.")
        size = int(size_text, 16)
        pos = end + 2
        if size == 0:
            if raw[pos:pos + 2] != b"\r\n" and b"\r\n\r\n" not in raw[pos:]:
                raise ValidationError("Final chunked incompleto.")
            return b"".join(chunks)
        total += size
        if total > MAX_RESPONSE or pos + size + 2 > len(raw) or raw[pos + size:pos + size + 2] != b"\r\n":
            raise ValidationError("Resposta chunked inv\u00e1lida ou maior que 2 MB.")
        chunks.append(raw[pos:pos + size])
        pos += size + 2


class Response(object):
    def __init__(self, request, raw):
        self.request, self.raw = request, raw
        if raw is None or b"\r\n\r\n" not in raw:
            raise ValidationError("Sem resposta HTTP completa; execu\u00e7\u00e3o interrompida.")
        if len(raw) > MAX_RESPONSE + 100000:
            raise ValidationError("Resposta maior que o limite de mem\u00f3ria.")
        head, self.wire_body = raw.split(b"\r\n\r\n", 1)
        lines = head.decode("iso-8859-1").split("\r\n")
        status = re.match(r"^HTTP/[^ ]+ ([0-9]{3})(?: |$)", lines[0])
        if not status:
            raise ValidationError("Status HTTP inv\u00e1lido.")
        self.status = int(status.group(1))
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                name, value = line.split(":", 1)
                headers[name.lower()] = value.strip().lower()
        if len(self.wire_body) > MAX_RESPONSE:
            raise ValidationError("Corpo da resposta maior que 2 MB.")
        self.body = self.wire_body
        transfer = headers.get("transfer-encoding", "")
        if transfer == "chunked":
            self.body = dechunk(self.body)
        elif transfer not in ("", "identity"):
            raise ValidationError("Transfer-Encoding da resposta n\u00e3o suportado.")
        encoding = headers.get("content-encoding", "")
        if encoding in ("gzip", "x-gzip") and self.body:
            try:
                stream = gzip.GzipFile(fileobj=io.BytesIO(self.body))
                try:
                    self.body = stream.read(MAX_RESPONSE + 1)
                finally:
                    stream.close()
            except (IOError, EOFError, ValueError):
                raise ValidationError("Resposta gzip inv\u00e1lida.")
            if len(self.body) > MAX_RESPONSE:
                raise ValidationError("Resposta descomprimida maior que 2 MB.")
        # Other content encodings remain raw and are compared byte-for-byte.
        self.milliseconds = 0


class AttackConfiguration(object):
    def __init__(self, base_request, target, semantic_type, tests, requests,
                 ignored=(), extra_header=None, delay_ms=500):
        self.base_request = base_request
        self.target = target
        self.semantic_type = semantic_type
        self.tests = list(tests)
        self.requests = list(requests)
        self.ignored = list(ignored)
        self.extra_header = extra_header
        self.delay_ms = delay_ms

class AttackResult(object):
    def __init__(self, sequence, kind, label, payload, request):
        self.sequence, self.kind, self.label = sequence, kind, label
        self.payload, self.request = payload, request
        self.response = None
        self.state = "PENDENTE"
        self.http_status = self.response_bytes = self.delta_bytes = self.elapsed_ms = ""
        self.body_relation = ""
        self.reflected = False
        self.analysis = ""
        self.changed_json_pointers = []

class PreparedAttack(object):
    def __init__(self, config, execution_raw):
        self.config, self.execution_raw = config, execution_raw
        self.results = [AttackResult(0, "BASELINE", "Baseline 1", "original", execution_raw),
                        AttackResult(1, "BASELINE", "Baseline 2", "original", execution_raw)]
        for index, (test, raw) in enumerate(zip(config.tests, config.requests), 1):
            kind = "AUTORIZACAO" if test.authorization else "VALIDACAO"
            self.results.append(AttackResult(index + 1, kind, "%d. %s" % (index, test.name),
                                             value_text(test.value), raw))
        self.results.append(AttackResult(len(self.results), "BASELINE", "Baseline final",
                                         "original", execution_raw))
        self.baseline_bytes = None

    def reset_results(self):
        self.baseline_bytes = None
        for result in self.results:
            result.response = None
            result.state = "PENDENTE"
            result.http_status = result.response_bytes = result.delta_bytes = result.elapsed_ms = ""
            result.body_relation = result.analysis = ""
            result.reflected = False
            result.changed_json_pointers = []


class RunStopped(Exception):
    pass


def monotonic():
    if IS_JYTHON:
        from java.lang import System
        return System.nanoTime() / 1000000000.0
    return time.monotonic()


class Runner(object):
    def __init__(self, transport, in_scope, stopped, emit, delay_ms=500, progress=None, paused=None):
        if not 0 <= delay_ms <= 10000:
            raise ValidationError("Intervalo invalido.")
        self.transport, self.in_scope, self.stopped, self.emit = transport, in_scope, stopped, emit
        self.progress = progress or (lambda current, total, label: None)
        self.delay = delay_ms / 1000.0
        self.paused = paused
        self.last_finished = None
        self.rows = []
        self.outcome = "Execucao nao iniciada."
        self.complete = False
        self.current_step = ""
        self.current_index = 0
        self.total_steps = 0

    def _progress(self, current, total, label):
        self.current_index = current
        self.total_steps = total
        self.current_step = label
        try:
            self.progress(current, total, label)
        except Exception:
            pass

    def _send(self, raw):
        while self.paused is not None and self.paused.is_set() and not self.stopped.is_set():
            self.stopped.wait(0.05)
        if self.last_finished is not None:
            remaining = self.delay - (monotonic() - self.last_finished)
            while remaining > 0 and not self.stopped.is_set():
                self.stopped.wait(min(remaining, 0.05))
                remaining = self.delay - (monotonic() - self.last_finished)
        if self.stopped.is_set():
            raise RunStopped("Execu\u00e7\u00e3o parada; resultados parciais e sem baseline final completo.")
        if not self.in_scope(raw):
            raise ValidationError("Requisi\u00e7\u00e3o fora do Target scope atual; execu\u00e7\u00e3o interrompida.")
        started = monotonic()
        response = self.transport(raw)
        finished = monotonic()
        self.last_finished = finished
        if not isinstance(response, Response):
            raise ValidationError("Transporte n\u00e3o retornou resposta v\u00e1lida.")
        response.milliseconds = int((finished - started) * 1000)
        return response

    def _row(self, name, response, conclusion, changes=(), test=None):
        row = {"test": name, "payload": value_text(test.value) if test else "",
               "http_status": response.status, "response_bytes": len(response.wire_body),
               "elapsed_ms": response.milliseconds, "analysis": conclusion,
               "changed_json_pointers": list(changes),
               "response_body_sha256": hashlib.sha256(response.wire_body).hexdigest(),
               "request": response.request, "response": response.raw}
        self.rows.append(row)
        self.emit(row)

    def run(self, original, tests, requests, ignored=()):
        if len(tests) != len(requests) or not 1 <= len(tests) <= MAX_TESTS:
            raise ValidationError("Plano vazio, inconsistente ou maior que 50 testes.")
        self.outcome = "Execu\u00e7\u00e3o em andamento; resultados provis\u00f3rios."
        try:
            self.outcome = self._run(original, tests, requests, ignored)
        except RunStopped as exc:
            self.outcome = as_text(exc)
        except Exception:
            self.outcome = "Execu\u00e7\u00e3o interrompida por erro; resultados parciais e sem valida\u00e7\u00e3o final."
            raise
        finally:
            if not self.complete:
                for row in self.rows:
                    if row["payload"] or not row["test"].startswith("Baseline"):
                        row["analysis"] = "INCONCLUSIVO (rodada incompleta/inst\u00e1vel): " + row["analysis"]
        return self.outcome

    def _run(self, original, tests, requests, ignored):
        total = len(tests) + 3
        self.total_steps = total

        self._progress(1, total, "Baseline 1")
        base = self._send(original)
        self._row("Baseline 1", base, "Referencia original")
        if not 200 <= base.status < 300:
            return "Interrompido: baseline sem sucesso (HTTP %d). Revise sessao/requisicao." % base.status

        self._progress(2, total, "Baseline 2")
        second = self._send(original)
        check = compare(base, second, ignored=ignored)
        stable = base.status == second.status and check["same"]
        self._row("Baseline 2", second, "Baseline estavel" if stable else "Baseline instavel", check["changes"])
        if not stable:
            return "Interrompido: baselines diferentes. Revise campos dinamicos e sessao."

        for index, (test, raw) in enumerate(zip(tests, requests), 1):
            step = index + 2
            self._progress(step, total, "%d. %s" % (index, test.name))
            response = self._send(raw)
            analysis = compare(base, response, test.authorization, ignored)
            self._row("%d. %s" % (index, test.name), response,
                      analysis["conclusion"] + (" | Corpo igual" if analysis["same"] else " | Corpo diferente"),
                      analysis["changes"], test)
            if response.status in (401, 429):
                return "Interrompido: HTTP %d; verifique sessao/limite. Sem baseline final." % response.status

        self._progress(total, total, "Baseline final")
        final = self._send(original)
        check = compare(base, final, ignored=ignored)
        self.complete = base.status == final.status and check["same"]
        self._row("Baseline final", final, "Referencia estavel" if self.complete else "Referencia mudou; rodada inconclusiva", check["changes"])
        return ("Execucao concluida. Revise as evidencias." if self.complete else
                "Baseline final mudou: resultados inconclusivos; revise sessao e estado.")


def export_report(runner):
    allowed = ("test", "http_status", "response_bytes", "elapsed_ms", "analysis",
               "changed_json_pointers", "response_body_sha256")
    return {"tool": "Semantic Intruder V2 Python " + VERSION,
            "exported_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "run_status": runner.outcome, "baseline_final_validated": runner.complete,
            "notice": "Triagem; n\u00e3o confirma vulnerabilidades. Sem URLs, headers, corpos ou payloads.",
            "results": [dict((k, row[k]) for k in allowed) for row in runner.rows]}


# The complete Burp/Swing integration is below. The core above imports no Java.
if IS_JYTHON:
    from burp import (IBurpExtender, ITab, IContextMenuFactory,
                      IExtensionStateListener, IMessageEditorController)
    from java.lang import Runnable
    from java.util import ArrayList
    from java.awt import BorderLayout, Dimension, FlowLayout, GridLayout
    from java.awt.event import ActionListener
    from javax.swing import (JPanel, JLabel, JButton, JComboBox, JTextArea,
                             JTextField, JCheckBox, JScrollPane, JSplitPane,
                             JTabbedPane, JTable, JFileChooser, JOptionPane,
                             JSpinner, SpinnerNumberModel, SwingUtilities,
                             BorderFactory, JMenuItem, ListSelectionModel)
    from javax.swing.table import DefaultTableModel
    from javax.swing.event import DocumentListener, ChangeListener, ListSelectionListener

    class Call(Runnable):
        def __init__(self, function):
            self.function = function

        def run(self):
            self.function()

    def on_ui(function, wait=False):
        if SwingUtilities.isEventDispatchThread():
            function()
        elif wait:
            SwingUtilities.invokeAndWait(Call(function))
        else:
            SwingUtilities.invokeLater(Call(function))

    class Action(ActionListener):
        def __init__(self, function):
            self.function = function

        def actionPerformed(self, event):
            self.function()

    class Changed(DocumentListener, ChangeListener):
        def __init__(self, function):
            self.function = function

        def insertUpdate(self, event):
            self.function()

        def removeUpdate(self, event):
            self.function()

        def changedUpdate(self, event):
            self.function()

        def stateChanged(self, event):
            self.function()

    class Selected(ListSelectionListener):
        def __init__(self, function):
            self.function = function

        def valueChanged(self, event):
            if not event.getValueIsAdjusting():
                self.function()

    class ReadOnlyModel(DefaultTableModel):
        def isCellEditable(self, row, column):
            return False

    class TrafficController(IMessageEditorController):
        def __init__(self):
            self.service = None
            self.request_data = None
            self.response_data = None

        def getHttpService(self):
            return self.service

        def getRequest(self):
            return self.request_data

        def getResponse(self):
            return self.response_data

    class BurpExtender(IBurpExtender, ITab, IContextMenuFactory, IExtensionStateListener):
        def registerExtenderCallbacks(self, callbacks):
            self.callbacks = callbacks
            self.helpers = callbacks.getHelpers()
            self.running = False
            self.loading_request = False
            self.unloaded = False
            self.stopped = threading.Event()
            self.paused = threading.Event()
            self.attack = None
            self.original = None
            self.service = None
            self.targets = []
            self.prepared = None
            self.runner = None
            self.rows = []
            self.preview_rows = []
            self.controls = []
            callbacks.setExtensionName("Semantic Intruder V2 Python")
            # This marker can only appear after Burp's own directory bootstrap succeeds.
            # A <string>:1 -> PosixModule.chdir error before it must be fixed in the
            # selected installation path; changing codecs here would run too late.
            callbacks.printOutput("Semantic V2 Python %s: codigo iniciado; preparando interface." % VERSION)
            on_ui(self._build_ui, wait=True)
            callbacks.registerContextMenuFactory(self)
            callbacks.registerExtensionStateListener(self)
            callbacks.addSuiteTab(self)
            callbacks.printOutput("Semantic V2 Python %s carregado. Use o menu de contexto e abra a aba Semantic V2 Py." % VERSION)

        def getTabCaption(self):
            return "Semantic V2 Py"

        def getUiComponent(self):
            return self.panel

        def extensionUnloaded(self):
            self.unloaded = True
            self.stopped.set()

        def createMenuItems(self, invocation):
            messages = invocation.getSelectedMessages()
            if messages is None or len(messages) == 0:
                return None
            selected = messages[0]
            item = JMenuItem("Enviar para Semantic V2 Python")
            item.addActionListener(Action(lambda: self._load(selected)))
            items = ArrayList()
            items.add(item)
            return items

        def _to_bytes(self, java_bytes):
            if java_bytes is None:
                return None
            # Burp byte/string helpers use a one-to-one byte mapping, not UTF-8.
            return as_text(self.helpers.bytesToString(java_bytes)).encode("iso-8859-1")

        def _to_java(self, raw):
            return self.helpers.stringToBytes(raw.decode("iso-8859-1")) if raw is not None else None

        def _in_scope(self, raw, service):
            url = self.helpers.analyzeRequest(service, self._to_java(raw)).getUrl()
            return bool(self.callbacks.isInScope(url))

        def _transport(self, raw, service):
            exchange = self.callbacks.makeHttpRequest(service, self._to_java(raw))
            if exchange is None:
                raise ValidationError("Burp n\u00e3o retornou resposta.")
            effective = self._to_bytes(exchange.getRequest()) or raw
            return Response(effective, self._to_bytes(exchange.getResponse()))

        def _button(self, title, callback):
            button = JButton(title)
            button.addActionListener(Action(callback))
            return button

        def _field(self, container, title, component, grow=False):
            row = JPanel(BorderLayout(0, 4))
            row.setBorder(BorderFactory.createEmptyBorder(4, 0, 4, 0))
            row.add(JLabel(title), BorderLayout.NORTH)
            row.add(component, BorderLayout.CENTER)
            row.setAlignmentX(0.0)
            if not grow:
                row.setMaximumSize(Dimension(32767, row.getPreferredSize().height))
            container.add(row)

        def _build_ui(self):
            from javax.swing import BoxLayout
            self.panel = JPanel(BorderLayout(8, 8))
            self.panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
            header = JPanel(GridLayout(0, 1, 0, 4))
            header.add(JLabel("SEMANTIC INTRUDER V2  |  Positions  >  Payloads  >  Results"))
            self.source = JLabel("Repeater / HTTP history \u2192 bot\u00e3o direito \u2192 Extensions \u2192 Enviar para Semantic V2 Python")
            header.add(self.source)
            self.panel.add(header, BorderLayout.NORTH)
            settings = JPanel()
            settings.setLayout(BoxLayout(settings, BoxLayout.Y_AXIS))
            self.target_box = JComboBox()
            self.meaning_box = JComboBox(list(MEANINGS))
            self._field(settings, "Positions - ponto de insercao", self.target_box)
            self._field(settings, "Semantic type", self.meaning_box)
            self.alternatives = JTextArea(4, 28)
            self.alternatives.setToolTipText("Um ID de teste por linha, sem aspas. A sess\u00e3o original ser\u00e1 mantida.")
            self._field(settings, "Payloads / massa autorizada (1 por linha)", JScrollPane(self.alternatives))
            self.validation = JCheckBox("Incluir valida\u00e7\u00e3o de entrada e tipos", True)
            settings.add(self.validation)
            self.ignored = JTextField()
            self.ignored.setToolTipText("JSON Pointers separados por v\u00edrgula: /timestamp,/meta/requestId")
            self._field(settings, "Options - JSON pointers ignorados", self.ignored)
            self.interval = JSpinner(SpinnerNumberModel(500, 100, 10000, 100))
            self._field(settings, "Options - intervalo (ms)", self.interval)
            self.writes = JCheckBox("Repetir esta opera\u00e7\u00e3o de escrita (POST/PUT etc.)", False)
            settings.add(self.writes)
            self.add_header_enabled = JCheckBox("Adicionar novo cabecalho nesta rodada", False)
            settings.add(self.add_header_enabled)
            self.new_header_name = JTextField()
            self.new_header_name.setToolTipText("Ex.: X-Forwarded-For. Nao substitui headers existentes.")
            self._field(settings, "Novo cabecalho - nome", self.new_header_name)
            self.new_header_value = JTextField()
            self.new_header_value.setToolTipText("Valor literal. CR/LF nao sao permitidos.")
            self._field(settings, "Novo cabecalho - valor", self.new_header_value)
            info = JLabel("Ate 50 testes + 3 referencias | 1 request por vez | exige Target Scope | Parar aguarda o request atual")
            info.setBorder(BorderFactory.createEmptyBorder(8, 0, 8, 0))
            settings.add(info)
            self.generate_button = self._button("4. Preparar testes", self._generate)
            settings.add(self.generate_button)
            self.preview = JTextArea(6, 28)
            self.preview.setEditable(False)
            self.preview.setLineWrap(True)
            self.preview.setWrapStyleWord(True)
            self._field(settings, "Attack summary / avisos", JScrollPane(self.preview), grow=True)
            for component in settings.getComponents():
                component.setAlignmentX(0.0)
            self.start = self._button("5. Iniciar", self._execute)
            self.pause = self._button("Pausar", self._pause)
            self.stop = self._button("Parar", self._stop)
            self.repeat = self._button("Repetir", self._repeat)
            self.save = self._button("Exportar metadados JSON", self._export)
            self.clear = self._button("Limpar", self._clear)
            self.start.setEnabled(False)
            self.pause.setEnabled(False)
            self.stop.setEnabled(False)
            self.repeat.setEnabled(False)
            self.save.setEnabled(False)
            actions = JPanel(FlowLayout(FlowLayout.LEFT))
            for button in (self.start, self.pause, self.stop, self.repeat, self.save, self.clear):
                actions.add(button)
            self.run_state = JLabel("Ataque nao iniciado.")
            self.progress_state = JLabel("Estado: aguardando preparacao.")
            self.details = JLabel("Importe uma requisicao para comecar.")
            footer = JPanel(BorderLayout())
            messages = JPanel(GridLayout(0, 1))
            messages.add(self.run_state)
            messages.add(self.progress_state)
            messages.add(self.details)
            footer.add(actions, BorderLayout.NORTH)
            footer.add(messages, BorderLayout.SOUTH)
            self.panel.add(footer, BorderLayout.SOUTH)
            self.model = ReadOnlyModel(["#", "Tipo", "Teste", "Payload", "Estado", "HTTP", "Bytes", "Delta", "ms", "Body", "Refletido", "Triagem"], 0)
            self.table = JTable(self.model)
            self.table.setRowHeight(22)
            self.table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN)
            for index, width in enumerate((35, 90, 190, 120, 95, 50, 65, 60, 55, 85, 70, 260)):
                self.table.getColumnModel().getColumn(index).setPreferredWidth(width)
            self.table.setAutoCreateRowSorter(True)
            self.table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
            self.table.getSelectionModel().addListSelectionListener(Selected(self._select_row))
            self.current_controller = TrafficController()
            self.base_controller = TrafficController()
            self.request_editor = self.callbacks.createMessageEditor(self.current_controller, False)
            self.response_editor = self.callbacks.createMessageEditor(self.current_controller, False)
            self.base_request_editor = self.callbacks.createMessageEditor(self.base_controller, False)
            self.base_response_editor = self.callbacks.createMessageEditor(self.base_controller, False)
            evidence = JTabbedPane()
            evidence.addTab("Request selecionada", self.request_editor.getComponent())
            evidence.addTab("Response selecionada", self.response_editor.getComponent())
            evidence.addTab("Request baseline", self.base_request_editor.getComponent())
            evidence.addTab("Response baseline", self.base_response_editor.getComponent())
            table_scroll = JScrollPane(self.table)
            table_scroll.setColumnHeaderView(self.table.getTableHeader())
            result_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT, table_scroll, evidence)
            result_pane.setResizeWeight(0.58)
            settings_scroll = JScrollPane(settings)
            settings_scroll.setPreferredSize(Dimension(360, 680))
            main = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, settings_scroll, result_pane)
            main.setResizeWeight(0.0)
            main.setDividerLocation(375)
            self.panel.add(main, BorderLayout.CENTER)
            self.controls = [self.target_box, self.meaning_box, self.alternatives, self.validation,
                             self.ignored, self.interval, self.writes, self.generate_button,
                             self.add_header_enabled, self.new_header_name, self.new_header_value]
            self.target_box.addActionListener(Action(self._target_changed))
            self.meaning_box.addActionListener(Action(self._invalidate))
            self.validation.addActionListener(Action(self._invalidate))
            self.writes.addActionListener(Action(self._invalidate))
            self.add_header_enabled.addActionListener(Action(self._invalidate))
            self.new_header_name.getDocument().addDocumentListener(Changed(self._invalidate))
            self.new_header_value.getDocument().addDocumentListener(Changed(self._invalidate))
            self.interval.addChangeListener(Changed(self._invalidate))
            self.alternatives.getDocument().addDocumentListener(Changed(self._invalidate))
            self.ignored.getDocument().addDocumentListener(Changed(self._invalidate))
            self.callbacks.customizeUiComponent(self.panel)

        def _error(self, message):
            JOptionPane.showMessageDialog(self.panel, as_text(message), "Semantic V2 Python", JOptionPane.INFORMATION_MESSAGE)

        def _invalidate(self):
            if getattr(self, "generating", False):
                return
            self.prepared = None
            self.attack = None
            self.preview_rows = []
            self.start.setEnabled(False)
            self.repeat.setEnabled(False) if hasattr(self, "repeat") else None

        def _target_changed(self):
            if self.loading_request:
                return
            index = self.target_box.getSelectedIndex()
            if 0 <= index < len(self.targets):
                field = self.targets[index]
                self.meaning_box.setSelectedItem(classify(field.name + field.pointer, field.value))
            self._invalidate()

        def _clear(self):
            if self.running:
                self._error("Pare e aguarde o envio em andamento antes de limpar.")
                return
            self._invalidate()
            self.original, self.service, self.runner = None, None, None
            self.rows, self.targets = [], []
            self.preview_rows = []
            self.attack = None
            self.model.setRowCount(0)
            was_loading = self.loading_request
            self.loading_request = True
            try:
                self.target_box.removeAllItems()
            finally:
                self.loading_request = was_loading
            self.alternatives.setText("")
            self.ignored.setText("")
            self.writes.setSelected(False)
            self.add_header_enabled.setSelected(False)
            self.new_header_name.setText("")
            self.new_header_value.setText("")
            self.preview.setText("")
            self.save.setEnabled(False)
            self.repeat.setEnabled(False)
            self.source.setText("Envie uma requisi\u00e7\u00e3o pelo menu de contexto do Burp.")
            self.run_state.setText("Nenhuma execucao realizada.")
            self.progress_state.setText("Progresso: aguardando.")
            self.details.setText("Dados removidos da interface.")
            for controller in (self.current_controller, self.base_controller):
                controller.service = controller.request_data = controller.response_data = None
            for editor, is_request in ((self.request_editor, True), (self.response_editor, False),
                                       (self.base_request_editor, True), (self.base_response_editor, False)):
                editor.setMessage(None, is_request)

        def _load(self, message):
            if not SwingUtilities.isEventDispatchThread():
                on_ui(lambda: self._load(message))
                return
            if self.running:
                self._error("Ha uma rodada em andamento. Pare e aguarde antes de importar outra requisicao.")
                return

            stage = "inicio"
            try:
                stage = "ler mensagem"
                if message is None or message.getRequest() is None:
                    raise ValidationError("A selecao nao possui uma requisicao HTTP.")

                service = message.getHttpService()
                if service is None:
                    raise ValidationError("A requisicao nao possui servico HTTP de destino.")

                stage = "converter bytes"
                raw = self._to_bytes(message.getRequest())

                stage = "parsear requisicao"
                request = Request(raw)

                stage = "descobrir campos"
                fields, notices = discover(request)
                if not fields:
                    raise ValidationError(
                        "Nenhum campo testavel foi encontrado. A requisicao foi lida, "
                        "mas nao ha path/query/JSON/form/header editavel."
                    )

                stage = "converter request para Burp"
                java_request = self._to_java(request.raw)

                # From this point onward we commit the new request to the UI.
                # Do not call _clear(): it resets labels/editors and can fire Swing
                # selection events while the combo box is being populated.
                stage = "preparar interface"
                self.loading_request = True
                try:
                    self.prepared = None
                    self.original = request
                    self.service = service
                    self.runner = None
                    self.rows = []
                    self.targets = fields

                    self.model.setRowCount(0)
                    self.target_box.removeAllItems()
                    self.alternatives.setText("")
                    self.ignored.setText("")
                    self.writes.setSelected(False)
                    self.preview.setText("")
                    self.save.setEnabled(False)

                    stage = "preencher campos"
                    for field in fields:
                        self.target_box.addItem(ui_text(field.label()))

                    stage = "carregar baseline visual"
                    self.base_controller.service = service
                    self.base_controller.request_data = java_request
                    self.base_controller.response_data = None
                    self.base_request_editor.setMessage(java_request, True)
                    self.base_response_editor.setMessage(None, False)

                    self.current_controller.service = service
                    self.current_controller.request_data = None
                    self.current_controller.response_data = None
                    self.request_editor.setMessage(None, True)
                    self.response_editor.setMessage(None, False)

                    stage = "atualizar textos"
                    self.source.setText(ui_text("%s | %s | %d campos" % (
                        request.method, service.getHost(), len(fields)
                    )))
                    self.preview.setText(ui_text("\n".join(notices)))
                    self.run_state.setText("Nenhuma execucao realizada.")
                    self.progress_state.setText("Progresso: aguardando.")
                    self.details.setText("Requisicao importada: %d campos encontrados." % len(fields))
                finally:
                    self.loading_request = False

                stage = "selecionar primeiro campo"
                if self.target_box.getItemCount() > 0:
                    self.target_box.setSelectedIndex(0)
                    field = self.targets[0]
                    self.meaning_box.setSelectedItem(
                        ui_text(classify(field.name + field.pointer, field.value))
                    )

                self._invalidate()
                self.details.setText(
                    "Requisicao importada com sucesso. Escolha o campo e gere a previa."
                )
                self.callbacks.printOutput(
                    "Semantic V2 Python %s: requisicao importada com sucesso (%d campos)." %
                    (VERSION, len(fields))
                )

            except Exception as exc:
                message_text = "Falha ao importar na etapa '%s': %s: %s" % (
                    stage, type(exc).__name__, as_text(exc)
                )
                # Persist the failure in the tab itself so it remains visible even
                # when modal dialogs are dismissed.
                try:
                    self.details.setText(ui_text(message_text))
                    self.preview.setText(ui_text(message_text))
                    self.run_state.setText("Falha na importacao da requisicao.")
                except Exception:
                    pass
                try:
                    self.callbacks.printError("Semantic V2 Python %s: %s" % (
                        VERSION, ui_text(message_text)
                    ))
                except Exception:
                    pass
                self._error(ui_text(message_text))

        def _generate(self):
            if self.running:
                return
            self._invalidate()
            self.generating = True
            try:
                index = self.target_box.getSelectedIndex()
                if self.original is None or not 0 <= index < len(self.targets):
                    raise ValidationError("Importe uma requisi\u00e7\u00e3o e escolha um campo.")
                if not self._in_scope(self.original.raw, self.service):
                    raise ValidationError("Inclua o endpoint em Target \u2192 Scope antes de gerar os testes.")
                writing = self.original.method.upper() not in ("GET", "HEAD", "OPTIONS")
                if writing and not self.writes.isSelected():
                    raise ValidationError("Metodo %s: marque 'Repetir esta operacao de escrita' para confirmar os envios." % self.original.method)
                field = self.targets[index]
                ignored = [p.strip() for p in as_text(self.ignored.getText()).split(",") if p.strip()]
                for pointer in ignored:
                    pointer_parts(pointer)
                tests = plan(as_text(self.meaning_box.getSelectedItem()), field,
                             as_text(self.alternatives.getText()), self.validation.isSelected())
                requests = [mutate(self.original, field, test.value) for test in tests]
                add_header = self.add_header_enabled.isSelected()
                header_name = as_text(self.new_header_name.getText()).strip()
                header_value = as_text(self.new_header_value.getText())
                execution_raw = self.original.raw
                if add_header:
                    execution_raw = self.original.add_header(header_name, header_value)
                    requests = [Request(raw).add_header(header_name, header_value) for raw in requests]
                for raw in requests:
                    if not self._in_scope(raw, self.service):
                        raise ValidationError("Uma muta\u00e7\u00e3o sai do Target scope. Revise o campo, a pr\u00e9via pretendida e o escopo do endpoint.")
                config = AttackConfiguration(self.original, field,
                                             as_text(self.meaning_box.getSelectedItem()),
                                             tests, requests, ignored,
                                             (header_name, header_value) if add_header else None,
                                             int(self.interval.getValue()))
                self.attack = PreparedAttack(config, execution_raw)
                self.preview_rows = self.attack.results
                self.model.setRowCount(0)
                for result in self.attack.results:
                    self.model.addRow([result.sequence, result.kind, result.label, result.payload,
                                       result.state, "", "", "", "", "", "", ""])
                if self.attack.results:
                    self.table.setRowSelectionInterval(0, 0)
                    self._select_row()

                lines = ["Campo: " + field.label(), "Original: " + json_text(field.value), ""]
                if add_header:
                    lines.extend(("Novo cabecalho: %s: %s" % (header_name, header_value),
                                  "Aplicado aos baselines e a todas as mutacoes desta rodada.", ""))
                lines.extend("%d. %s \u2192 %s" % (i, test.name, json_text(test.value)) for i, test in enumerate(tests, 1))
                lines.extend(("", "M\u00e1ximo de %d envios: 2 baselines + %d testes + 1 baseline final." % (len(tests) + 3, len(tests)),
                              "IDs alternativos mant\u00eam a sess\u00e3o original. Um 2xx exige revis\u00e3o de propriedade e regra de acesso."))
                if writing:
                    lines.append("ATENCAO: metodo de escrita confirmado. Baselines e testes repetirao a operacao.")
                    lines.append("Parar impede novos envios, mas nao desfaz um POST/PUT/PATCH/DELETE ja enviado.")
                if field.location == "HEADER_JSON":
                    lines.append("Codec detectado: %s. Assinaturas n\u00e3o s\u00e3o recalculadas." % field.codec)
                self.preview.setText("\n".join(lines))
                self.preview.setCaretPosition(0)
                # PreparedAttack is the authoritative immutable execution plan.
                self.prepared = None
                self.details.setText("Ataque preparado. Revise as linhas e clique em Iniciar.")
                self.generating = False
                self.start.setEnabled(self.attack is not None and bool(self.attack.results))
                self.repeat.setEnabled(False)
            except Exception as exc:
                self.generating = False
                self.prepared = None
                self.start.setEnabled(False)
                self._error(as_text(exc))

        def _repeat(self):
            if self.running or self.attack is None:
                return
            self.start.setEnabled(True)
            self._execute()

        def _pause(self):
            if not self.running:
                return
            if self.paused.is_set():
                self.paused.clear()
                self.pause.setText("Pausar")
                self.run_state.setText("Execucao retomada.")
            else:
                self.paused.set()
                self.pause.setText("Continuar")
                self.run_state.setText("Execucao pausada entre requests.")

        def _stop(self):
            if not self.running:
                return
            self.stopped.set()
            self.stop.setEnabled(False)
            self.run_state.setText("Cancelamento solicitado.")
            self.progress_state.setText(
                "Aguardando a requisicao HTTP atual terminar; o Burp controla o timeout da chamada."
            )
            self.details.setText(
                "Nenhum novo teste sera enviado. Em POST/PUT/PATCH/DELETE, a requisicao atual pode ja ter produzido efeito."
            )

        def _execute(self):
            if self.running:
                return
            if self.attack is None or not self.attack.results:
                self._error("Nenhum ataque preparado. Clique em Preparar testes primeiro.")
                return
            config = self.attack.config
            raw = self.attack.execution_raw
            service = self.service
            tests = config.tests
            requests = config.requests
            ignored = config.ignored
            delay = config.delay_ms
            self.running = True
            self.stopped.clear()
            self.paused.clear()
            self.pause.setText("Pausar")
            self.start.setEnabled(False)
            self.pause.setEnabled(True)
            self.stop.setEnabled(True)
            self.save.setEnabled(False)
            self.clear.setEnabled(False)
            for control in self.controls:
                control.setEnabled(False)
            self.rows = []
            if self.attack is not None:
                self.attack.reset_results()
            for pi, result in enumerate(self.preview_rows):
                self.model.setValueAt("PENDENTE", pi, 4)
                for col in range(5, 12):
                    self.model.setValueAt("", pi, col)
            self.current_controller.request_data = self.current_controller.response_data = None
            self.base_controller.response_data = None
            self.request_editor.setMessage(None, True)
            self.response_editor.setMessage(None, False)
            self.base_response_editor.setMessage(None, False)
            self.run_state.setText("Execucao em andamento; resultados provisorios ate o baseline final.")
            self.progress_state.setText("Progresso: iniciando rodada.")
            def progress(current, total, label):
                on_ui(lambda: self._set_progress(current, total, label))

            runner = Runner(lambda data: self._transport(data, service),
                            lambda data: self._in_scope(data, service), self.stopped,
                            lambda row: on_ui(lambda: self._append(row)), delay,
                            progress=progress, paused=self.paused)
            self.runner = runner

            def work():
                try:
                    runner.run(raw, tests, requests, ignored)
                except Exception as exc:
                    # Do not log exception messages that may contain request URLs or credentials.
                    runner.outcome = "Execu\u00e7\u00e3o interrompida (%s). Revise sess\u00e3o, escopo, formato e timeouts do Burp; resultados parciais." % type(exc).__name__
                    if isinstance(exc, ValidationError):
                        runner.outcome = as_text(exc)
                finally:
                    on_ui(lambda: self._finished(runner))

            self.worker = threading.Thread(target=work, name="SemanticV2Python")
            self.worker.daemon = True
            self.worker.start()

        def _set_progress(self, current, total, label):
            if self.unloaded:
                return
            index = current - 1
            if 0 <= index < len(self.preview_rows):
                result = self.preview_rows[index]
                result.state = "EXECUTANDO"
                self.model.setValueAt("EXECUTANDO", index, 4)
                self.table.setRowSelectionInterval(index, index)
                self._select_row()
            self.progress_state.setText("Progresso: %d/%d - %s" %
                                        (current, total, ui_text(label)))
            self.progress_state.setToolTipText("A chamada HTTP atual usa os timeouts configurados no Burp.")

        def _append(self, row):
            if self.unloaded:
                return
            self.rows.append(row)
            index = len(self.rows) - 1
            if index >= len(self.preview_rows):
                return
            result = self.preview_rows[index]
            result.request, result.response = row["request"], row["response"]
            result.state = "CONCLUIDO"
            result.http_status = row["http_status"]
            result.response_bytes = row["response_bytes"]
            result.elapsed_ms = row["elapsed_ms"]
            result.analysis = row["analysis"]
            result.changed_json_pointers = row["changed_json_pointers"]
            if index == 0:
                result.delta_bytes = 0
                if self.attack is not None:
                    self.attack.baseline_bytes = row["response_bytes"]
            elif self.attack is not None and self.attack.baseline_bytes is not None:
                result.delta_bytes = row["response_bytes"] - self.attack.baseline_bytes
            result.body_relation = "IGUAL" if "Corpo igual" in row["analysis"] else "DIFERENTE"
            try:
                parsed = Response(row["request"], row["response"])
                marker = as_text(result.payload).encode("utf-8")
                result.reflected = bool(result.kind != "BASELINE" and marker and marker in parsed.body)
            except Exception:
                result.reflected = False
            values = [result.sequence, result.kind, result.label, result.payload, result.state,
                      result.http_status, result.response_bytes, result.delta_bytes,
                      result.elapsed_ms, result.body_relation,
                      "SIM" if result.reflected else "NAO", result.analysis]
            for col, value in enumerate(values):
                self.model.setValueAt(value, index, col)
            if index == 0:
                self.base_controller.request_data = self._to_java(row["request"])
                self.base_controller.response_data = self._to_java(row["response"])
                self.base_request_editor.setMessage(self.base_controller.request_data, True)
                self.base_response_editor.setMessage(self.base_controller.response_data, False)
            selected = self.table.getSelectedRow()
            if selected >= 0 and self.table.convertRowIndexToModel(selected) == index:
                self._select_row()
            self.details.setText("%d de %d respostas recebidas." % (len(self.rows), len(self.preview_rows)))

        def _finished(self, runner):
            self.running = False
            if self.unloaded:
                return
            for control in self.controls:
                control.setEnabled(True)
            self.clear.setEnabled(True)
            self.stop.setEnabled(False)
            self.save.setEnabled(bool(runner.rows))

            # Keep the exact generated preview available for an explicit re-run.
            # Previously _invalidate() cleared self.prepared here, leaving
            # "Executar previa" disabled after Stop/completion.
            self.start.setEnabled(self.prepared is not None)

            self.pause.setEnabled(False)
            self.pause.setText("Pausar")
            self.paused.clear()
            self.repeat.setEnabled(self.attack is not None)
            for index, result in enumerate(self.preview_rows):
                if result.response is None:
                    result.state = "CANCELADO" if self.stopped.is_set() else "NAO EXECUTADO"
                    self.model.setValueAt(result.state, index, 4)
            self.run_state.setText(runner.outcome)
            self.run_state.setToolTipText(runner.outcome)

            if self.stopped.is_set():
                self.progress_state.setText(
                    "Rodada encerrada apos solicitacao de cancelamento. A previa continua disponivel para nova execucao."
                )
            elif runner.complete:
                self.progress_state.setText(
                    "Rodada concluida. A mesma previa pode ser executada novamente, se necessario."
                )
            else:
                self.progress_state.setText(
                    "Rodada encerrada. Revise o status antes de executar novamente."
                )

            self.details.setText(
                "Selecione uma linha para examinar request/response. Alterar qualquer configuracao invalida esta previa."
            )

        def _select_row(self):
            index = self.table.getSelectedRow()
            if index < 0:
                return
            index = self.table.convertRowIndexToModel(index)
            if index >= len(self.preview_rows):
                return
            result = self.preview_rows[index]
            self.current_controller.service = self.service
            self.current_controller.request_data = self._to_java(result.request)
            self.current_controller.response_data = self._to_java(result.response)
            self.request_editor.setMessage(self.current_controller.request_data, True)
            self.response_editor.setMessage(self.current_controller.response_data, False)
            detail = result.state
            if result.analysis:
                detail += " | " + result.analysis
            if result.changed_json_pointers:
                detail += " | Diferencas: " + ", ".join(result.changed_json_pointers)
            if result.response is None:
                detail += " | Request preparada; response ainda nao recebida."
            self.details.setText(detail)
            self.details.setToolTipText(detail)

        def _export(self):
            if self.running or self.runner is None or not self.runner.rows:
                return
            from java.io import File
            chooser = JFileChooser()
            chooser.setSelectedFile(File("semantic-v2-python-resultados.json"))
            if chooser.showSaveDialog(self.panel) != JFileChooser.APPROVE_OPTION:
                return
            destination = chooser.getSelectedFile()
            if destination.exists() and JOptionPane.showConfirmDialog(self.panel, "Substituir o arquivo escolhido?", "Exporta\u00e7\u00e3o", JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION:
                return
            try:
                with io.open(as_text(destination.getAbsolutePath()), "w", encoding="utf-8") as handle:
                    handle.write(as_text(json.dumps(export_report(self.runner), ensure_ascii=False, indent=2)))
                self.details.setText("Metadados exportados para " + as_text(destination.getName()))
            except Exception as exc:
                self._error("N\u00e3o foi poss\u00edvel exportar: " + as_text(exc))
