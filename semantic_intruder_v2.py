# -*- coding: utf-8 -*-
"""Semantic Intruder V2 for Burp Suite: Python 2.7/Jython, dependency-free.

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

VERSION = "0.3.0-python"
MAX_REQUEST = 1000000
MAX_RESPONSE = 2000000
MAX_TESTS = 50
MEANINGS = ("Identificador", "Texto", "Número", "Booleano")
IDENTIFIER, TEXT, NUMBER, BOOLEAN = MEANINGS
JSON_NUMBER = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
WS = " \t\r\n"


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
            raise ValidationError("Número não finito.")
        return text_type(value)
    return as_text(json.dumps(value, ensure_ascii=True, allow_nan=False,
                              separators=(",", ":")))


def value_text(value):
    return value if isinstance(value, text_type) else json_text(value)


def pointer_escape(value):
    return value.replace("~", "~0").replace("/", "~1")


def pointer_parts(pointer):
    if pointer == "":
        return []
    if not pointer.startswith("/") or re.search(r"~(?![01])", pointer):
        raise ValidationError("Use JSON Pointer válido, como /meta/requestId.")
    return [p.replace("~1", "/").replace("~0", "~")
            for p in pointer[1:].split("/")]


class JsonDocument(object):
    """Strict JSON reader with exact token spans for surgical mutations."""
    def __init__(self, source):
        self.source = as_text(source)
        if len(self.source) > MAX_REQUEST:
            raise ValidationError("JSON maior que 1 milhão de caracteres.")
        self.pos = 0
        self.spans = OrderedDict()
        self.values = OrderedDict()
        self.decoder = json.JSONDecoder()
        self.root = self._value("", 0)
        self._space()
        if self.pos != len(self.source):
            raise ValidationError("Conteúdo após o JSON.")

    def _space(self):
        while self.pos < len(self.source) and self.source[self.pos] in WS:
            self.pos += 1

    def _string(self):
        try:
            value, end = self.decoder.raw_decode(self.source, self.pos)
        except ValueError:
            raise ValidationError("String JSON inválida.")
        if not isinstance(value, text_type):
            raise ValidationError("Chave JSON deve ser texto.")
        self.pos = end
        return value

    def _value(self, pointer, depth):
        if depth > 64:
            raise ValidationError("JSON excede 64 níveis.")
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
                            raise ValidationError("Chave JSON inválida.")
                        key = self._string()
                        if key in value:
                            raise ValidationError("Chaves JSON duplicadas não são editadas.")
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
                        raise ValidationError("Separador JSON inválido.")
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
                    raise ValidationError("Valor JSON inválido.")
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
            raise ValidationError("Campo JSON não encontrado.")
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
                raise ValidationError("Percent-encoding inválido.")
            out.append(int(value[i + 1:i + 3], 16))
            i += 3
        else:
            out.extend((" " if char == "+" and not path else char).encode("utf-8"))
            i += 1
    return out.decode("utf-8")


def replace_pair(source, index, value):
    pairs = source.split("&")
    if index < 0 or index >= len(pairs):
        raise ValidationError("Ocorrência do parâmetro não encontrada.")
    name = pairs[index].split("=", 1)[0]
    pairs[index] = name + "=" + encode_component(value)
    return "&".join(pairs)


class Request(object):
    def __init__(self, raw):
        self.raw = raw
        if len(raw) > MAX_REQUEST:
            raise ValidationError("Requisição maior que 1 MB.")
        if b"\r\n\r\n" not in raw:
            raise ValidationError("Requisição precisa de headers e separador CRLF.")
        head, self.body = raw.split(b"\r\n\r\n", 1)
        self.lines = head.decode("iso-8859-1").split("\r\n")
        start = self.lines[0].split(" ")
        if len(start) != 3 or not start[1].startswith("/") or not re.match(r"^HTTP/(1\.[01]|2(?:\.0)?)$", start[2]):
            raise ValidationError("Use uma requisição HTTP com caminho relativo, como GET /api HTTP/1.1.")
        self.method, self.path, self.version = start
        self.route, separator, self.query = self.path.partition("?")
        self.has_query = bool(separator)
        self.headers = []
        for index, line in enumerate(self.lines[1:], 1):
            if ":" not in line or line.startswith((" ", "\t")):
                raise ValidationError("Header inválido ou dobrado em várias linhas.")
            name, value = line.split(":", 1)
            self.headers.append((name, value.strip(" \t"), index))
        if self.header("Transfer-Encoding"):
            raise ValidationError("Normalize Transfer-Encoding da requisição no Repeater antes de importar.")
        if len(self.header_entries("Content-Length")) > 1:
            raise ValidationError("Content-Length repetido não suportado.")

    def header_entries(self, name):
        return [h for h in self.headers if h[0].lower() == name.lower()]

    def header(self, name):
        entries = self.header_entries(name)
        return entries[0][1] if entries else ""

    def rebuild(self, path=None, body=None, header_index=None, header_value=None):
        lines = list(self.lines)
        if path is not None:
            if any(ord(c) < 32 or c in " #" for c in path):
                raise ValidationError("Caminho HTTP inválido.")
            lines[0] = "%s %s %s" % (self.method, path, self.version)
        if header_index is not None:
            if any(ord(c) < 32 and c != "\t" for c in header_value):
                raise ValidationError("Valor de header contém caractere de controle.")
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


class Target(object):
    def __init__(self, location, name, value, index=0, pointer="", codec="json", padded=True):
        self.location, self.name, self.value = location, name, value
        self.index, self.pointer, self.codec, self.padded = index, pointer, codec, padded
        self.typed = location in ("JSON", "HEADER_JSON")

    def label(self):
        return "%s · %s%s" % (self.location, self.name, (" · " + self.pointer) if self.pointer else "")


EXCLUDED_HEADERS = set(("host", "content-length", "transfer-encoding", "connection",
    "authorization", "proxy-authorization", "cookie", "content-type", "content-encoding",
    "accept-encoding", "x-api-key", "x-auth-token"))


def decode_header(value, codec):
    if codec == "json":
        return value.encode("iso-8859-1").decode("utf-8")
    if re.search(r"[^A-Za-z0-9+/=_-]", value) or len(value.rstrip("=")) % 4 == 1:
        raise ValidationError("Base64 inválido.")
    if "=" in value.rstrip("=") or len(value) - len(value.rstrip("=")) > 2:
        raise ValidationError("Padding Base64 inválido.")
    if codec == "base64" and ("-" in value or "_" in value):
        raise ValidationError("Alfabeto Base64url.")
    if codec == "base64url" and ("+" in value or "/" in value):
        raise ValidationError("Alfabeto Base64 padrão.")
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
                notices.append("Segmento de path com encoding inválido ignorado.")

    def pairs(source, location):
        for i, part in enumerate(source.split("&")):
            if part:
                name, sep, value = part.partition("=")
                try:
                    fields.append(Target(location, decode_component(name) + " [%d]" % i, decode_component(value), i))
                except (ValueError, UnicodeError):
                    notices.append("Parâmetro com encoding inválido ignorado.")

    pairs(request.query, "QUERY")
    ct = request.header("Content-Type").lower()
    charset = re.search(r"charset\s*=\s*\"?([^;\s\"]+)", ct)
    encoded = request.header("Content-Encoding").lower() not in ("", "identity")
    if encoded or (charset and charset.group(1) != "utf-8"):
        notices.append("Campos do corpo indisponíveis para compressão ou charset diferente de UTF-8.")
    elif "application/json" in ct or "+json" in ct:
        try:
            doc = JsonDocument(request.body.decode("utf-8"))
            fields.extend(Target("JSON", "body", value, pointer=p) for p, value in doc.values.items())
        except (ValueError, UnicodeError) as exc:
            notices.append("Corpo JSON não editável: " + as_text(exc))
    elif "application/x-www-form-urlencoded" in ct:
        try:
            pairs(request.body.decode("utf-8"), "FORM")
        except UnicodeError:
            notices.append("Form sem UTF-8 válido.")
    elif request.body:
        notices.append("Formato do corpo não suportado; campos de path/query/headers continuam disponíveis.")
    for name, value, index in request.headers:
        if name.lower() in EXCLUDED_HEADERS:
            continue
        if len(request.header_entries(name)) != 1:
            notices.append("Header repetido não editado: " + name)
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
        raise ValidationError("Requisição excede 2.500 campos.")
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
            raise ValidationError("Informe até 50 IDs por rodada.")
        for line in lines:
            if len(line) > 512:
                raise ValidationError("Identificador excede 512 caracteres.")
            value = line
            if target.typed and isinstance(target.value, integer_types + (Decimal, float)) and not isinstance(target.value, bool):
                if not re.match(r"^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$", line):
                    raise ValidationError("O campo JSON é numérico; informe IDs numéricos.")
                value = Decimal(line)
            tests.append(TestCase("Autorização: massa alternativa", value, True))
    if validation:
        tests.append(TestCase("Valor vazio", ""))
        if target.typed:
            tests.extend((TestCase("Nulo JSON", None), TestCase("Objeto no lugar do valor", {}), TestCase("Lista no lugar do valor", [])))
        if meaning == IDENTIFIER:
            tests.append(TestCase("Formato inválido", "invalid-id!"))
        elif meaning == TEXT:
            tests.extend((TestCase("Espaço em branco", " "), TestCase("Texto Unicode", "ação_日本"), TestCase("Texto com 256 caracteres", "A" * 256)))
            if target.typed:
                tests.append(TestCase("Número no lugar do texto", 1))
        elif meaning == NUMBER:
            for value in ("-1", "0", "1.5", "2147483648"):
                tests.append(TestCase("Limite/tipo numérico: " + value, Decimal(value) if target.typed else value))
            tests.append(TestCase("Texto no lugar do número", "not-a-number"))
        elif meaning == BOOLEAN:
            tests.extend((TestCase("Booleano verdadeiro", True if target.typed else "true"), TestCase("Booleano falso", False if target.typed else "false"), TestCase("Coerção numérica", 1 if target.typed else "1")))
            if target.typed:
                tests.append(TestCase("Booleano como texto", "true"))
    seen, output = set(), []
    for test in tests:
        key = (test.authorization, canonical(test.value))
        if canonical(test.value) != canonical(target.value) and key not in seen:
            output.append(test)
            seen.add(key)
    if not output:
        raise ValidationError("Nenhum teste gerado. Informe IDs alternativos ou habilite validação.")
    if len(output) > MAX_TESTS:
        raise ValidationError("Máximo de 50 testes; reduza a massa alternativa.")
    return output


def normalized(body, ignored):
    root = JsonDocument(body.decode("utf-8")).root
    for pointer in ignored:
        parts = pointer_parts(pointer)
        if not parts:
            raise ValidationError("A raiz inteira não pode ser ignorada.")
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
        changes = [] if same else ["Corpo diferente; diff JSON indisponível"]
    code = response.status
    if not 200 <= base.status < 300:
        conclusion = "Inconclusivo: baseline sem sucesso"
    elif code >= 500:
        conclusion = "Revisar: erro de servidor"
    elif code in (401, 403):
        conclusion = "Acesso recusado; confirmar regra esperada"
    elif code == 404:
        conclusion = "Não encontrado ou ocultado; inconclusivo"
    elif 300 <= code < 400:
        conclusion = "Redirecionamento; inconclusivo"
    elif authorization and 200 <= code < 300:
        conclusion = "Revisar autorização: 2xx com ID alternativo (não confirma IDOR)"
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
            raise ValidationError("Tamanho chunked inválido.")
        size = int(size_text, 16)
        pos = end + 2
        if size == 0:
            if raw[pos:pos + 2] != b"\r\n" and b"\r\n\r\n" not in raw[pos:]:
                raise ValidationError("Final chunked incompleto.")
            return b"".join(chunks)
        total += size
        if total > MAX_RESPONSE or pos + size + 2 > len(raw) or raw[pos + size:pos + size + 2] != b"\r\n":
            raise ValidationError("Resposta chunked inválida ou maior que 2 MB.")
        chunks.append(raw[pos:pos + size])
        pos += size + 2


class Response(object):
    def __init__(self, request, raw):
        self.request, self.raw = request, raw
        if raw is None or b"\r\n\r\n" not in raw:
            raise ValidationError("Sem resposta HTTP completa; execução interrompida.")
        if len(raw) > MAX_RESPONSE + 100000:
            raise ValidationError("Resposta maior que o limite de memória.")
        head, self.wire_body = raw.split(b"\r\n\r\n", 1)
        lines = head.decode("iso-8859-1").split("\r\n")
        status = re.match(r"^HTTP/[^ ]+ ([0-9]{3})(?: |$)", lines[0])
        if not status:
            raise ValidationError("Status HTTP inválido.")
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
            raise ValidationError("Transfer-Encoding da resposta não suportado.")
        encoding = headers.get("content-encoding", "")
        if encoding in ("gzip", "x-gzip") and self.body:
            try:
                stream = gzip.GzipFile(fileobj=io.BytesIO(self.body))
                try:
                    self.body = stream.read(MAX_RESPONSE + 1)
                finally:
                    stream.close()
            except (IOError, EOFError, ValueError):
                raise ValidationError("Resposta gzip inválida.")
            if len(self.body) > MAX_RESPONSE:
                raise ValidationError("Resposta descomprimida maior que 2 MB.")
        # Other content encodings remain raw and are compared byte-for-byte.
        self.milliseconds = 0


class RunStopped(Exception):
    pass


def monotonic():
    if sys.platform.startswith("java"):
        from java.lang import System
        return System.nanoTime() / 1000000000.0
    return time.monotonic()


class Runner(object):
    def __init__(self, transport, in_scope, stopped, emit, delay_ms=500):
        if not 0 <= delay_ms <= 10000:
            raise ValidationError("Intervalo inválido.")
        self.transport, self.in_scope, self.stopped, self.emit = transport, in_scope, stopped, emit
        self.delay = delay_ms / 1000.0
        self.last_finished = None
        self.rows = []
        self.outcome = "Execução não iniciada."
        self.complete = False

    def _send(self, raw):
        if self.last_finished is not None:
            remaining = self.delay - (monotonic() - self.last_finished)
            while remaining > 0 and not self.stopped.is_set():
                self.stopped.wait(min(remaining, 0.05))
                remaining = self.delay - (monotonic() - self.last_finished)
        if self.stopped.is_set():
            raise RunStopped("Execução parada; resultados parciais e sem baseline final completo.")
        if not self.in_scope(raw):
            raise ValidationError("Requisição fora do Target scope atual; execução interrompida.")
        started = monotonic()
        response = self.transport(raw)
        finished = monotonic()
        self.last_finished = finished
        if not isinstance(response, Response):
            raise ValidationError("Transporte não retornou resposta válida.")
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
        self.outcome = "Execução em andamento; resultados provisórios."
        try:
            self.outcome = self._run(original, tests, requests, ignored)
        except RunStopped as exc:
            self.outcome = as_text(exc)
        except Exception:
            self.outcome = "Execução interrompida por erro; resultados parciais e sem validação final."
            raise
        finally:
            if not self.complete:
                for row in self.rows:
                    if row["payload"] or not row["test"].startswith("Baseline"):
                        row["analysis"] = "INCONCLUSIVO (rodada incompleta/instável): " + row["analysis"]
        return self.outcome

    def _run(self, original, tests, requests, ignored):
        base = self._send(original)
        self._row("Baseline 1", base, "Referência original")
        if not 200 <= base.status < 300:
            return "Interrompido: baseline sem sucesso (HTTP %d). Revise sessão/requisição." % base.status
        second = self._send(original)
        check = compare(base, second, ignored=ignored)
        stable = base.status == second.status and check["same"]
        self._row("Baseline 2", second, "Baseline estável" if stable else "Baseline instável", check["changes"])
        if not stable:
            return "Interrompido: baselines diferentes. Revise campos dinâmicos e sessão."
        for index, (test, raw) in enumerate(zip(tests, requests), 1):
            response = self._send(raw)
            analysis = compare(base, response, test.authorization, ignored)
            self._row("%d. %s" % (index, test.name), response,
                      analysis["conclusion"] + (" · Corpo igual" if analysis["same"] else " · Corpo diferente"),
                      analysis["changes"], test)
            if response.status in (401, 429):
                return "Interrompido: HTTP %d; verifique sessão/limite. Sem baseline final." % response.status
        final = self._send(original)
        check = compare(base, final, ignored=ignored)
        self.complete = base.status == final.status and check["same"]
        self._row("Baseline final", final, "Referência estável" if self.complete else "Referência mudou; rodada inconclusiva", check["changes"])
        return ("Execução concluída. Revise as evidências." if self.complete else
                "Baseline final mudou: resultados inconclusivos; revise sessão e estado.")


def export_report(runner):
    allowed = ("test", "http_status", "response_bytes", "elapsed_ms", "analysis",
               "changed_json_pointers", "response_body_sha256")
    return {"tool": "Semantic Intruder V2 Python " + VERSION,
            "exported_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "run_status": runner.outcome, "baseline_final_validated": runner.complete,
            "notice": "Triagem; não confirma vulnerabilidades. Sem URLs, headers, corpos ou payloads.",
            "results": [dict((k, row[k]) for k in allowed) for row in runner.rows]}


# The complete Burp/Swing integration is below. The core above imports no Java.
if sys.platform.startswith("java"):
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
            self.unloaded = False
            self.stopped = threading.Event()
            self.original = None
            self.service = None
            self.targets = []
            self.prepared = None
            self.runner = None
            self.rows = []
            self.controls = []
            callbacks.setExtensionName("Semantic Intruder V2 Python")
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
                raise ValidationError("Burp não retornou resposta.")
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
            header.add(JLabel("SEMANTIC INTRUDER V2 · PYTHON · Testes de API por significado"))
            self.source = JLabel("Repeater / HTTP history → botão direito → Extensions → Enviar para Semantic V2 Python")
            header.add(self.source)
            self.panel.add(header, BorderLayout.NORTH)
            settings = JPanel()
            settings.setLayout(BoxLayout(settings, BoxLayout.Y_AXIS))
            self.target_box = JComboBox()
            self.meaning_box = JComboBox(list(MEANINGS))
            self._field(settings, "1. Campo a testar", self.target_box)
            self._field(settings, "2. Significado (sugestão editável)", self.meaning_box)
            self.alternatives = JTextArea(4, 28)
            self.alternatives.setToolTipText("Um ID de teste por linha, sem aspas. A sessão original será mantida.")
            self._field(settings, "3. IDs alternativos (para Identificador)", JScrollPane(self.alternatives))
            self.validation = JCheckBox("Incluir validação de entrada e tipos", True)
            settings.add(self.validation)
            self.ignored = JTextField()
            self.ignored.setToolTipText("JSON Pointers separados por vírgula: /timestamp,/meta/requestId")
            self._field(settings, "Ignorar campos dinâmicos (opcional)", self.ignored)
            self.interval = JSpinner(SpinnerNumberModel(500, 100, 10000, 100))
            self._field(settings, "Intervalo entre requisições (ms)", self.interval)
            self.writes = JCheckBox("Repetir esta operação de escrita (POST/PUT etc.)", False)
            settings.add(self.writes)
            info = JLabel("<html>Até 50 testes + 3 referências. Uma requisição por vez.<br>Exige Target scope do Burp. Não segue redirecionamentos.<br>Parar aguarda o envio atual; valem os timeouts do Burp.</html>")
            info.setBorder(BorderFactory.createEmptyBorder(8, 0, 8, 0))
            settings.add(info)
            self.generate_button = self._button("4. Gerar prévia", self._generate)
            settings.add(self.generate_button)
            self.preview = JTextArea(10, 30)
            self.preview.setEditable(False)
            self.preview.setLineWrap(True)
            self.preview.setWrapStyleWord(True)
            self._field(settings, "Prévia / avisos", JScrollPane(self.preview), grow=True)
            for component in settings.getComponents():
                component.setAlignmentX(0.0)
            self.start = self._button("5. Executar prévia", self._execute)
            self.stop = self._button("Parar", self._stop)
            self.save = self._button("Exportar metadados JSON", self._export)
            self.clear = self._button("Limpar", self._clear)
            self.start.setEnabled(False)
            self.stop.setEnabled(False)
            self.save.setEnabled(False)
            actions = JPanel(FlowLayout(FlowLayout.LEFT))
            for button in (self.start, self.stop, self.save, self.clear):
                actions.add(button)
            self.run_state = JLabel("Nenhuma execução realizada.")
            self.details = JLabel("Importe uma requisição para começar.")
            footer = JPanel(BorderLayout())
            messages = JPanel(GridLayout(0, 1))
            messages.add(self.run_state)
            messages.add(self.details)
            footer.add(actions, BorderLayout.NORTH)
            footer.add(messages, BorderLayout.SOUTH)
            self.panel.add(footer, BorderLayout.SOUTH)
            self.model = ReadOnlyModel(["Teste", "Valor", "HTTP", "Bytes", "ms", "Análise"], 0)
            self.table = JTable(self.model)
            self.table.setRowHeight(22)
            self.table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN)
            for index, width in enumerate((220, 100, 50, 70, 60, 430)):
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
            result_pane.setResizeWeight(0.4)
            settings_scroll = JScrollPane(settings)
            settings_scroll.setPreferredSize(Dimension(420, 680))
            main = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, settings_scroll, result_pane)
            main.setResizeWeight(0.0)
            main.setDividerLocation(440)
            self.panel.add(main, BorderLayout.CENTER)
            self.controls = [self.target_box, self.meaning_box, self.alternatives, self.validation,
                             self.ignored, self.interval, self.writes, self.generate_button]
            self.target_box.addActionListener(Action(self._target_changed))
            self.meaning_box.addActionListener(Action(self._invalidate))
            self.validation.addActionListener(Action(self._invalidate))
            self.writes.addActionListener(Action(self._invalidate))
            self.interval.addChangeListener(Changed(self._invalidate))
            self.alternatives.getDocument().addDocumentListener(Changed(self._invalidate))
            self.ignored.getDocument().addDocumentListener(Changed(self._invalidate))
            self.callbacks.customizeUiComponent(self.panel)

        def _error(self, message):
            JOptionPane.showMessageDialog(self.panel, as_text(message), "Semantic V2 Python", JOptionPane.INFORMATION_MESSAGE)

        def _invalidate(self):
            self.prepared = None
            self.start.setEnabled(False)

        def _target_changed(self):
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
            self.model.setRowCount(0)
            self.target_box.removeAllItems()
            self.alternatives.setText("")
            self.ignored.setText("")
            self.writes.setSelected(False)
            self.preview.setText("")
            self.save.setEnabled(False)
            self.source.setText("Envie uma requisição pelo menu de contexto do Burp.")
            self.run_state.setText("Nenhuma execução realizada.")
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
                self._error("Há uma rodada em andamento. Pare e aguarde antes de importar outra requisição.")
                return
            try:
                request = Request(self._to_bytes(message.getRequest()))
                fields, notices = discover(request)
                service = message.getHttpService()
                if service is None:
                    raise ValidationError("A requisição não possui serviço HTTP de destino.")
                self._clear()
                self.original, self.service, self.targets = request, service, fields
                for field in fields:
                    self.target_box.addItem(field.label())
                self.base_controller.service = service
                self.base_controller.request_data = self._to_java(request.raw)
                self.base_request_editor.setMessage(self.base_controller.request_data, True)
                self.source.setText("%s · %s · %d campos" % (request.method, service.getHost(), len(fields)))
                self.preview.setText("\n".join(notices))
                self.details.setText("Abra Semantic V2 Py, escolha o campo e gere a prévia.")
            except Exception as exc:
                self._error(as_text(exc))

        def _generate(self):
            if self.running:
                return
            self._invalidate()
            try:
                index = self.target_box.getSelectedIndex()
                if self.original is None or not 0 <= index < len(self.targets):
                    raise ValidationError("Importe uma requisição e escolha um campo.")
                if not self._in_scope(self.original.raw, self.service):
                    raise ValidationError("Inclua o endpoint em Target → Scope antes de gerar os testes.")
                writing = self.original.method.upper() not in ("GET", "HEAD", "OPTIONS")
                if writing and not self.writes.isSelected():
                    raise ValidationError("Método %s: habilite a opção de escrita para repetir esta operação." % self.original.method)
                field = self.targets[index]
                ignored = [p.strip() for p in as_text(self.ignored.getText()).split(",") if p.strip()]
                for pointer in ignored:
                    pointer_parts(pointer)
                tests = plan(as_text(self.meaning_box.getSelectedItem()), field,
                             as_text(self.alternatives.getText()), self.validation.isSelected())
                requests = [mutate(self.original, field, test.value) for test in tests]
                for raw in requests:
                    if not self._in_scope(raw, self.service):
                        raise ValidationError("Uma mutação sai do Target scope. Revise o campo, a prévia pretendida e o escopo do endpoint.")
                lines = ["Campo: " + field.label(), "Original: " + json_text(field.value), ""]
                lines.extend("%d. %s → %s" % (i, test.name, json_text(test.value)) for i, test in enumerate(tests, 1))
                lines.extend(("", "Máximo de %d envios: 2 baselines + %d testes + 1 baseline final." % (len(tests) + 3, len(tests)),
                              "IDs alternativos mantêm a sessão original. Um 2xx exige revisão de propriedade e regra de acesso."))
                if writing:
                    lines.append("A operação de escrita será repetida também nos baselines.")
                if field.location == "HEADER_JSON":
                    lines.append("Codec detectado: %s. Assinaturas não são recalculadas." % field.codec)
                self.preview.setText("\n".join(lines))
                self.preview.setCaretPosition(0)
                self.prepared = (self.original.raw, self.service, tests, requests, ignored, int(self.interval.getValue()))
                self.start.setEnabled(True)
                self.details.setText("Prévia pronta. Executar enviará somente esta rodada.")
            except Exception as exc:
                self._error(as_text(exc))

        def _stop(self):
            self.stopped.set()
            self.stop.setEnabled(False)
            self.run_state.setText("Parando: aguarde a requisição atual. Valem os timeouts de conexão do Burp.")

        def _execute(self):
            if self.running or self.prepared is None:
                return
            prepared = self.prepared
            self.running = True
            self.stopped.clear()
            self.start.setEnabled(False)
            self.stop.setEnabled(True)
            self.save.setEnabled(False)
            self.clear.setEnabled(False)
            for control in self.controls:
                control.setEnabled(False)
            self.rows = []
            self.model.setRowCount(0)
            self.current_controller.request_data = self.current_controller.response_data = None
            self.base_controller.response_data = None
            self.request_editor.setMessage(None, True)
            self.response_editor.setMessage(None, False)
            self.base_response_editor.setMessage(None, False)
            self.run_state.setText("Execução em andamento; resultados provisórios até o baseline final.")
            raw, service, tests, requests, ignored, delay = prepared
            runner = Runner(lambda data: self._transport(data, service),
                            lambda data: self._in_scope(data, service), self.stopped,
                            lambda row: on_ui(lambda: self._append(row)), delay)
            self.runner = runner

            def work():
                try:
                    runner.run(raw, tests, requests, ignored)
                except Exception as exc:
                    # Do not log exception messages that may contain request URLs or credentials.
                    runner.outcome = "Execução interrompida (%s). Revise sessão, escopo, formato e timeouts do Burp; resultados parciais." % type(exc).__name__
                    if isinstance(exc, ValidationError):
                        runner.outcome = as_text(exc)
                finally:
                    on_ui(lambda: self._finished(runner))

            self.worker = threading.Thread(target=work, name="SemanticV2Python")
            self.worker.daemon = True
            self.worker.start()

        def _append(self, row):
            if self.unloaded:
                return
            self.rows.append(row)
            self.model.addRow([row["test"], row["payload"], row["http_status"], row["response_bytes"], row["elapsed_ms"], row["analysis"]])
            if len(self.rows) == 1:
                self.base_controller.request_data = self._to_java(row["request"])
                self.base_controller.response_data = self._to_java(row["response"])
                self.base_request_editor.setMessage(self.base_controller.request_data, True)
                self.base_response_editor.setMessage(self.base_controller.response_data, False)
            self.details.setText("%d respostas recebidas." % len(self.rows))

        def _finished(self, runner):
            self.running = False
            if self.unloaded:
                return
            for control in self.controls:
                control.setEnabled(True)
            self.clear.setEnabled(True)
            self.stop.setEnabled(False)
            self.save.setEnabled(bool(runner.rows))
            self._invalidate()
            for index, row in enumerate(self.rows):
                self.model.setValueAt(row["analysis"], index, 5)
            self.run_state.setText(runner.outcome)
            self.run_state.setToolTipText(runner.outcome)
            self.details.setText("Selecione uma linha para examinar request e response.")

        def _select_row(self):
            index = self.table.getSelectedRow()
            if index < 0:
                return
            index = self.table.convertRowIndexToModel(index)
            if index >= len(self.rows):
                return
            row = self.rows[index]
            self.current_controller.service = self.service
            self.current_controller.request_data = self._to_java(row["request"])
            self.current_controller.response_data = self._to_java(row["response"])
            self.request_editor.setMessage(self.current_controller.request_data, True)
            self.response_editor.setMessage(self.current_controller.response_data, False)
            detail = row["analysis"] + (" · Diferenças: " + ", ".join(row["changed_json_pointers"]) if row["changed_json_pointers"] else "")
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
            if destination.exists() and JOptionPane.showConfirmDialog(self.panel, "Substituir o arquivo escolhido?", "Exportação", JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION:
                return
            try:
                with io.open(as_text(destination.getAbsolutePath()), "w", encoding="utf-8") as handle:
                    handle.write(as_text(json.dumps(export_report(self.runner), ensure_ascii=False, indent=2)))
                self.details.setText("Metadados exportados para " + as_text(destination.getName()))
            except Exception as exc:
                self._error("Não foi possível exportar: " + as_text(exc))
