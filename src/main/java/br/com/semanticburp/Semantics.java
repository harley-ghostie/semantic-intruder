package br.com.semanticburp;

import com.google.gson.*;
import com.google.gson.stream.*;
import java.io.StringReader;
import java.math.BigDecimal;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

/** Deterministic planning and comparison. No network or Burp dependency. */
public final class Semantics {
    public static final Gson JSON = new GsonBuilder().disableHtmlEscaping().setPrettyPrinting().create();
    public enum Meaning {
        IDENTIFIER("Identificador"), STRING("Texto"), NUMBER("Número"), BOOLEAN("Booleano");
        private final String label;
        Meaning(String label) { this.label = label; }
        public String toString() { return label; }
    }
    public record TestCase(String name, JsonElement value, boolean authorization) {}
    public record Comparison(String conclusion, boolean sameBody, List<String> changes) {}

    public static Meaning classify(String name, JsonElement value) {
        String n = name.toLowerCase(Locale.ROOT);
        if (n.matches(".*(^|[/_.-])(id|uuid)$") || n.endsWith("id") || n.contains("identifier")) return Meaning.IDENTIFIER;
        if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isBoolean()) return Meaning.BOOLEAN;
        if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isNumber()) return Meaning.NUMBER;
        if (value.isJsonPrimitive() && Set.of("true", "false").contains(value.getAsString())) return Meaning.BOOLEAN;
        if (value.isJsonPrimitive() && value.getAsString().matches("-?(0|[1-9][0-9]*)(\\.[0-9]+)?")) return Meaning.NUMBER;
        if (value.isJsonPrimitive() && value.getAsString().matches("[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")) return Meaning.IDENTIFIER;
        return Meaning.STRING;
    }

    public static List<TestCase> plan(Meaning meaning, JsonElement original, boolean typed, String alternatives, boolean validation) {
        List<TestCase> out = new ArrayList<>();
        if (meaning == Meaning.IDENTIFIER) {
            for (String line : alternatives.split("\\R")) {
                String v = line.strip();
                if (v.isEmpty()) continue;
                if (v.length() > 512) throw new IllegalArgumentException("Identificador maior que 512 caracteres.");
                JsonElement value = new JsonPrimitive(v);
                if (typed && original.isJsonPrimitive() && original.getAsJsonPrimitive().isNumber()) {
                    try { value = new JsonPrimitive(new BigDecimal(v)); }
                    catch (NumberFormatException e) { throw new IllegalArgumentException("Este campo é numérico: use IDs numéricos na massa alternativa."); }
                }
                out.add(new TestCase("Autorização: massa alternativa", value, true));
            }
        }
        if (validation) {
            out.add(new TestCase("Valor vazio", new JsonPrimitive(""), false));
            if (typed) {
                out.add(new TestCase("Nulo JSON", JsonNull.INSTANCE, false));
                out.add(new TestCase("Objeto no lugar do valor", new JsonObject(), false));
                out.add(new TestCase("Lista no lugar do valor", new JsonArray(), false));
            }
            switch (meaning) {
                case IDENTIFIER -> out.add(new TestCase("Formato de identificador inválido", new JsonPrimitive("invalid-id!"), false));
                case STRING -> {
                    out.add(new TestCase("Espaço em branco", new JsonPrimitive(" "), false));
                    out.add(new TestCase("Texto Unicode", new JsonPrimitive("ação_日本"), false));
                    out.add(new TestCase("Comprimento de 256 caracteres", new JsonPrimitive("A".repeat(256)), false));
                    if (typed) out.add(new TestCase("Número no lugar do texto", new JsonPrimitive(1), false));
                }
                case NUMBER -> {
                    for (String n : List.of("-1", "0", "1.5", "2147483648"))
                        out.add(new TestCase("Limite/tipo numérico: " + n, typed ? new JsonPrimitive(new BigDecimal(n)) : new JsonPrimitive(n), false));
                    out.add(new TestCase("Texto no lugar do número", new JsonPrimitive("not-a-number"), false));
                }
                case BOOLEAN -> {
                    out.add(new TestCase("Booleano verdadeiro", typed ? new JsonPrimitive(true) : new JsonPrimitive("true"), false));
                    out.add(new TestCase("Booleano falso", typed ? new JsonPrimitive(false) : new JsonPrimitive("false"), false));
                    out.add(new TestCase("Coerção numérica", typed ? new JsonPrimitive(1) : new JsonPrimitive("1"), false));
                    if (typed) out.add(new TestCase("Booleano como texto", new JsonPrimitive("true"), false));
                }
            }
        }
        Set<String> seen = new HashSet<>();
        out.removeIf(t -> t.value.equals(original) || !seen.add(t.authorization + ":" + t.value));
        if (out.size() > 50) throw new IllegalArgumentException("Máximo de 50 testes por execução; reduza a massa alternativa.");
        if (out.isEmpty()) throw new IllegalArgumentException("Nenhum teste gerado. Informe uma massa alternativa ou habilite validação.");
        return List.copyOf(out);
    }

    public static String text(JsonElement value) { return value.isJsonPrimitive() ? value.getAsString() : value.toString(); }
    public static String encode(String value, boolean path) {
        String encoded = URLEncoder.encode(value, StandardCharsets.UTF_8);
        return path ? encoded.replace("+", "%20") : encoded;
    }
    public static String decode(String value, boolean path) {
        return URLDecoder.decode(path ? value.replace("+", "%2B") : value, StandardCharsets.UTF_8);
    }
    public static String replacePair(String raw, int index, String value) {
        String[] parts = raw.split("&", -1);
        if (index < 0 || index >= parts.length) throw new IllegalArgumentException("Parâmetro não encontrado.");
        int eq = parts[index].indexOf('=');
        String name = eq < 0 ? parts[index] : parts[index].substring(0, eq);
        parts[index] = name + "=" + encode(value, false);
        return String.join("&", parts);
    }

    /** Reject duplicate keys and non-JSON syntax rather than silently losing fields. */
    public static JsonElement parse(String source) {
        if (source.length() > 1_000_000) throw new IllegalArgumentException("JSON maior que 1 MB de caracteres não é processado.");
        try (JsonReader reader = new JsonReader(new StringReader(source))) {
            reader.setStrictness(Strictness.STRICT);
            JsonElement result = read(reader, 0);
            if (reader.peek() != JsonToken.END_DOCUMENT) throw new IllegalArgumentException("Conteúdo após JSON.");
            return result;
        } catch (Exception e) { throw new IllegalArgumentException("JSON inválido, profundo demais ou com chaves duplicadas.", e); }
    }
    private static JsonElement read(JsonReader reader, int depth) throws java.io.IOException {
        if (depth > 64) throw new IllegalArgumentException("Profundidade máxima: 64.");
        return switch (reader.peek()) {
            case BEGIN_OBJECT -> {
                JsonObject object = new JsonObject(); reader.beginObject();
                while (reader.hasNext()) {
                    String name = reader.nextName();
                    if (object.has(name)) throw new IllegalArgumentException("Chave duplicada.");
                    object.add(name, read(reader, depth + 1));
                }
                reader.endObject(); yield object;
            }
            case BEGIN_ARRAY -> {
                JsonArray array = new JsonArray(); reader.beginArray();
                while (reader.hasNext()) array.add(read(reader, depth + 1));
                reader.endArray(); yield array;
            }
            case STRING -> new JsonPrimitive(reader.nextString());
            case NUMBER -> new JsonPrimitive(new BigDecimal(reader.nextString()));
            case BOOLEAN -> new JsonPrimitive(reader.nextBoolean());
            case NULL -> { reader.nextNull(); yield JsonNull.INSTANCE; }
            default -> throw new IllegalArgumentException("Token JSON inesperado.");
        };
    }
    public static Map<String, JsonElement> leaves(JsonElement root) {
        Map<String, JsonElement> result = new LinkedHashMap<>();
        flatten(root, "", result); return result;
    }
    private static void flatten(JsonElement node, String path, Map<String, JsonElement> out) {
        if (out.size() >= 2000) throw new IllegalArgumentException("Máximo de 2.000 campos JSON.");
        if (node.isJsonObject() && !node.getAsJsonObject().isEmpty())
            node.getAsJsonObject().entrySet().forEach(e -> flatten(e.getValue(), path + "/" + escape(e.getKey()), out));
        else if (node.isJsonArray() && !node.getAsJsonArray().isEmpty()) {
            for (int i = 0; i < node.getAsJsonArray().size(); i++) flatten(node.getAsJsonArray().get(i), path + "/" + i, out);
        } else out.put(path, node);
    }
    private static String escape(String key) { return key.replace("~", "~0").replace("/", "~1"); }
    private static String unescape(String key) {
        if (key.matches(".*~(?![01]).*")) throw new IllegalArgumentException("Escape de JSON Pointer inválido.");
        return key.replace("~1", "/").replace("~0", "~");
    }
    public static JsonElement replace(JsonElement root, String pointer, JsonElement value) {
        if (pointer.isEmpty()) return value.deepCopy();
        if (!pointer.startsWith("/")) throw new IllegalArgumentException("JSON Pointer deve começar com /.");
        JsonElement copy = root.deepCopy(), node = copy;
        String[] pieces = pointer.substring(1).split("/", -1);
        for (int i = 0; i < pieces.length - 1; i++) node = child(node, unescape(pieces[i]));
        String last = unescape(pieces[pieces.length - 1]);
        child(node, last); // Require existing field, no silent additions.
        if (node.isJsonObject()) node.getAsJsonObject().add(last, value.deepCopy());
        else node.getAsJsonArray().set(Integer.parseInt(last), value.deepCopy());
        return copy;
    }
    private static JsonElement child(JsonElement node, String key) {
        JsonElement next = node.isJsonObject() ? node.getAsJsonObject().get(key) : node.getAsJsonArray().get(Integer.parseInt(key));
        if (next == null) throw new IllegalArgumentException("JSON Pointer inexistente.");
        return next;
    }
    private static JsonElement normalize(String body, List<String> ignored) {
        JsonElement tree = parse(body);
        for (String pointer : ignored) {
            try { tree = replace(tree, pointer, new JsonPrimitive("<campo ignorado>")); }
            catch (RuntimeException ignoredMissingPath) { /* Field may be absent in an error response. */ }
        }
        return tree;
    }
    public static Comparison compare(int baseStatus, String base, int status, String body, boolean authorization, boolean stable, List<String> ignored) {
        boolean equal;
        List<String> changes = new ArrayList<>();
        try {
            JsonElement a = normalize(base, ignored), b = normalize(body, ignored);
            equal = a.equals(b);
            Map<String, JsonElement> left = leaves(a), right = leaves(b);
            Set<String> paths = new TreeSet<>(left.keySet()); paths.addAll(right.keySet());
            for (String p : paths) if (!Objects.equals(left.get(p), right.get(p)) && changes.size() < 30) changes.add(p.isEmpty() ? "(raiz)" : p);
        } catch (RuntimeException e) {
            equal = base.equals(body);
            if (!equal) changes.add("Corpo diferente; diff JSON indisponível");
        }
        String conclusion;
        if (!stable || baseStatus < 200 || baseStatus >= 300) conclusion = "Inconclusivo: baseline instável ou sem sucesso";
        else if (status >= 500) conclusion = "Revisar: erro de servidor";
        else if (status == 401 || status == 403) conclusion = "Acesso recusado; confirmar regra esperada";
        else if (status == 404) conclusion = "Não encontrado ou ocultado; inconclusivo";
        else if (status >= 300 && status < 400) conclusion = "Redirecionamento não seguido; inconclusivo";
        else if (authorization && status >= 200 && status < 300) conclusion = "Revisar autorização: 2xx com ID alternativo (não confirma IDOR)";
        else if (status >= 400) conclusion = "Entrada recusada; confirmar contrato";
        else if (status >= 200 && status < 300) conclusion = "Entrada aceita; validar contrato e efeito";
        else conclusion = "Inconclusivo";
        return new Comparison(conclusion, equal, List.copyOf(changes));
    }
    public static String sha256(byte[] value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value)); }
        catch (Exception e) { throw new IllegalStateException(e); }
    }
}
