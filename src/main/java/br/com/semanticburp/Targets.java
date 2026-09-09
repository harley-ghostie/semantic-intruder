package br.com.semanticburp;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.core.ByteArray;
import com.google.gson.*;
import java.nio.ByteBuffer;
import java.nio.charset.*;
import java.util.*;

public final class Targets {
    public enum Location { PATH, QUERY, FORM, JSON, HEADER, HEADER_JSON }
    public enum Codec { PLAIN, BASE64, BASE64_URL }
    public record Target(Location location, String name, int index, String pointer, JsonElement value, Codec codec, boolean padded) {
        public boolean typed() { return location == Location.JSON || location == Location.HEADER_JSON; }
        public String toString() { return location + " · " + name + (pointer.isEmpty() ? "" : " · " + pointer); }
    }
    public record Discovery(List<Target> fields, List<String> notices) {}
    // Routing, framing and authentication headers are not input-validation targets.
    private static final Set<String> EXCLUDED = Set.of("host", "content-length", "transfer-encoding", "connection", "authorization", "proxy-authorization", "cookie", "content-type", "content-encoding", "accept-encoding");

    public static Discovery discover(HttpRequest request) {
        List<Target> result = new ArrayList<>();
        List<String> notices = new ArrayList<>();
        String[] segments = request.pathWithoutQuery().split("/", -1);
        for (int i = 0; i < segments.length; i++) if (!segments[i].isEmpty()) {
            try { result.add(target(Location.PATH, "segmento " + i, i, Semantics.decode(segments[i], true))); }
            catch (RuntimeException e) { notices.add("Segmento de path com encoding inválido ignorado."); }
        }
        pairs(request.query(), Location.QUERY, result, notices);
        String ct = Optional.ofNullable(request.headerValue("Content-Type")).orElse("").toLowerCase(Locale.ROOT);
        String ce = Optional.ofNullable(request.headerValue("Content-Encoding")).orElse("identity");
        boolean utf8 = !ct.contains("charset=") || ct.matches(".*charset=\"?utf-8\"?([; ].*)?$");
        if (!ce.equalsIgnoreCase("identity") || !utf8) notices.add("Corpo com compressão ou charset diferente de UTF-8: campos do corpo não listados.");
        else if (ct.contains("application/json") || ct.contains("+json")) {
            try { addJson(Location.JSON, "body", Semantics.parse(utf8(request.body().getBytes())), Codec.PLAIN, true, result); }
            catch (RuntimeException e) { notices.add("Corpo JSON não editável: " + e.getMessage()); }
        } else if (ct.contains("application/x-www-form-urlencoded")) {
            try { pairs(utf8(request.body().getBytes()), Location.FORM, result, notices); }
            catch (RuntimeException e) { notices.add("Corpo form sem UTF-8 válido: campos não listados."); }
        }
        else if (request.body().length() > 0) notices.add("Formato do corpo não suportado; path, query e headers continuam disponíveis.");
        Map<String, Integer> counts = new HashMap<>();
        request.headers().forEach(h -> counts.merge(h.name().toLowerCase(Locale.ROOT), 1, Integer::sum));
        request.headers().forEach(header -> {
            String name = header.name(), lower = name.toLowerCase(Locale.ROOT), value = header.value();
            if (lower.startsWith(":") || EXCLUDED.contains(lower)) return;
            if (counts.get(lower) != 1) { notices.add("Header repetido não editado: " + name); return; }
            if (lower.equals("x-charon") || lower.equals("x-charon-params")) {
                for (Codec codec : Codec.values()) {
                    try {
                        JsonElement json = Semantics.parse(decodeHeader(value, codec));
                        if (!json.isJsonObject() && !json.isJsonArray()) continue;
                        addJson(Location.HEADER_JSON, name, json, codec, value.endsWith("="), result);
                        return;
                    } catch (RuntimeException ignored) { }
                }
                notices.add(name + ": estrutura desconhecida; edição interna indisponível (suporta JSON e Base64 de JSON).");
                return;
            }
            result.add(target(Location.HEADER, name, 0, value));
        });
        if (result.size() > 2500) throw new IllegalArgumentException("Requisição com campos demais (limite: 2.500).");
        return new Discovery(List.copyOf(result), List.copyOf(new LinkedHashSet<>(notices)));
    }
    private static Target target(Location where, String name, int index, String value) {
        return new Target(where, name, index, "", new JsonPrimitive(value), Codec.PLAIN, true);
    }
    private static void pairs(String source, Location where, List<Target> out, List<String> notices) {
        if (source == null || source.isEmpty()) return;
        String[] pairs = source.split("&", -1);
        for (int i = 0; i < pairs.length; i++) {
            if (pairs[i].isEmpty()) continue;
            String[] pair = pairs[i].split("=", 2);
            try { out.add(target(where, Semantics.decode(pair[0], false) + " [" + i + "]", i, Semantics.decode(pair.length == 2 ? pair[1] : "", false))); }
            catch (RuntimeException e) { notices.add("Parâmetro com encoding inválido ignorado."); }
        }
    }
    private static void addJson(Location location, String name, JsonElement json, Codec codec, boolean padded, List<Target> out) {
        Semantics.leaves(json).forEach((pointer, value) -> out.add(new Target(location, name, 0, pointer, value, codec, padded)));
    }
    static String decodeHeader(String value, Codec codec) {
        if (codec == Codec.PLAIN) return value;
        byte[] bytes = (codec == Codec.BASE64 ? Base64.getDecoder() : Base64.getUrlDecoder()).decode(value);
        return utf8(bytes);
    }
    static String utf8(byte[] bytes) {
        try { return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString(); }
        catch (CharacterCodingException e) { throw new IllegalArgumentException("Base64 sem texto UTF-8 válido.", e); }
    }
    static String encodeHeader(String value, Codec codec, boolean padded) {
        if (codec == Codec.PLAIN) return value;
        Base64.Encoder encoder = codec == Codec.BASE64 ? Base64.getEncoder() : Base64.getUrlEncoder();
        if (!padded) encoder = encoder.withoutPadding();
        return encoder.encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
    public static HttpRequest mutate(HttpRequest original, Target target, JsonElement value) {
        return mutate(original, target, value, (request, body) -> request.withBody(ByteArray.byteArray(body.getBytes(StandardCharsets.UTF_8))));
    }
    static HttpRequest mutate(HttpRequest original, Target target, JsonElement value, java.util.function.BiFunction<HttpRequest, String, HttpRequest> bodyWriter) {
        String text = Semantics.text(value);
        return switch (target.location) {
            case PATH -> {
                String[] segments = original.pathWithoutQuery().split("/", -1);
                segments[target.index] = Semantics.encode(text, true);
                String path = String.join("/", segments);
                // Preserve even an empty query delimiter.
                int queryOffset = original.path().indexOf('?');
                yield original.withPath(path + (queryOffset < 0 ? "" : original.path().substring(queryOffset)));
            }
            case QUERY -> original.withPath(original.pathWithoutQuery() + "?" + Semantics.replacePair(original.query(), target.index, text));
            case FORM -> bodyWriter.apply(original, Semantics.replacePair(utf8(original.body().getBytes()), target.index, text));
            case JSON -> bodyWriter.apply(original, Semantics.replace(Semantics.parse(utf8(original.body().getBytes())), target.pointer, value).toString());
            case HEADER -> {
                if (text.indexOf('\r') >= 0 || text.indexOf('\n') >= 0 || text.indexOf('\0') >= 0) throw new IllegalArgumentException("Valor de header contém quebra de linha ou NUL.");
                yield original.withUpdatedHeader(target.name, text);
            }
            case HEADER_JSON -> {
                JsonElement root = Semantics.parse(decodeHeader(original.headerValue(target.name), target.codec));
                String modified = Semantics.replace(root, target.pointer, value).toString();
                yield original.withUpdatedHeader(target.name, encodeHeader(modified, target.codec, target.padded));
            }
        };
    }
}
