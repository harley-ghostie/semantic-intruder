package br.com.semanticburp;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.core.ByteArray;
import com.google.gson.*;
import org.junit.jupiter.api.Test;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.*;
import static org.junit.jupiter.api.Assertions.*;

class TargetsTest {
    /** Small immutable request double: no Montoya factory or Burp process is required. */
    static HttpRequest request(String path, String body, Map<String, String> headers) {
        return (HttpRequest) Proxy.newProxyInstance(HttpRequest.class.getClassLoader(), new Class[]{HttpRequest.class}, (p, m, args) -> switch (m.getName()) {
            case "path" -> path;
            case "query" -> path.contains("?") ? path.substring(path.indexOf('?') + 1) : "";
            case "pathWithoutQuery" -> path.split("\\?", -1)[0];
            case "bodyToString" -> body;
            case "body" -> Proxy.newProxyInstance(ByteArray.class.getClassLoader(), new Class[]{ByteArray.class}, (p2,m2,a2) -> switch (m2.getName()) {
                case "length" -> body.getBytes(StandardCharsets.UTF_8).length;
                case "getBytes" -> body.getBytes(StandardCharsets.UTF_8);
                default -> throw new UnsupportedOperationException(m2.getName());
            });
            case "headerValue" -> headers.entrySet().stream().filter(e -> e.getKey().equalsIgnoreCase((String) args[0])).map(Map.Entry::getValue).findFirst().orElse(null);
            case "headers" -> headers.entrySet().stream().map(e -> (HttpHeader) Proxy.newProxyInstance(HttpHeader.class.getClassLoader(), new Class[]{HttpHeader.class}, (p2,m2,a2) -> switch (m2.getName()) {
                case "name" -> e.getKey(); case "value" -> e.getValue(); default -> throw new UnsupportedOperationException(m2.getName());
            })).toList();
            case "withPath" -> request((String) args[0], body, headers);
            case "withBody" -> request(path, (String) args[0], headers);
            case "withUpdatedHeader" -> {
                Map<String, String> updated = new LinkedHashMap<>(headers); updated.put((String) args[0], (String) args[1]);
                yield request(path, body, updated);
            }
            default -> throw new UnsupportedOperationException(m.getName());
        });
    }
    private Targets.Target field(HttpRequest request, Targets.Location location, int index) {
        return Targets.discover(request).fields().stream().filter(t -> t.location() == location && t.index() == index).findFirst().orElseThrow();
    }
    @Test void pathMutationPreservesQueryAndEncodesSlashesInsideValue() {
        HttpRequest original = request("/api/cards/a+b?sig=x%2By&id=1", "", Map.of());
        HttpRequest mutated = Targets.mutate(original, field(original, Targets.Location.PATH, 3), new JsonPrimitive("x/y z"));
        assertEquals("/api/cards/x%2Fy%20z?sig=x%2By&id=1", mutated.path());
        assertEquals("/api/cards/a+b?sig=x%2By&id=1", original.path());
    }
    @Test void queryMutationUsesOccurrenceIndexRatherThanReplacingEveryId() {
        HttpRequest original = request("/api?id=1&id=2&sig=%2F+", "", Map.of());
        assertEquals("/api?id=1&id=9&sig=%2F+", Targets.mutate(original, field(original, Targets.Location.QUERY, 1), new JsonPrimitive("9")).path());
    }
    @Test void formMutationPreservesOtherFieldsAndHeaders() {
        HttpRequest original = request("/api?x=1", "id=1&id=2&sig=%2F+", Map.of("Content-Type", "application/x-www-form-urlencoded", "Authorization", "Bearer test"));
        HttpRequest mutated = Targets.mutate(original, field(original, Targets.Location.FORM, 1), new JsonPrimitive("9"), HttpRequest::withBody);
        assertEquals("id=1&id=9&sig=%2F+", mutated.bodyToString());
        assertEquals("Bearer test", mutated.headerValue("Authorization")); assertEquals(original.path(), mutated.path());
    }
    @Test void nestedBodyMaintainsTypesAndOnlyChangesSelectedJsonPointer() {
        HttpRequest original = request("/api", "{\"id\":1,\"items\":[{\"id\":2,\"ok\":true}]}", Map.of("Content-Type", "application/problem+json; charset=utf-8"));
        var target = Targets.discover(original).fields().stream().filter(t -> t.pointer().equals("/items/0/id")).findFirst().orElseThrow();
        assertTrue(target.typed());
        assertEquals(Semantics.parse("{\"id\":1,\"items\":[{\"id\":null,\"ok\":true}]}"), Semantics.parse(Targets.mutate(original, target, JsonNull.INSTANCE, HttpRequest::withBody).bodyToString()));
    }
    @Test void charonJsonAndBase64AreParsedAndReencoded() {
        for (Targets.Codec codec : Targets.Codec.values()) for (boolean padded : List.of(true, false)) {
            String encoded = Targets.encodeHeader("{\"accountId\":\"A\",\"keep\":3}", codec, padded);
            HttpRequest original = request("/api", "", Map.of("x-charon-params", encoded));
            var target = Targets.discover(original).fields().stream().filter(t -> t.pointer().equals("/accountId")).findFirst().orElseThrow();
            String changed = Targets.mutate(original, target, new JsonPrimitive("B")).headerValue("x-charon-params");
            assertEquals(Semantics.parse("{\"accountId\":\"B\",\"keep\":3}"), Semantics.parse(Targets.decodeHeader(changed, target.codec())));
            if (!padded && codec != Targets.Codec.PLAIN) assertFalse(changed.endsWith("="));
        }
    }
    @Test void urlSafeBase64KeepsItsAlphabetWhenDistinguishable() {
        String json = "{\"id\":\"~~~\"}";
        String encoded = Targets.encodeHeader(json, Targets.Codec.BASE64_URL, false);
        assertEquals(json, Targets.decodeHeader(encoded, Targets.Codec.BASE64_URL));
    }
    @Test void unknownCharonAndMalformedJsonAreNotSilentlyEdited() {
        var d = Targets.discover(request("/api", "{\"id\":1,\"id\":2}", Map.of("Content-Type", "application/json", "x-charon", "opaque.not.json")));
        assertTrue(d.fields().stream().noneMatch(t -> t.location() == Targets.Location.JSON || t.name().equals("x-charon")));
        assertEquals(2, d.notices().size());
    }
    @Test void skipsAuthenticationAndFramingHeaders() {
        var d = Targets.discover(request("/api", "", Map.of("Authorization", "secret", "Cookie", "session=x", "Host", "a", "Content-Length", "0", "device-id", "dev-1")));
        assertEquals(List.of("device-id"), d.fields().stream().filter(t -> t.location() == Targets.Location.HEADER).map(Targets.Target::name).toList());
    }
    @Test void rejectsHeaderLineBreaks() {
        HttpRequest original = request("/api", "", Map.of("device-id", "dev-1"));
        assertThrows(IllegalArgumentException.class, () -> Targets.mutate(original, field(original, Targets.Location.HEADER, 0), new JsonPrimitive("a\r\nb")));
    }
    @Test void compressedAndNonUtf8BodiesAreSkipped() {
        for (Map<String, String> headers : List.of(Map.of("Content-Type", "application/json", "Content-Encoding", "gzip"), Map.of("Content-Type", "application/json; charset=iso-8859-1"))) {
            var d = Targets.discover(request("/api", "{\"id\":1}", headers));
            assertTrue(d.fields().stream().noneMatch(t -> t.location() == Targets.Location.JSON));
            assertFalse(d.notices().isEmpty());
        }
    }
}
