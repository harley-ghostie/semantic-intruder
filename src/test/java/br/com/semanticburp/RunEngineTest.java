package br.com.semanticburp;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.google.gson.JsonPrimitive;
import org.junit.jupiter.api.Test;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.atomic.*;
import java.util.function.BooleanSupplier;
import static org.junit.jupiter.api.Assertions.*;

class RunEngineTest {
    @SuppressWarnings("unchecked") private static <T> T proxy(Class<T> type, java.lang.reflect.InvocationHandler handler) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class[]{type}, handler);
    }
    private HttpRequest request(BooleanSupplier inScope) {
        return proxy(HttpRequest.class, (p,m,a) -> {
            if (m.getName().equals("isInScope")) return inScope.getAsBoolean();
            throw new UnsupportedOperationException(m.getName());
        });
    }
    private HttpRequestResponse response(int status, String body) {
        ByteArray bytes = proxy(ByteArray.class, (p,m,a) -> switch (m.getName()) {
            case "length" -> body.getBytes(StandardCharsets.UTF_8).length;
            case "getBytes" -> body.getBytes(StandardCharsets.UTF_8);
            default -> throw new UnsupportedOperationException(m.getName());
        });
        HttpResponse response = proxy(HttpResponse.class, (p,m,a) -> switch (m.getName()) {
            case "statusCode" -> (short) status; case "bodyToString" -> body; case "body" -> bytes;
            default -> throw new UnsupportedOperationException(m.getName());
        });
        return proxy(HttpRequestResponse.class, (p,m,a) -> switch (m.getName()) {
            case "hasResponse" -> true; case "response" -> response;
            default -> throw new UnsupportedOperationException(m.getName());
        });
    }
    private List<Semantics.TestCase> tests(int count) {
        List<Semantics.TestCase> out = new ArrayList<>();
        for (int i = 0; i < count; i++) out.add(new Semantics.TestCase("ID alternativo", new JsonPrimitive("B" + i), true));
        return out;
    }
    @Test void sendsTwoBaselinesThenMutationsThenFinalBaseline() throws Exception {
        HttpRequest base = request(() -> true), altered = request(() -> true);
        List<HttpRequest> sent = new ArrayList<>(); List<RunEngine.Result> rows = new ArrayList<>();
        RunEngine engine = new RunEngine(req -> { sent.add(req); return response(200, sent.size() == 3 ? "{\"owner\":\"B\"}" : "{\"owner\":\"A\"}"); }, new AtomicBoolean(), rows::add, 0);
        assertTrue(engine.run(base, tests(1), List.of(altered), List.of()).startsWith("Execução concluída"));
        assertEquals(4, sent.size()); assertSame(base, sent.get(0)); assertSame(base, sent.get(1)); assertSame(altered, sent.get(2)); assertSame(base, sent.get(3));
        assertTrue(rows.get(2).conclusion().contains("não confirma IDOR"));
    }
    @Test void invalidBaselineSendsNoMutations() throws Exception {
        AtomicInteger count = new AtomicInteger(); HttpRequest req = request(() -> true);
        RunEngine engine = new RunEngine(r -> { count.incrementAndGet(); return response(401, "{}"); }, new AtomicBoolean(), r -> {}, 0);
        assertTrue(engine.run(req, tests(1), List.of(req), List.of()).contains("baseline sem sucesso")); assertEquals(1, count.get());
    }
    @Test void changingBaselineHaltsBeforeMutations() throws Exception {
        AtomicInteger count = new AtomicInteger(); HttpRequest req = request(() -> true);
        RunEngine engine = new RunEngine(r -> response(200, "{\"time\":" + count.incrementAndGet() + "}"), new AtomicBoolean(), r -> {}, 0);
        assertTrue(engine.run(req, tests(1), List.of(req), List.of()).contains("baselines diferentes")); assertEquals(2, count.get());
    }
    @Test void ignoredDynamicPointerAllowsStableSequence() throws Exception {
        AtomicInteger count = new AtomicInteger(); HttpRequest req = request(() -> true);
        RunEngine engine = new RunEngine(r -> response(200, "{\"time\":" + count.incrementAndGet() + "}"), new AtomicBoolean(), r -> {}, 0);
        assertTrue(engine.run(req, tests(1), List.of(req), List.of("/time")).contains("concluída")); assertEquals(4, count.get());
    }
    @Test void scopeIsCheckedAgainBeforeEverySend() {
        AtomicInteger count = new AtomicInteger(); HttpRequest req = request(() -> count.get() < 2);
        RunEngine engine = new RunEngine(r -> { count.incrementAndGet(); return response(200, "{}"); }, new AtomicBoolean(), r -> {}, 0);
        assertThrows(IllegalStateException.class, () -> engine.run(req, tests(1), List.of(req), List.of())); assertEquals(2, count.get());
    }
    @Test void userStopDoesNotSendFollowingRequest() {
        AtomicInteger count = new AtomicInteger(); AtomicBoolean stop = new AtomicBoolean(); HttpRequest req = request(() -> true);
        RunEngine engine = new RunEngine(r -> { count.incrementAndGet(); stop.set(true); return response(200, "{}"); }, stop, r -> {}, 0);
        assertThrows(InterruptedException.class, () -> engine.run(req, tests(2), List.of(req,req), List.of())); assertEquals(1, count.get());
    }
    @Test void rateLimitAndExpiredSessionStopRemainingTests() throws Exception {
        for (int status : List.of(401,429)) {
            AtomicInteger count = new AtomicInteger(); HttpRequest req = request(() -> true);
            RunEngine engine = new RunEngine(r -> response(count.incrementAndGet() == 3 ? status : 200, "{}"), new AtomicBoolean(), r -> {}, 0);
            assertTrue(engine.run(req, tests(2), List.of(req,req), List.of()).contains("HTTP " + status)); assertEquals(3, count.get());
        }
    }
    @Test void changedFinalBaselineMarksRunInconclusive() throws Exception {
        AtomicInteger count = new AtomicInteger(); HttpRequest req = request(() -> true);
        RunEngine engine = new RunEngine(r -> response(count.incrementAndGet() == 4 ? 401 : 200, "{}"), new AtomicBoolean(), r -> {}, 0);
        assertTrue(engine.run(req, tests(1), List.of(req), List.of()).contains("inconclusivos"));
    }
    @Test void missingOrOversizedResponseInterruptsRun() {
        HttpRequest req = request(() -> true);
        for (HttpRequestResponse reply : Arrays.asList(null, response(200,"X".repeat(2_000_001)))) {
            RunEngine engine = new RunEngine(r -> reply, new AtomicBoolean(), r -> {}, 0);
            assertThrows(IllegalStateException.class, () -> engine.run(req, tests(1), List.of(req), List.of()));
        }
    }
    @Test void delayIsRespectedBetweenFinishingAndStartingRequests() throws Exception {
        HttpRequest req = request(() -> true); List<Long> times = new ArrayList<>();
        RunEngine engine = new RunEngine(r -> { times.add(System.nanoTime()); return response(200, "{}"); }, new AtomicBoolean(), r -> {}, 100);
        engine.run(req, tests(1), List.of(req), List.of());
        for (int i = 1; i < times.size(); i++) assertTrue(times.get(i) - times.get(i-1) >= 95_000_000L);
    }
    @Test void rejectsMismatchedAndOversizedPlansBeforeTransport() {
        HttpRequest req = request(() -> true); AtomicInteger count = new AtomicInteger();
        RunEngine engine = new RunEngine(r -> { count.incrementAndGet(); return response(200, "{}"); }, new AtomicBoolean(), r -> {}, 0);
        assertThrows(IllegalArgumentException.class, () -> engine.run(req, tests(2), List.of(req), List.of()));
        assertThrows(IllegalArgumentException.class, () -> engine.run(req, tests(51), Collections.nCopies(51, req), List.of()));
        assertEquals(0,count.get());
    }
}
