package br.com.semanticburp;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.function.Function;

/** Sequential runner with injectable transport, so safety and stopping can be tested offline. */
public final class RunEngine {
    public record Result(String name, int status, int bytes, long milliseconds, String conclusion,
                         List<String> changes, String hash, HttpRequestResponse exchange) {}
    private final Function<HttpRequest, HttpRequestResponse> transport;
    private final AtomicBoolean stopping;
    private final Consumer<Result> listener;
    private final int delay;
    private long lastFinished;
    private long lastDuration;

    public RunEngine(Function<HttpRequest, HttpRequestResponse> transport, AtomicBoolean stopping, Consumer<Result> listener, int delay) {
        this.transport = transport; this.stopping = stopping; this.listener = listener; this.delay = delay;
        if (delay < 0) throw new IllegalArgumentException("Intervalo negativo.");
    }
    private HttpRequestResponse send(HttpRequest request) throws InterruptedException {
        long remaining = delay - (System.nanoTime() - lastFinished) / 1_000_000;
        while (remaining > 0 && !stopping.get()) {
            Thread.sleep(Math.min(remaining, 50)); remaining = delay - (System.nanoTime() - lastFinished) / 1_000_000;
        }
        if (stopping.get()) throw new InterruptedException("Parado pelo usuário.");
        if (!request.isInScope()) throw new IllegalStateException("Envio interrompido: requisição fora do Target scope atual.");
        long started = System.nanoTime();
        HttpRequestResponse exchange = transport.apply(request);
        lastFinished = System.nanoTime(); lastDuration = (lastFinished - started) / 1_000_000;
        if (exchange == null || !exchange.hasResponse()) throw new IllegalStateException("Sem resposta; execução interrompida.");
        if (exchange.response().body().length() > 2_000_000) throw new IllegalStateException("Resposta maior que 2 MB; execução interrompida.");
        return exchange;
    }
    private void emit(String name, HttpRequestResponse exchange, String conclusion, List<String> changes) {
        listener.accept(new Result(name, exchange.response().statusCode(), exchange.response().body().length(), lastDuration,
            conclusion, changes, Semantics.sha256(exchange.response().body().getBytes()), exchange));
    }
    private String body(HttpRequestResponse exchange) {
        // JSON APIs normally use UTF-8. Invalid UTF-8 falls back to Burp's representation.
        try { return Targets.utf8(exchange.response().body().getBytes()); }
        catch (RuntimeException e) { return exchange.response().bodyToString(); }
    }
    public String run(HttpRequest original, List<Semantics.TestCase> tests, List<HttpRequest> requests, List<String> ignored) throws InterruptedException {
        if (tests.size() != requests.size() || tests.isEmpty() || tests.size() > 50) throw new IllegalArgumentException("Plano inválido.");
        HttpRequestResponse base = send(original);
        int baselineStatus = base.response().statusCode(); String baselineBody = body(base);
        emit("Baseline 1", base, "Referência original", List.of());
        if (baselineStatus < 200 || baselineStatus >= 300) return "Interrompido: baseline sem sucesso (HTTP " + baselineStatus + "). Revise a sessão e a requisição.";
        HttpRequestResponse second = send(original);
        Semantics.Comparison stability = Semantics.compare(baselineStatus, baselineBody, second.response().statusCode(), body(second), false, true, ignored);
        boolean stable = baselineStatus == second.response().statusCode() && stability.sameBody();
        emit("Baseline 2", second, stable ? "Baseline estável" : "Baseline instável; configurar campos dinâmicos", stability.changes());
        if (!stable) return "Interrompido: baselines diferentes. Revise as respostas e configure os JSON Pointers dinâmicos antes de repetir.";
        for (int i = 0; i < tests.size(); i++) {
            Semantics.TestCase test = tests.get(i);
            HttpRequestResponse exchange = send(requests.get(i));
            Semantics.Comparison comparison = Semantics.compare(baselineStatus, baselineBody, exchange.response().statusCode(), body(exchange), test.authorization(), true, ignored);
            emit((i + 1) + ". " + test.name() + " → " + test.value(), exchange,
                comparison.conclusion() + (comparison.sameBody() ? " · Corpo igual" : " · Corpo diferente"), comparison.changes());
            if (exchange.response().statusCode() == 429) return "Interrompido: HTTP 429 (limite de requisições); sem baseline final.";
            if (exchange.response().statusCode() == 401) return "Interrompido: HTTP 401; verifique se a sessão expirou. Sem baseline final.";
        }
        HttpRequestResponse last = send(original);
        Semantics.Comparison end = Semantics.compare(baselineStatus, baselineBody, last.response().statusCode(), body(last), false, true, ignored);
        boolean stillStable = baselineStatus == last.response().statusCode() && end.sameBody();
        emit("Baseline final", last, stillStable ? "Referência permanece estável" : "Referência mudou; resultados da execução inconclusivos", end.changes());
        return stillStable ? "Execução concluída. Selecione uma linha para revisar as evidências." : "Baseline final mudou: revise sessão/estado; os resultados anteriores são inconclusivos.";
    }
}
