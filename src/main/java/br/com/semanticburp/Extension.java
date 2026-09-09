package br.com.semanticburp;

import burp.api.montoya.BurpExtension;
import br.com.semanticburp.RunEngine.Result;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.*;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.editor.*;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.time.Instant;
import java.util.*;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

public final class Extension implements BurpExtension {
    private MontoyaApi api;
    private final AtomicBoolean stopping = new AtomicBoolean();
    private final AtomicBoolean unloaded = new AtomicBoolean();
    private volatile boolean running;
    private String runSummary = "Nenhuma execução realizada.";
    private JPanel panel, settings;
    private JComboBox<Targets.Target> target;
    private JComboBox<Semantics.Meaning> meaning;
    private JTextArea alternatives, preview;
    private JTextField ignoredPaths;
    private JCheckBox validation, allowWrites;
    private JSpinner interval;
    private JLabel status, source, runState;
    private JButton start, stop, export;
    private DefaultTableModel model;
    private JTable table;
    private HttpRequestEditor requestEditor, baselineRequestEditor;
    private HttpResponseEditor responseEditor, baselineResponseEditor;
    private HttpRequest original;
    private Prepared prepared;
    private final List<Result> results = new ArrayList<>();
    private record Prepared(HttpRequest original, Targets.Target target, List<Semantics.TestCase> tests,
                            List<HttpRequest> requests, List<String> ignored, int delay) {}


    @Override public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Semantic Intruder V2");
        api.extension().registerUnloadingHandler(() -> { unloaded.set(true); stopping.set(true); });
        Runnable setup = () -> {
            buildUi();
            api.userInterface().registerSuiteTab("Semantic V2", panel);
            api.userInterface().registerContextMenuItemsProvider(new burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider() {
              @Override public List<Component> provideMenuItems(burp.api.montoya.ui.contextmenu.ContextMenuEvent event) {
                HttpRequest request = event.messageEditorRequestResponse().map(e -> e.requestResponse().request())
                    .orElseGet(() -> event.selectedRequestResponses().isEmpty() ? null : event.selectedRequestResponses().get(0).request());
                if (request == null) return List.of();
                JMenuItem item = new JMenuItem("Enviar para Semantic V2");
                item.addActionListener(e -> load(request));
                return List.of(item);
              }
            });
            api.logging().logToOutput("Semantic Intruder V2 0.2.0 carregado. Envie uma requisição pelo menu de contexto e abra a aba Semantic V2.");
        };
        if (SwingUtilities.isEventDispatchThread()) setup.run();
        else try { SwingUtilities.invokeAndWait(setup); } catch (Exception e) { throw new IllegalStateException(e); }
    }

    private void buildUi() {
        panel = new JPanel(new BorderLayout(8, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        JPanel heading = new JPanel(new GridLayout(0, 1, 0, 4));
        heading.add(new JLabel("SEMANTIC INTRUDER V2 · Testes de API orientados pelo significado do campo"));
        source = new JLabel("No Repeater ou HTTP history: botão direito → Extensions → Enviar para Semantic V2.");
        heading.add(source); panel.add(heading, BorderLayout.NORTH);

        settings = new JPanel(); settings.setLayout(new BoxLayout(settings, BoxLayout.Y_AXIS));
        target = new JComboBox<>(); meaning = new JComboBox<>(Semantics.Meaning.values());
        addSetting("1. Campo a testar", target); addSetting("2. Significado (sugestão editável)", meaning);
        alternatives = new JTextArea(4, 25);
        alternatives.setToolTipText("Um ID de teste por linha, sem aspas. A sessão original será mantida. Nenhum ID é enumerado automaticamente.");
        addSetting("3. IDs alternativos da massa de teste (somente Identificador)", new JScrollPane(alternatives));
        validation = new JCheckBox("Incluir validação de entrada e tipos", true); settings.add(validation);
        ignoredPaths = new JTextField();
        ignoredPaths.setToolTipText("JSON Pointers exatos separados por vírgula. Ex.: /timestamp,/requestId. Não ignore IDs/proprietários que deseja comparar.");
        addSetting("Ignorar campos dinâmicos na comparação (opcional)", ignoredPaths);
        interval = new JSpinner(new SpinnerNumberModel(500, 100, 10000, 100));
        addSetting("Intervalo entre requisições (ms)", interval);
        allowWrites = new JCheckBox("Incluir esta requisição de escrita (POST/PUT/PATCH/DELETE etc.)");
        settings.add(allowWrites);
        JLabel limits = new JLabel("<html>Até 50 testes + 3 baselines; uma requisição por vez.<br>Exige Target scope do Burp. Redirects não são seguidos.<br>A sessão e os headers de autenticação originais são mantidos.</html>");
        limits.setBorder(BorderFactory.createEmptyBorder(8, 0, 8, 0)); settings.add(limits);
        JButton plan = new JButton("4. Gerar prévia"); settings.add(plan);
        preview = new JTextArea(12, 30); preview.setEditable(false); preview.setLineWrap(true); preview.setWrapStyleWord(true);
        addSetting("Prévia / avisos", new JScrollPane(preview));
        start = new JButton("5. Executar prévia"); start.setEnabled(false);
        stop = new JButton("Parar"); stop.setEnabled(false);
        export = new JButton("Exportar metadados JSON"); export.setEnabled(false);
        JButton clear = new JButton("Limpar requisição e resultados");
        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT));
        actions.add(start); actions.add(stop); actions.add(export); actions.add(clear);
        status = new JLabel("Aguardando requisição. Nenhum teste foi enviado.");
        runState = new JLabel(runSummary);
        JPanel messages = new JPanel(new GridLayout(0, 1)); messages.add(runState); messages.add(status);
        JPanel footer = new JPanel(new BorderLayout()); footer.add(actions); footer.add(messages, BorderLayout.SOUTH);
        panel.add(footer, BorderLayout.SOUTH);

        model = new DefaultTableModel(new String[]{"Teste", "HTTP", "Bytes", "ms", "Análise"}, 0) {
            @Override public boolean isCellEditable(int row, int column) { return false; }
        };
        table = new JTable(model); table.setAutoCreateRowSorter(true); table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        baselineRequestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        baselineResponseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        JTabbedPane evidence = new JTabbedPane();
        evidence.addTab("Request selecionada", requestEditor.uiComponent());
        evidence.addTab("Response selecionada", responseEditor.uiComponent());
        evidence.addTab("Request baseline", baselineRequestEditor.uiComponent());
        evidence.addTab("Response baseline", baselineResponseEditor.uiComponent());
        JSplitPane resultPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(table), evidence); resultPane.setResizeWeight(0.4);
        JScrollPane settingsScroll = new JScrollPane(settings); settingsScroll.setPreferredSize(new Dimension(420, 650));
        JSplitPane main = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, settingsScroll, resultPane); main.setResizeWeight(0.28);
        panel.add(main);
        target.addActionListener(e -> {
            Targets.Target field = (Targets.Target) target.getSelectedItem();
            if (field != null) meaning.setSelectedItem(Semantics.classify(field.name() + field.pointer(), field.value()));
            invalidatePlan();
        });
        meaning.addActionListener(e -> invalidatePlan()); validation.addActionListener(e -> invalidatePlan());
        allowWrites.addActionListener(e -> invalidatePlan()); interval.addChangeListener(e -> invalidatePlan());
        javax.swing.event.DocumentListener invalidate = new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { invalidatePlan(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { invalidatePlan(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { invalidatePlan(); }
        };
        alternatives.getDocument().addDocumentListener(invalidate); ignoredPaths.getDocument().addDocumentListener(invalidate);
        plan.addActionListener(e -> generate()); start.addActionListener(e -> execute());
        stop.addActionListener(e -> { stopping.set(true); stop.setEnabled(false); status.setText("Parando após a requisição em andamento (timeout de 30 s)…"); });
        export.addActionListener(e -> export());
        clear.addActionListener(e -> { if (running) { error("Pare e aguarde o fim da execução antes de limpar."); return; } reset(); });
        table.getSelectionModel().addListSelectionListener(e -> {
            if (e.getValueIsAdjusting() || table.getSelectedRow() < 0) return;
            Result result = results.get(table.convertRowIndexToModel(table.getSelectedRow()));
            requestEditor.setRequest(result.exchange().request()); responseEditor.setResponse(result.exchange().response());
            status.setText(result.conclusion() + (result.changes().isEmpty() ? "" : " · Diferenças: " + String.join(", ", result.changes())));
        });
        api.userInterface().applyThemeToComponent(panel);
    }
    private void addSetting(String label, JComponent component) {
        JPanel row = new JPanel(new BorderLayout(0, 4)); row.setBorder(BorderFactory.createEmptyBorder(5, 0, 5, 0));
        row.add(new JLabel(label), BorderLayout.NORTH); row.add(component); settings.add(row);
    }
    private void invalidatePlan() { prepared = null; if (start != null) start.setEnabled(false); }
    private void error(String message) { JOptionPane.showMessageDialog(panel, message, "Semantic V2", JOptionPane.INFORMATION_MESSAGE); }
    private void reset() {
        original = null; invalidatePlan(); target.removeAllItems(); results.clear(); model.setRowCount(0);
        alternatives.setText(""); ignoredPaths.setText(""); allowWrites.setSelected(false); preview.setText("");
        requestEditor.setRequest(null); responseEditor.setResponse(null); baselineRequestEditor.setRequest(null); baselineResponseEditor.setResponse(null);
        runSummary = "Nenhuma execução realizada.";
        runState.setText(runSummary);
        export.setEnabled(false); source.setText("Envie uma requisição pelo menu de contexto do Burp."); status.setText("Dados desta execução removidos da interface.");
    }
    private void load(HttpRequest request) {
        if (!SwingUtilities.isEventDispatchThread()) { SwingUtilities.invokeLater(() -> load(request)); return; }
        if (running) { error("Há uma execução em andamento. Pare e aguarde antes de importar outra requisição."); return; }
        try {
            if (request.toByteArray().length() > 1_000_000) throw new IllegalArgumentException("Requisição maior que 1 MB não suportada.");
            Targets.Discovery discovery = Targets.discover(request);
            reset(); original = request;
            for (Targets.Target field : discovery.fields()) target.addItem(field);
            // Avoid displaying credentials that may live in query strings.
            source.setText(request.method() + " · " + request.httpService().host() + " · " + discovery.fields().size() + " campos disponíveis");
            preview.setText(String.join("\n", discovery.notices()));
            baselineRequestEditor.setRequest(request);
            status.setText("Requisição recebida. Abra a aba Semantic V2, escolha o campo e gere a prévia.");
        } catch (RuntimeException e) { error(e.getMessage()); }
    }
    private boolean readMethod(String method) { return Set.of("GET", "HEAD", "OPTIONS").contains(method.toUpperCase(Locale.ROOT)); }
    private void generate() {
        if (running) return;
        invalidatePlan();
        try {
            if (original == null || target.getSelectedItem() == null) throw new IllegalArgumentException("Envie uma requisição e escolha um campo.");
            if (!original.isInScope()) throw new IllegalArgumentException("Inclua este endpoint em Target → Scope no Burp antes de gerar os testes.");
            if (!readMethod(original.method()) && !allowWrites.isSelected()) throw new IllegalArgumentException("A requisição usa " + original.method() + ". Habilite a opção de escrita se quiser repeti-la neste teste.");
            Targets.Target field = (Targets.Target) target.getSelectedItem();
            List<String> ignored = Arrays.stream(ignoredPaths.getText().split(",")).map(String::strip).filter(s -> !s.isEmpty()).toList();
            for (String pointer : ignored) if (!pointer.startsWith("/") || pointer.matches(".*~(?![01]).*")) throw new IllegalArgumentException("Use JSON Pointers válidos, como /timestamp, separados por vírgula.");
            List<Semantics.TestCase> tests = Semantics.plan((Semantics.Meaning) meaning.getSelectedItem(), field.value(), field.typed(), alternatives.getText(), validation.isSelected());
            List<HttpRequest> requests = new ArrayList<>();
            StringBuilder text = new StringBuilder("Campo: " + field + "\nOriginal: " + field.value() + "\n\n");
            int i = 0;
            for (Semantics.TestCase test : tests) {
                HttpRequest mutated = Targets.mutate(original, field, test.value());
                if (!mutated.isInScope()) throw new IllegalArgumentException("Uma mutação sai do Target scope: " + test.name() + ". Ajuste o campo/testes ou o escopo do endpoint.");
                requests.add(mutated); text.append(++i).append(". ").append(test.name()).append(" → ").append(test.value()).append('\n');
            }
            text.append("\nTotal máximo: ").append(tests.size() + 3).append(" envios (2 baselines iniciais + testes + 1 baseline final).\n");
            text.append("IDs alternativos mantêm a sessão original. Um 2xx exige conferência do proprietário e da política de acesso.\n");
            if (!readMethod(original.method())) text.append("A operação de escrita original será repetida nos baselines e em cada teste.\n");
            if (field.typed()) text.append("JSON será serializado novamente; formato/espaços podem mudar. Assinaturas do conteúdo não são recalculadas.\n");
            prepared = new Prepared(original, field, tests, List.copyOf(requests), ignored, (int) interval.getValue());
            preview.setText(text.toString()); preview.setCaretPosition(0); start.setEnabled(true);
            status.setText("Prévia pronta. Executar enviará as requisições listadas.");
        } catch (RuntimeException e) { error(e.getMessage()); }
    }
    private void enableSettings(Container root, boolean enabled) {
        for (Component component : root.getComponents()) { component.setEnabled(enabled); if (component instanceof Container child) enableSettings(child, enabled); }
    }
    private void execute() {
        Prepared run = prepared;
        if (run == null || running) return;
        running = true; stopping.set(false); start.setEnabled(false); stop.setEnabled(true); export.setEnabled(false);
        runSummary = "Execução em andamento; resultados parciais.";
        runState.setText(runSummary);
        enableSettings(settings, false); results.clear(); model.setRowCount(0);
        requestEditor.setRequest(null); responseEditor.setResponse(null); baselineResponseEditor.setResponse(null);
        status.setText("Executando baselines…");
        new SwingWorker<String, Result>() {
            @Override protected String doInBackground() throws Exception {
                RunEngine engine = new RunEngine(request -> api.http().sendRequest(request,
                    RequestOptions.requestOptions().withRedirectionMode(RedirectionMode.NEVER).withResponseTimeout(30_000)),
                    stopping, result -> publish(result), run.delay);
                return engine.run(run.original, run.tests, run.requests, run.ignored);
            }
            @Override protected void process(List<Result> chunks) {
                if (unloaded.get()) return;
                for (Result result : chunks) {
                    results.add(result); model.addRow(new Object[]{result.name(), result.status(), result.bytes(), result.milliseconds(), result.conclusion()});
                    if (results.size() == 1) { baselineRequestEditor.setRequest(result.exchange().request()); baselineResponseEditor.setResponse(result.exchange().response()); }
                }
                status.setText(results.size() + " respostas recebidas" + (stopping.get() ? " · parando…" : "…"));
            }
            @Override protected void done() {
                running = false;
                if (unloaded.get()) return;
                enableSettings(settings, true); stop.setEnabled(false); export.setEnabled(!results.isEmpty());
                invalidatePlan();
                try { runSummary = get(); }
                catch (Exception e) {
                    Throwable cause = e.getCause() == null ? e : e.getCause();
                    runSummary = stopping.get() ? "Execução parada. Resultados parciais disponíveis; sem validação final da referência." : "Execução interrompida: " + cause.getMessage();
                }
                status.setText(runSummary);
                runState.setText(runSummary);
            }
        }.execute();
    }
    private void export() {
        if (running || results.isEmpty()) return;
        JFileChooser chooser = new JFileChooser(); chooser.setSelectedFile(new java.io.File("semantic-v2-resultados.json"));
        if (chooser.showSaveDialog(panel) != JFileChooser.APPROVE_OPTION) return;
        if (chooser.getSelectedFile().exists() && JOptionPane.showConfirmDialog(panel, "Substituir o arquivo selecionado?", "Exportação", JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION) return;
        try {
            List<Map<String, Object>> rows = new ArrayList<>();
            int index = 0;
            for (Result result : results) {
                // Raw traffic and tested values stay in Burp; the export only contains comparison metadata.
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("index", index++); row.put("test", result.name().split(" → ", 2)[0]);
                row.put("http_status", result.status()); row.put("response_bytes", result.bytes()); row.put("elapsed_ms", result.milliseconds());
                row.put("analysis", result.conclusion()); row.put("changed_json_pointers", result.changes()); row.put("response_body_sha256", result.hash());
                rows.add(row);
            }
            Map<String, Object> report = new LinkedHashMap<>();
            report.put("tool", "Semantic Intruder V2 0.2.0"); report.put("exported_at", Instant.now().toString());
            report.put("notice", "Triagem, não confirmação de vulnerabilidade. Corpos, headers, URLs e valores testados não exportados.");
            report.put("run_status", runSummary); report.put("results", rows);
            Files.writeString(chooser.getSelectedFile().toPath(), Semantics.JSON.toJson(report), StandardCharsets.UTF_8);
            status.setText("Metadados exportados para " + chooser.getSelectedFile().getName());
        } catch (Exception e) { error("Falha na exportação: " + e.getMessage()); }
    }
}
