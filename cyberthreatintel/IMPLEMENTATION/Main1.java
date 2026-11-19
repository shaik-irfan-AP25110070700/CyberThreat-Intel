import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ExecutionException;
import javax.swing.filechooser.FileNameExtensionFilter;

// Core data structure wrapper for incoming threat logs
class IncidentReportPayload {
    private final String content;
    private final String origin;

    public IncidentReportPayload(String content) {
        this(content, "Manual Input");
    }

    public IncidentReportPayload(String content, String origin) {
        this.content = content;
        this.origin = origin;
    }

    public String getContent() {
        return content;
    }

    public String getOrigin() {
        return origin;
    }
}

// Tokenizer & String cleaning utility implementation
class TokenizerEngine {
    private static final Set<String> FILTERED_WORDS = new HashSet<>(
        Arrays.asList(
            "the", "is", "a", "an", "and", "or", "of", "to",
            "in", "on", "for", "with", "by", "was", "were",
            "are", "be", "has", "have", "had", "this", "that",
            "from", "it", "as", "at", "their", "they"
        )
    );

    public String[] parseTokens(String rawText) {
        if (rawText == null || rawText.trim().isEmpty()) {
            return new String[0];
        }

        String normalized = rawText.toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9\\s]", " ")
                .trim();

        if (normalized.isEmpty()) {
            return new String[0];
        }

        return Arrays.stream(normalized.split("\\s+"))
                .filter(token -> !FILTERED_WORDS.contains(token))
                .toArray(String[]::new);
    }
}

// Statistical model matching Bayesian classification behavior
class BayesianThreatClassifier extends TokenizerEngine {
    private final Map<String, Map<String, Integer>> categoryFrequencies;
    private final Map<String, Integer> categoryTokenSums;
    private final Map<String, Integer> categoryDocCounts;
    private final Set<String> globalVocabulary;
    private int corpusSize;

    public BayesianThreatClassifier() {
        categoryFrequencies = new HashMap<>();
        categoryTokenSums = new HashMap<>();
        categoryDocCounts = new HashMap<>();
        globalVocabulary = new HashSet<>();
        corpusSize = 0;

        feedTrainingSample("Ransomware", "ransomware encrypt encrypted encryption files ransom payment victim locked restore decrypt extortion");
        feedTrainingSample("Phishing", "phishing email emails password credentials fraudulent malicious link fake login impersonation scam");
        feedTrainingSample("Malware", "malware trojan virus spyware infection malicious software payload executable backdoor");
        feedTrainingSample("Data Breach", "data breach stolen leaked database information exposed records exfiltration confidential");
        feedTrainingSample("Denial of Service", "denial service ddos dos traffic server network overload requests unavailable flooding");
        feedTrainingSample("Credential Theft", "credential theft stolen username password authentication account login keylogger identity");
        feedTrainingSample("Ransomware", "attackers encrypted documents demanded cryptocurrency payment files inaccessible");
        feedTrainingSample("Phishing", "fraudulent message directed employees to fake website steal credentials");
    }

    private void feedTrainingSample(String label, String corpusText) {
        String[] parsedTokens = parseTokens(corpusText);

        categoryFrequencies.putIfAbsent(label, new HashMap<>());
        categoryDocCounts.put(label, categoryDocCounts.getOrDefault(label, 0) + 1);
        corpusSize++;

        Map<String, Integer> termMap = categoryFrequencies.get(label);

        for (String token : parsedTokens) {
            termMap.put(token, termMap.getOrDefault(token, 0) + 1);
            categoryTokenSums.put(label, categoryTokenSums.getOrDefault(label, 0) + 1);
            globalVocabulary.add(token);
        }
    }

    public String predictLabel(String text) throws Exception {
        String[] parsedTokens = parseTokens(text);

        if (parsedTokens.length == 0) {
            throw new Exception("Please enter a valid cyber threat report.");
        }

        String optimalCategory = "Unknown";
        double peakLogProbability = Double.NEGATIVE_INFINITY;

        for (String label : categoryFrequencies.keySet()) {
            double priorLog = Math.log((double) categoryDocCounts.get(label) / corpusSize);
            double runningScore = priorLog;

            Map<String, Integer> termMap = categoryFrequencies.get(label);
            int totalCategoryTokens = categoryTokenSums.get(label);

            for (String token : parsedTokens) {
                int frequency = termMap.getOrDefault(token, 0);
                double smoothedProbability = (frequency + 1.0) / (totalCategoryTokens + globalVocabulary.size());
                runningScore += Math.log(smoothedProbability);
            }

            if (runningScore > peakLogProbability) {
                peakLogProbability = runningScore;
                optimalCategory = label;
            }
        }

        return optimalCategory;
    }

    public String[] extractTopKeywords(String text) {
        String[] parsedTokens = parseTokens(text);
        LinkedHashSet<String> keywordSet = new LinkedHashSet<>();

        for (String token : parsedTokens) {
            if (globalVocabulary.contains(token)) {
                keywordSet.add(token);
            }
            if (keywordSet.size() == 8) {
                break;
            }
        }

        if (keywordSet.isEmpty()) {
            return new String[]{"No known keywords found"};
        }

        return keywordSet.toArray(new String[0]);
    }
}

// Data holder representing the completed analysis output
class AnalysisOutcome {
    private final String threatCategory;
    private final String[] extractedKeywords;
    private final String timestampStr;
    private final String sourceChannel;

    public AnalysisOutcome(String threatCategory, String[] extractedKeywords, String sourceChannel) {
        this.threatCategory = threatCategory;
        this.extractedKeywords = extractedKeywords;
        this.sourceChannel = sourceChannel;
        this.timestampStr = LocalDateTime.now().format(DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss"));
    }

    public String getThreatCategory() {
        return threatCategory;
    }

    public String[] getExtractedKeywords() {
        return extractedKeywords;
    }

    public String getTimestampStr() {
        return timestampStr;
    }

    public String getSourceChannel() {
        return sourceChannel;
    }
}

// Pipeline coordinator bridging classifier and payload data
class ThreatPipelineService extends BayesianThreatClassifier {
    public AnalysisOutcome evaluate(IncidentReportPayload payload) throws Exception {
        if (payload == null) {
            throw new Exception("Report cannot be null.");
        }
        return evaluate(payload.getContent(), payload.getOrigin());
    }

    public AnalysisOutcome evaluate(String text, String origin) throws Exception {
        String categoryResult = predictLabel(text);
        String[] keywordResult = extractTopKeywords(text);
        return new AnalysisOutcome(categoryResult, keywordResult, origin);
    }
}

// Audit record log controller and file export utility
class LogArchiveController {
    private final DefaultTableModel tableModelBinding;

    public LogArchiveController(DefaultTableModel tableModelBinding) {
        this.tableModelBinding = tableModelBinding;
    }

    public void appendRecord(AnalysisOutcome outcome) {
        tableModelBinding.addRow(new Object[]{
            outcome.getTimestampStr(),
            outcome.getSourceChannel(),
            outcome.getThreatCategory(),
            String.join(", ", outcome.getExtractedKeywords())
        });
    }

    public void exportLogsToDisk(Component parentFrame) {
        JFileChooser saveDialogue = new JFileChooser();
        saveDialogue.setSelectedFile(new File("classification_history.csv"));

        if (saveDialogue.showSaveDialog(parentFrame) != JFileChooser.APPROVE_OPTION) {
            return;
        }

        File targetFile = saveDialogue.getSelectedFile();

        try (PrintWriter fileWriter = new PrintWriter(new FileWriter(targetFile))) {
            fileWriter.println("Date and Time,Source,Category,Keywords");

            for (int index = 0; index < tableModelBinding.getRowCount(); index++) {
                fileWriter.println(
                    surroundQuotes(tableModelBinding.getValueAt(index, 0)) + "," +
                    surroundQuotes(tableModelBinding.getValueAt(index, 1)) + "," +
                    surroundQuotes(tableModelBinding.getValueAt(index, 2)) + "," +
                    surroundQuotes(tableModelBinding.getValueAt(index, 3))
                );
            }

            JOptionPane.showMessageDialog(parentFrame, "History exported successfully.");

        } catch (IOException errorEx) {
            JOptionPane.showMessageDialog(
                parentFrame,
                "Unable to export history: " + errorEx.getMessage(),
                "File Error",
                JOptionPane.ERROR_MESSAGE
            );
        }
    }

    private String surroundQuotes(Object targetValue) {
        String stringValue = String.valueOf(targetValue);
        return "\"" + stringValue.replace("\"", "\"\"") + "\"";
    }
}

// Main Window Graphical Dashboard Interface
class CyberThreatDashboard extends JFrame {

    private final JTextArea inputTextArea;
    private final JTextArea outputTextArea;
    private final JLabel systemStatusLabel;
    private final JButton runAnalysisButton;

    private final ThreatPipelineService pipelineService;
    private final LogArchiveController archiveController;
    private final DefaultTableModel sessionTableModel;

    private String activeSourceContext = "Manual Input";

    public CyberThreatDashboard() {
        pipelineService = new ThreatPipelineService();

        setTitle("CyberThreat Intel | Threat Report Classifier");
        setSize(1050, 720);
        setMinimumSize(new Dimension(850, 600));
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        Color themeBackground = new Color(19, 27, 43);
        Color themePanel = new Color(30, 41, 59);
        Color themeAccent = new Color(56, 189, 248);
        Color themeForeground = new Color(235, 241, 250);

        JPanel mainRoot = new JPanel(new BorderLayout(12, 12));
        mainRoot.setBackground(themeBackground);
        mainRoot.setBorder(BorderFactory.createEmptyBorder(18, 18, 18, 18));

        JLabel titleHeader = new JLabel("CyberThreat Intel", SwingConstants.CENTER);
        titleHeader.setForeground(themeAccent);
        titleHeader.setFont(new Font("Arial", Font.BOLD, 28));

        JLabel subTitleHeader = new JLabel(
            "NLP-Based Classification of Cyber Threat Intelligence Reports",
            SwingConstants.CENTER
        );
        subTitleHeader.setForeground(themeForeground);
        subTitleHeader.setFont(new Font("Arial", Font.PLAIN, 13));

        JPanel topHeaderWrapper = new JPanel(new GridLayout(2, 1, 4, 4));
        topHeaderWrapper.setBackground(themeBackground);
        topHeaderWrapper.add(titleHeader);
        topHeaderWrapper.add(subTitleHeader);

        mainRoot.add(topHeaderWrapper, BorderLayout.NORTH);

        inputTextArea = new JTextArea(10, 50);
        inputTextArea.setLineWrap(true);
        inputTextArea.setWrapStyleWord(true);
        inputTextArea.setFont(new Font("Consolas", Font.PLAIN, 14));
        inputTextArea.setBackground(themePanel);
        inputTextArea.setForeground(themeForeground);
        inputTextArea.setCaretColor(themeAccent);
        inputTextArea.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JScrollPane inputScrollPane = new JScrollPane(inputTextArea);
        inputScrollPane.setBorder(BorderFactory.createTitledBorder("Threat Report Input"));

        outputTextArea = new JTextArea(5, 50);
        outputTextArea.setEditable(false);
        outputTextArea.setLineWrap(true);
        outputTextArea.setWrapStyleWord(true);
        outputTextArea.setFont(new Font("Consolas", Font.PLAIN, 14));
        outputTextArea.setBackground(themePanel);
        outputTextArea.setForeground(themeForeground);
        outputTextArea.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JScrollPane outputScrollPane = new JScrollPane(outputTextArea);
        outputScrollPane.setBorder(BorderFactory.createTitledBorder("Analysis Results"));

        JButton fileOpenButton = new JButton("Load Report");
        runAnalysisButton = new JButton("Analyze Report");
        JButton resetFieldsButton = new JButton("Clear");
        JButton exportReportButton = new JButton("Export History");

        fileOpenButton.setToolTipText("Open a text or CSV report file");
        runAnalysisButton.setToolTipText("Classify the report");
        resetFieldsButton.setToolTipText("Clear the input and results");

        JPanel commandBar = new JPanel(new FlowLayout(FlowLayout.CENTER, 12, 10));
        commandBar.setBackground(themeBackground);
        commandBar.add(fileOpenButton);
        commandBar.add(runAnalysisButton);
        commandBar.add(resetFieldsButton);
        commandBar.add(exportReportButton);

        JPanel workstationPanel = new JPanel(new BorderLayout(10, 10));
        workstationPanel.setBackground(themeBackground);
        workstationPanel.add(inputScrollPane, BorderLayout.CENTER);
        workstationPanel.add(commandBar, BorderLayout.SOUTH);

        sessionTableModel = new DefaultTableModel(
            new String[]{"Date and Time", "Source", "Category", "Keywords"}, 0
        ) {
            @Override
            public boolean isCellEditable(int rowIndex, int columnIndex) {
                return false;
            }
        };

        JTable historyAuditTable = new JTable(sessionTableModel);
        historyAuditTable.setRowHeight(24);
        historyAuditTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);

        JScrollPane historyScrollPane = new JScrollPane(historyAuditTable);
        historyScrollPane.setBorder(BorderFactory.createTitledBorder("Session History"));

        archiveController = new LogArchiveController(sessionTableModel);

        JTabbedPane navigationTabs = new JTabbedPane();
        navigationTabs.addTab("Analyze", workstationPanel);
        navigationTabs.addTab("History", historyScrollPane);

        systemStatusLabel = new JLabel("Ready");
        systemStatusLabel.setForeground(themeAccent);

        JPanel lowerStackedPanel = new JPanel(new BorderLayout(10, 10));
        lowerStackedPanel.setBackground(themeBackground);
        lowerStackedPanel.add(outputScrollPane, BorderLayout.CENTER);
        lowerStackedPanel.add(systemStatusLabel, BorderLayout.SOUTH);

        JPanel centralCorePanel = new JPanel(new BorderLayout(10, 10));
        centralCorePanel.setBackground(themeBackground);
        centralCorePanel.add(navigationTabs, BorderLayout.CENTER);
        centralCorePanel.add(lowerStackedPanel, BorderLayout.SOUTH);

        mainRoot.add(centralCorePanel, BorderLayout.CENTER);
        add(mainRoot);

        fileOpenButton.addActionListener(e -> invokeFileLoaderDialogue());
        runAnalysisButton.addActionListener(e -> triggerThreatEvaluationTask());
        resetFieldsButton.addActionListener(e -> {
            inputTextArea.setText("");
            outputTextArea.setText("");
            activeSourceContext = "Manual Input";
            systemStatusLabel.setText("Ready");
        });
        exportReportButton.addActionListener(e -> archiveController.exportLogsToDisk(this));
    }

    private void invokeFileLoaderDialogue() {
        JFileChooser fileDialogue = new JFileChooser();
        fileDialogue.setDialogTitle("Select Cyber Threat Report");
        fileDialogue.setFileFilter(new FileNameExtensionFilter(
            "Text and CSV Reports (*.txt, *.csv)",
            "txt",
            "csv"
        ));

        int dialogueSelection = fileDialogue.showOpenDialog(this);

        if (dialogueSelection == JFileChooser.APPROVE_OPTION) {
            File selectedFile = fileDialogue.getSelectedFile();
            String lowerFileName = selectedFile.getName().toLowerCase(Locale.ROOT);

            if (!lowerFileName.endsWith(".txt") && !lowerFileName.endsWith(".csv")) {
                JOptionPane.showMessageDialog(
                    this, "Please select a .txt or .csv file.",
                    "Invalid File", JOptionPane.WARNING_MESSAGE
                );
                return;
            }

            try (BufferedReader bufferStream = new BufferedReader(
                    new InputStreamReader(new FileInputStream(selectedFile), StandardCharsets.UTF_8))) {
                StringBuilder textAccumulator = new StringBuilder();
                String dataLine;

                while ((dataLine = bufferStream.readLine()) != null) {
                    textAccumulator.append(dataLine).append("\n");
                }

                String reportText = textAccumulator.toString();
                if (lowerFileName.endsWith(".csv")) {
                    reportText = parseCsvReport(reportText);
                }

                inputTextArea.setText(reportText);
                activeSourceContext = selectedFile.getName();
                systemStatusLabel.setText("Report loaded successfully.");

            } catch (IOException ioError) {
                JOptionPane.showMessageDialog(
                    this, "Unable to read report: " + ioError.getMessage(),
                    "File Error", JOptionPane.ERROR_MESSAGE
                );
            }
        }
    }

    private String parseCsvReport(String csvText) {
        if (csvText == null || csvText.isEmpty()) {
            return "";
        }

        StringBuilder parsedText = new StringBuilder();
        StringBuilder field = new StringBuilder();
        boolean inQuotes = false;

        for (int index = 0; index < csvText.length(); index++) {
            char current = csvText.charAt(index);

            if (current == '"') {
                if (inQuotes && index + 1 < csvText.length()
                        && csvText.charAt(index + 1) == '"') {
                    field.append('"');
                    index++;
                } else {
                    inQuotes = !inQuotes;
                }
            } else if (current == ',' && !inQuotes) {
                appendCsvField(parsedText, field);
            } else if ((current == '\n' || current == '\r') && !inQuotes) {
                appendCsvField(parsedText, field);
                if (current == '\r' && index + 1 < csvText.length()
                        && csvText.charAt(index + 1) == '\n') {
                    index++;
                }
                if (parsedText.length() > 0
                        && parsedText.charAt(parsedText.length() - 1) != '\n') {
                    parsedText.append('\n');
                }
            } else {
                field.append(current);
            }
        }

        appendCsvField(parsedText, field);
        return parsedText.toString().replace("\uFEFF", "").trim();
    }

    private void appendCsvField(StringBuilder parsedText, StringBuilder field) {
        String value = field.toString().trim();
        if (!value.isEmpty()) {
            if (parsedText.length() > 0
                    && parsedText.charAt(parsedText.length() - 1) != '\n'
                    && parsedText.charAt(parsedText.length() - 1) != ' ') {
                parsedText.append(' ');
            }
            parsedText.append(value);
        }
        field.setLength(0);
    }

    private void triggerThreatEvaluationTask() {
        String targetReportText = inputTextArea.getText();
        String originReference = activeSourceContext;

        runAnalysisButton.setEnabled(false);
        outputTextArea.setText("Analyzing report...");
        systemStatusLabel.setText("Processing in background...");

        SwingWorker<AnalysisOutcome, Void> backgroundWorker = new SwingWorker<>() {
            @Override
            protected AnalysisOutcome doInBackground() throws Exception {
                IncidentReportPayload reportPayload = new IncidentReportPayload(targetReportText, originReference);
                return pipelineService.evaluate(reportPayload);
            }

            @Override
            protected void done() {
                try {
                    AnalysisOutcome outcomeResult = get();

                    outputTextArea.setText(
                        "Predicted Threat Category: " + outcomeResult.getThreatCategory()
                        + "\n\nImportant Keywords: " + String.join(", ", outcomeResult.getExtractedKeywords())
                        + "\n\nSource: " + outcomeResult.getSourceChannel()
                        + "\nAnalyzed At: " + outcomeResult.getTimestampStr()
                        + "\n\nNote: Prototype prediction; not a validated security assessment."
                    );

                    archiveController.appendRecord(outcomeResult);
                    systemStatusLabel.setText("Classification completed.");

                } catch (InterruptedException interruptedEx) {
                    Thread.currentThread().interrupt();
                    systemStatusLabel.setText("Analysis interrupted.");

                } catch (ExecutionException executionEx) {
                    Throwable rootCause = executionEx.getCause();
                    String errorMsg = rootCause == null ? "Unable to analyze the report." : rootCause.getMessage();
                    outputTextArea.setText(errorMsg);
                    systemStatusLabel.setText("Classification failed.");

                } finally {
                    runAnalysisButton.setEnabled(true);
                }
            }
        };

        backgroundWorker.execute();
    }
}

public class Main1 {
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            try {
                UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            } catch (Exception ex) {
                System.out.println("Using default interface appearance.");
            }

            CyberThreatDashboard dashboardInstance = new CyberThreatDashboard();
            dashboardInstance.setVisible(true);
        });
    }
}