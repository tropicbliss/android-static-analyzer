package org.example;

import soot.*;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;
import soot.jimple.toolkits.callgraph.CHATransformer;
import soot.options.Options;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.graph.UnitGraph;
import soot.util.dot.DotGraph;

import java.io.*;
import java.util.*;

public class Main {
    private static final String OUTPUT_DIR = "output";
    private static final Map<String, Set<String>> permissionToApiMap = new HashMap<>();
    /**
     * Map of API name to list of all calls
     * Each call contains the calling method and the position in the code
     */
    private static final Map<String, List<ApiCall>> apiCalls = new HashMap<>();

    /**
     * Represents a single call to an API
     */
    private static class ApiCall {
        String callerMethod;
        Unit position;

        ApiCall(String callerMethod, Unit position) {
            this.callerMethod = callerMethod;
            this.position = position;
        }

        @Override
        public boolean equals(Object obj) {
            if (!(obj instanceof ApiCall other)) return false;
            return this.callerMethod.equals(other.callerMethod) && this.position.equals(other.position);
        }

        @Override
        public int hashCode() {
            return callerMethod.hashCode() * 31 + (position != null ? position.hashCode() : 0);
        }
    }

    public static void main(String[] args) {
        try {
            if (args.length != 2) {
                System.out.println("Usage: java AndroidStaticAnalyzer <apk-file> <sensitive-apis-csv>");
                System.exit(1);
            }

            String apkPath = args[0];
            String csvPath = args[1];

            // Validate input files
            File apkFile = new File(apkPath);
            File csvFile = new File(csvPath);

            if (!apkFile.exists() || !apkFile.isFile()) {
                System.err.println("Error: APK file does not exist or is not a file: " + apkPath);
                System.exit(1);
            }

            if (!csvFile.exists() || !csvFile.isFile()) {
                System.err.println("Error: CSV file does not exist or is not a file: " + csvPath);
                System.exit(1);
            }

            // Create output directory
            File outputDir = new File(OUTPUT_DIR);
            if (!outputDir.exists()) {
                outputDir.mkdirs();
            }

            System.out.println("Starting analysis of APK: " + apkPath);

            // Load sensitive APIs from CSV
            System.out.println("Loading sensitive APIs from: " + csvPath);
            loadSensitiveApis(csvPath);

            // Configure Soot
            System.out.println("Configuring Soot...");
            configureSoot(apkPath);

            // Analyze the APK
            System.out.println("Analyzing the APK...");
            analyzeApk();

            // Output results
            System.out.println("Generating output files...");
            outputSensitiveApiUsage();

            System.out.println("Analysis completed successfully. Check the output directory for results.");
        } catch (Exception e) {
            System.err.println("Fatal error during analysis: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static void loadSensitiveApis(String csvPath) {
        try {
            // First try to parse with standard CSV reader
            try (BufferedReader reader = new BufferedReader(new FileReader(csvPath))) {
                String line;
                boolean firstLine = true;
                while ((line = reader.readLine()) != null) {
                    // Skip header line if it looks like a header
                    if (firstLine && line.contains("CallerClass") && line.contains("CallerMethod")) {
                        firstLine = false;
                        continue;
                    }

                    firstLine = false;
                    String[] parts = line.split(",");
                    if (parts.length >= 3) {
                        String callerClass = parts[0].trim();
                        String callerMethod = parts[1].trim();
                        String permission = parts[2].trim();

                        // Normalize format for class name (replace / with .)
                        callerClass = callerClass.replace('/', '.');

                        String api = callerClass + "." + callerMethod;
                        permissionToApiMap.computeIfAbsent(permission, _ -> new HashSet<>()).add(api);
                    }
                }
            }

            // Count total APIs
            int totalApis = 0;
            for (Set<String> apis : permissionToApiMap.values()) {
                totalApis += apis.size();
            }

            System.out.println("Loaded " + permissionToApiMap.size() + " permissions with " + totalApis + " sensitive APIs.");

            // Print a few examples for verification
            int count = 0;
            for (Map.Entry<String, Set<String>> entry : permissionToApiMap.entrySet()) {
                if (count++ > 3) break;
                System.out.println("Permission: " + entry.getKey() + " has " + entry.getValue().size() + " APIs");
            }

        } catch (IOException e) {
            System.err.println("Error reading CSV file: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void configureSoot(String apkPath) {
        // Reset Soot
        G.reset();

        // Set up Soot options
        Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_android_jars("platforms"); // Path to Android platforms
        Options.v().set_process_dir(Collections.singletonList(apkPath));
        Options.v().set_whole_program(true);
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_output_format(Options.output_format_jimple);
        Options.v().set_output_dir(OUTPUT_DIR);
        Options.v().set_no_bodies_for_excluded(true);
        Options.v().set_exclude(getExcludeList());
        Options.v().set_include(getIncludeList());

        // Enable call graph
        Options.v().setPhaseOption("cg", "enabled:true");
        // Enable SPARK call graph construction
        Options.v().setPhaseOption("cg.spark", "enabled:true");
        Options.v().setPhaseOption("cg.spark", "verbose:true");

        // Load necessary classes for analysis
        Scene.v().loadNecessaryClasses();
    }

    private static List<String> getExcludeList() {
        return Arrays.asList(
                "java.*", "javax.*", "sun.*", "android.*", "androidx.*",
                "org.apache.*", "org.json.*", "org.xml.*", "org.w3c.*"
        );
    }

    private static List<String> getIncludeList() {
        // Include app packages only
        return Collections.singletonList("*");
    }

    private static void analyzeApk() {
        try {
            // Try to build call graph first
            try {
                System.out.println("Building call graph...");
                PackManager.v().getPack("wjtp").add(new Transform("wjtp.callgraph", new SceneTransformer() {
                    @Override
                    protected void internalTransform(String phaseName, Map<String, String> options) {
                        CHATransformer.v().transform();
                        System.out.println("Call graph built successfully.");
                    }
                }));

                // Run the packs
                PackManager.v().runPacks();

                // Verify call graph was created
                if (Scene.v().hasCallGraph()) {
                    System.out.println("Call graph verification successful.");
                } else {
                    System.out.println("Call graph not available, falling back to direct method analysis.");
                }
            } catch (Exception e) {
                System.out.println("Call graph construction failed: " + e.getMessage());
                System.out.println("Falling back to direct method analysis...");
            }

            // Always process application classes directly, even if call graph fails
            fallbackAnalysis();

        } catch (Exception e) {
            System.err.println("Error during APK analysis: " + e.getMessage());
            e.printStackTrace();
            // Try fallback analysis even if primary analysis fails
            System.out.println("Attempting fallback analysis...");
            try {
                fallbackAnalysis();
            } catch (Exception e2) {
                System.err.println("Fallback analysis also failed: " + e2.getMessage());
            }
        }
    }

    private static void fallbackAnalysis() {
        System.out.println("Processing application classes...");
        int classCount = 0;
        int methodCount = 0;
        int analyzedCount = 0;

        for (SootClass sootClass : Scene.v().getApplicationClasses()) {
            // Skip if it's a phantom class
            if (sootClass.isPhantom()) continue;
            classCount++;

            for (SootMethod method : sootClass.getMethods()) {
                methodCount++;

                // Skip if the method doesn't have a body
                if (!method.hasActiveBody()) {
                    try {
                        method.retrieveActiveBody();
                    } catch (Exception e) {
                        // Skip methods that can't retrieve a body
                        continue;
                    }
                }

                if (!method.hasActiveBody()) continue;
                analyzedCount++;

                // Generate and store the control flow graph
                generateCFG(method);

                // Analyze method body for sensitive API calls
                analyzeMethod(method);
            }
        }

        System.out.println("Processed " + classCount + " classes, " + methodCount +
                " methods, analyzed " + analyzedCount + " method bodies.");
    }

    private static void generateCFG(SootMethod method) {
        try {
            Body body = method.getActiveBody();

            // Create CFG
            UnitGraph cfg = new BriefUnitGraph(body);

            // Create a dot file with sanitized method name
            String className = method.getDeclaringClass().getShortName();
            String methodName = sanitizeMethodName(method.getName());
            String fileName = String.format("%s_%s.dot", className, methodName);

            // Create a proper file path with correct separator
            File dotFile = new File(OUTPUT_DIR, fileName);

            DotGraph dot = new DotGraph(fileName);

            // Add nodes and edges
            for (Unit unit : cfg.getBody().getUnits()) {
                String unitStr = unit.toString().replace("\"", "\\\"");
                dot.drawNode(unitStr);

                // Add edges
                for (Unit succ : cfg.getSuccsOf(unit)) {
                    String succStr = succ.toString().replace("\"", "\\\"");
                    dot.drawEdge(unitStr, succStr);
                }
            }

            // Save dot file using absolute path instead of Paths
            dot.plot(dotFile.getAbsolutePath());
        } catch (Exception e) {
            System.err.println("Error generating CFG for method " + method.getSignature() + ": " + e.getMessage());
        }
    }

    /**
     * Sanitizes method names to be used in filenames
     *
     * @param methodName The original method name
     * @return A sanitized version safe for filenames
     */
    private static String sanitizeMethodName(String methodName) {
        // Replace special characters that are not allowed in filenames
        String sanitized = methodName;

        // Special handling for init methods
        if (sanitized.equals("<init>")) {
            return "constructor";
        } else if (sanitized.equals("<clinit>")) {
            return "static_initializer";
        }

        // Replace other invalid characters
        sanitized = sanitized.replace('<', '_')
                .replace('>', '_')
                .replace(':', '_')
                .replace('\"', '_')
                .replace('/', '_')
                .replace('\\', '_')
                .replace('|', '_')
                .replace('?', '_')
                .replace('*', '_');

        return sanitized;
    }

    private static void analyzeMethod(SootMethod method) {
        try {
            Body body = method.getActiveBody();

            // Get method identifier with parentheses to indicate it's a method
            String methodId = method.getDeclaringClass().getName() + "." + method.getName() + "()";

            // Examine each statement
            for (Unit unit : body.getUnits()) {
                if (unit instanceof Stmt stmt) {

                    // Check if it's a call statement
                    if (stmt.containsInvokeExpr()) {
                        try {
                            InvokeExpr invokeExpr = stmt.getInvokeExpr();
                            SootMethod calledMethod = invokeExpr.getMethod();
                            String calledMethodSig = calledMethod.getDeclaringClass().getName() + "." + calledMethod.getName();

                            // Check if it's a sensitive API call
                            boolean isSensitiveApi = false;
                            for (Set<String> apis : permissionToApiMap.values()) {
                                if (apis.contains(calledMethodSig)) {
                                    isSensitiveApi = true;
                                    break;
                                }
                            }

                            if (isSensitiveApi) {
                                // Update call list with this specific call instance
                                String apiName = calledMethod.getName();
                                ApiCall call = new ApiCall(methodId, unit);

                                apiCalls.computeIfAbsent(apiName, _ -> new ArrayList<>()).add(call);
                            }
                        } catch (Exception e) {
                            // Skip this invoke expression if it causes an error
                            System.err.println("Error analyzing method call in " + methodId + ": " + e.getMessage());
                        }
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Error analyzing method " + method.getSignature() + ": " + e.getMessage());
        }
    }

    private static void outputSensitiveApiUsage() {
        try {
            File outputFile = new File(OUTPUT_DIR, "sensitive_api_usage.txt");

            if (apiCalls.isEmpty()) {
                // If no sensitive APIs were found, write a message to the file
                try (PrintWriter writer = new PrintWriter(new FileWriter(outputFile))) {
                    writer.println("No sensitive API calls detected in the application.");
                }
                System.out.println("No sensitive API calls were detected in the application.");
                return;
            }

            // Write sensitive API usage to file
            try (PrintWriter writer = new PrintWriter(new FileWriter(outputFile))) {
                int totalApiCalls = 0;

                for (String api : apiCalls.keySet()) {
                    List<ApiCall> calls = apiCalls.get(api);
                    int frequency = calls.size();
                    totalApiCalls += frequency;

                    StringBuilder sb = new StringBuilder();
                    sb.append(api).append(":").append(frequency).append(":");

                    // List each call instance separately
                    boolean first = true;
                    for (ApiCall call : calls) {
                        if (!first) sb.append(",");
                        sb.append(call.callerMethod);
                        first = false;
                    }

                    writer.println(sb);
                }

                System.out.println("Found " + apiCalls.size() + " unique sensitive APIs with a total of " +
                        totalApiCalls + " calls. Results written to " + outputFile.getPath());
            }
        } catch (IOException e) {
            System.err.println("Error writing output file: " + e.getMessage());
        }
    }
}