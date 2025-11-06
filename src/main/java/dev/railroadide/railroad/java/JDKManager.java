package dev.railroadide.railroad.java;

import dev.railroadide.core.utility.OperatingSystem;
import dev.railroadide.railroad.Railroad;
import dev.railroadide.railroad.settings.Settings;
import dev.railroadide.railroad.utility.JavaVersion;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JDKManager {
    private static final List<String> WIN_JDK_PATHS = List.of(
        "{drive}:\\Program Files\\Java",
        "{drive}:\\Program Files (x86)\\Java",
        "{drive}:\\Program Files\\Eclipse Adoptium",
        "{drive}:\\Program Files (x86)\\Eclipse Adoptium",
        "{drive}:\\Program Files\\Azul",
        "{drive}:\\Program Files (x86)\\Azul",
        "{drive}:\\Program Files\\Zulu",
        "{drive}:\\Program Files (x86)\\Zulu",
        "{drive}:\\Program Files\\Amazon Corretto",
        "{drive}:\\Program Files (x86)\\Amazon Corretto",
        "{drive}:\\Program Files\\BellSoft",
        "{drive}:\\Program Files\\GraalVM"
    );
    private static final List<String> MAC_JDK_PATHS = List.of(
        "/Library/Java/JavaVirtualMachines"
    );
    private static final List<String> LINUX_JDK_PATHS = List.of(
        "/usr/lib/jvm",
        "/usr/java",
        "/opt/java",
        "/opt/jdk"
    );
    private static final String JAVA_EXECUTABLE = javaExecutableName();
    private static final Pattern JAVA_VERSION_PATTERN =
        Pattern.compile("^(\\d+)(?:\\.(\\d+))?(?:\\.\\d+)?(?:_\\d+)?$");

    private static final List<JDK> JDKS = new CopyOnWriteArrayList<>();

    public static List<JDK> getAvailableJDKs() {
        return Collections.unmodifiableList(JDKS);
    }

    public static void refreshJDKs() {
        JDKS.clear();
        JDKS.addAll(discoverJDKs());

        for (JDK jdk : JDKS) {
            Railroad.LOGGER.info("Detected JDK: {} (brand: {}, version: {}, path: {})",
                jdk.name(), jdk.brand(), jdk.version(), jdk.path());
        }
    }

    public static List<JDK> getJDKsInVersionRange(JavaVersion minVersion, JavaVersion maxVersion) {
        List<JDK> filtered = new ArrayList<>();
        for (JDK jdk : JDKS) {
            if ((minVersion == null || jdk.version().compareTo(minVersion) >= 0) &&
                (maxVersion == null || jdk.version().compareTo(maxVersion) <= 0)) {
                filtered.add(jdk);
            }
        }

        return filtered;
    }

    private static List<JDK> discoverJDKs() {
        // Location 1: JAVA_HOME and JDK_HOME environment variable
        List<JDK> jdks = new ArrayList<>();
        List<Path> excludedPaths = normalizePaths(Settings.EXCLUDED_JDK_SCAN_PATHS.getOrDefaultValue());
        List<Path> manualJdkPaths = normalizePaths(Settings.ADDITIONAL_JDKS.getOrDefaultValue());
        String javaHome = System.getenv("JAVA_HOME");
        if (javaHome != null && !javaHome.isEmpty()) {
            addIfValid(jdks, createJDKFromAnyPath(javaHome), excludedPaths);
        }

        String jdkHome = System.getenv("JDK_HOME");
        if (jdkHome != null && !jdkHome.isEmpty()) {
            addIfValid(jdks, createJDKFromAnyPath(jdkHome), excludedPaths);
        }

        // Location 2: System PATH
        String javaPath = findJavaOnPath();
        if (javaPath != null) {
            addIfValid(jdks, createJDKFromAnyPath(javaPath), excludedPaths);
        }

        // Location 3: Common installation directories
        for (Path dir : getPossibleJDKPaths()) {
            if (isExcluded(dir, excludedPaths))
                continue;

            if (Files.exists(dir) && Files.isDirectory(dir)) {
                try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir)) {
                    for (Path entry : stream) {
                        if (!Files.isDirectory(entry))
                            continue;

                        if (isExcluded(entry, excludedPaths))
                            continue;

                        Path exe;
                        if (OperatingSystem.CURRENT == OperatingSystem.MAC) {
                            exe = entry.resolve("Contents").resolve("Home").resolve("bin").resolve(JAVA_EXECUTABLE);
                        } else {
                            exe = entry.resolve("bin").resolve(JAVA_EXECUTABLE);
                        }

                        addIfValid(jdks, createJDKFromAnyPath(exe.toString()), excludedPaths);
                    }
                } catch (IOException exception) {
                    Railroad.LOGGER.warn("Failed to read JDKs from directory: {}", dir, exception);
                }
            }
        }

        // Location 4: User-provided JDK executables
        for (Path manualPath : manualJdkPaths) {
            addIfValid(jdks, createJDKFromAnyPath(manualPath.toString()), excludedPaths);
        }

        // Remove duplicates based on normalized paths
        Map<String, JDK> uniqueJDKs = new LinkedHashMap<>();
        for (JDK jdk : jdks) {
            try {
                Path normalizedPath = jdk.path().toRealPath();
                if (!isExcluded(normalizedPath, excludedPaths)) {
                    uniqueJDKs.putIfAbsent(normalizedPath.toString(), new JDK(normalizedPath, jdk.name(), jdk.version()));
                }
            } catch (IOException | InvalidPathException ignored) {
                // fallback to raw path if normalization fails
                addIfNotExcluded(uniqueJDKs, jdk, excludedPaths);
            }
        }

        return new ArrayList<>(uniqueJDKs.values());
    }

    private static void addIfValid(List<JDK> jdks, JDK jdk, List<Path> excludedPaths) {
        if (jdk == null)
            return;

        Path jdkPath = jdk.path();
        if (isExcluded(jdkPath, excludedPaths))
            return;

        jdks.add(jdk);
    }

    private static void addIfNotExcluded(Map<String, JDK> uniqueJDKs, JDK jdk, List<Path> excludedPaths) {
        Path jdkPath = jdk.path();
        if (isExcluded(jdkPath, excludedPaths))
            return;

        uniqueJDKs.putIfAbsent(jdk.path().toString(), jdk);
    }

    private static JDK createJDKFromAnyPath(String javaHomeOrExe) {
        Path path;
        try {
            path = Path.of(javaHomeOrExe);
        } catch (InvalidPathException ignored) {
            return null;
        }

        if (Files.notExists(path))
            return null;

        Path home = resolveJavaHome(path);
        if (home == null)
            return null;

        JavaVersion version = readJavaVersion(home);
        if (version == null)
            return null;

        String name = home.getFileName() != null ? home.getFileName().toString() : home.toString();
        return new JDK(home.toAbsolutePath(), name, version);
    }

    public static Properties readReleaseProperties(Path javaHome) {
        var props = new Properties();
        Path release = javaHome.resolve("release");
        if (Files.isRegularFile(release)) {
            try (BufferedReader bufferedReader = Files.newBufferedReader(release)) {
                props.load(bufferedReader);
            } catch (IOException ignored) {
            }
        }

        return props;
    }

    private static JavaVersion readJavaVersion(Path javaHome) {
        // 1) Try $JAVA_HOME/release
        var properties = readReleaseProperties(javaHome);
        String versionStr = stripQuotes(properties.getProperty("JAVA_VERSION"));
        JavaVersion version = parseJavaVersionString(versionStr);
        if (version != null)
            return version;

        // 2) Fallback to `java -version`
        String exe = javaHome.resolve("bin").resolve(JAVA_EXECUTABLE).toString();
        return getJavaVersionFromProcess(exe);
    }

    private static JavaVersion getJavaVersionFromProcess(String javaExe) {
        try {
            Process process = new ProcessBuilder(javaExe, "-version")
                .redirectErrorStream(true)
                .start();

            String line;
            try (var bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                while ((line = bufferedReader.readLine()) != null) {
                    // Look for "... version "21.0.3" ..." or "java version "1.8.0_392""
                    int q1 = line.indexOf('"');
                    int q2 = line.indexOf('"', q1 + 1);
                    if (q1 >= 0 && q2 > q1) {
                        String versionStr = line.substring(q1 + 1, q2);
                        JavaVersion version = parseJavaVersionString(versionStr);
                        if (version != null) {
                            process.waitFor(300, TimeUnit.MILLISECONDS);
                            return version;
                        }
                    }
                }
            }

            process.waitFor(300, TimeUnit.MILLISECONDS);
        } catch (IOException ignored) {
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }

        return null;
    }

    private static List<Path> normalizePaths(Collection<Path> paths) {
        if (paths == null || paths.isEmpty())
            return Collections.emptyList();

        Set<Path> normalized = new LinkedHashSet<>();
        for (Path path : paths) {
            addNormalized(normalized, path);
        }

        return new ArrayList<>(normalized);
    }

    private static void addNormalized(Set<Path> target, Path path) {
        if (path == null)
            return;

        target.add(path.toAbsolutePath().normalize());
    }

    private static boolean isExcluded(Path candidate, List<Path> excludedPaths) {
        if (candidate == null || excludedPaths == null || excludedPaths.isEmpty())
            return false;

        Path normalizedCandidate = candidate.toAbsolutePath().normalize();
        for (Path excluded : excludedPaths) {
            if (excluded == null)
                continue;

            if (normalizedCandidate.equals(excluded) || normalizedCandidate.startsWith(excluded))
                return true;
        }

        return false;
    }

    private static String stripQuotes(String str) {
        if (str == null)
            return null;

        return str.length() >= 2 && str.startsWith("\"") && str.endsWith("\"") ?
            str.substring(1, str.length() - 1) :
            str;
    }

    private static JavaVersion parseJavaVersionString(String version) {
        if (version == null)
            return null;

        Matcher matcher = JAVA_VERSION_PATTERN.matcher(version);
        if (!matcher.find())
            return null;

        int major = Integer.parseInt(matcher.group(1));
        Integer minor = matcher.group(2) != null ? Integer.parseInt(matcher.group(2)) : null;

        // Map legacy 1.x -> x
        if (major == 1 && minor != null) {
            major = minor;
            minor = 0;
        }

        return new JavaVersion(major, minor != null ? minor : 0);
    }

    private static Path resolveJavaHome(Path any) {
        try {
            any = any.toRealPath(); // normalize symlinks
        } catch (IOException ignored) {
        }

        if (Files.isDirectory(any)) {
            // If it's already a JDK home (has bin/java)
            if (Files.isExecutable(any.resolve("bin").resolve(JAVA_EXECUTABLE)))
                return any;

            // legacy: <home>/jre/bin/java
            if (Files.isExecutable(any.resolve("jre").resolve("bin").resolve(JAVA_EXECUTABLE)))
                return any;

            // macOS bundle directory (<*.jdk>), use Contents/Home
            Path macHome = any.resolve("Contents").resolve("Home");
            if (Files.isExecutable(macHome.resolve("bin").resolve(JAVA_EXECUTABLE)))
                return macHome;

            // If it's a bin directory itself, step up one
            if (any.getFileName() != null && any.getFileName().toString().equalsIgnoreCase("bin")) {
                Path parent = any.getParent();
                if (parent != null && Files.isExecutable(parent.resolve("bin").resolve(JAVA_EXECUTABLE)))
                    return parent;
            }

            return null;
        }

        // It's a file (likely .../bin/java)
        Path parent = any.getParent();
        if (parent == null)
            return null;

        String parentName = parent.getFileName() != null ? parent.getFileName().toString() : "";
        // .../Contents/Home/bin/java
        if (parentName.equals("bin") && parent.getParent() != null &&
            parent.getParent().getFileName() != null &&
            parent.getParent().getFileName().toString().equals("Home")) {
            Path home = parent.getParent();
            // .../Contents/Home
            if (home.getParent() != null && home.getParent().getFileName() != null &&
                home.getParent().getFileName().toString().equals("Contents")) {
                return home; // macOS
            }
        }

        // .../bin/java  (most platforms)
        if (parentName.equalsIgnoreCase("bin")) {
            Path home = parent.getParent();
            if (home != null)
                return home;
        }

        // .../jre/bin/java  (older layouts)
        if (parentName.equalsIgnoreCase("bin") && parent.getParent() != null &&
            parent.getParent().getFileName() != null &&
            parent.getParent().getFileName().toString().equalsIgnoreCase("jre")) {
            return parent.getParent().getParent();
        }

        return null;
    }

    private static String findJavaOnPath() {
        String pathEnv = System.getenv("PATH");
        if (pathEnv == null)
            return null;

        for (String raw : pathEnv.split(File.pathSeparator)) {
            String path = stripQuotes(raw.trim());
            if (path.isEmpty())
                continue;

            Path javaPath = Path.of(path, JAVA_EXECUTABLE);
            if (Files.exists(javaPath) && Files.isExecutable(javaPath))
                return javaPath.toAbsolutePath().toString();
        }

        return null;
    }

    private static List<Path> getPossibleJDKPaths() {
        Set<Path> candidates = new LinkedHashSet<>();

        switch (OperatingSystem.CURRENT) {
            case WINDOWS -> {
                for (String basePath : WIN_JDK_PATHS) {
                    for (char drive = 'A'; drive <= 'Z'; drive++) {
                        String path = basePath.replace("{drive}", String.valueOf(drive));
                        addNormalized(candidates, Path.of(path));
                    }
                }
            }
            case MAC -> MAC_JDK_PATHS.forEach(path -> addNormalized(candidates, Path.of(path)));
            case LINUX -> LINUX_JDK_PATHS.forEach(path -> addNormalized(candidates, Path.of(path)));
            case UNKNOWN -> {
                // no default paths
            }
        }

        String userHome = System.getProperty("user.home");
        if (userHome != null && !userHome.isBlank()) {
            addNormalized(candidates, Path.of(userHome, ".sdkman", "candidates", "java"));
            addNormalized(candidates, Path.of(userHome, ".asdf", "installs", "java"));
            addNormalized(candidates, Path.of(userHome, ".jdks"));
            addNormalized(candidates, Path.of(userHome, ".gradle", "jdks"));
        }

        String gradleUserHome = System.getenv("GRADLE_USER_HOME");
        if (gradleUserHome != null && !gradleUserHome.isBlank()) {
            addNormalized(candidates, Path.of(gradleUserHome, "jdks"));
        }

        for (Path path : normalizePaths(Settings.ADDITIONAL_JDK_SCAN_PATHS.getOrDefaultValue())) {
            addNormalized(candidates, path);
        }

        return new ArrayList<>(candidates);
    }

    private static String javaExecutableName() {
        return OperatingSystem.CURRENT == OperatingSystem.WINDOWS ? "java.exe" : "java";
    }
}
