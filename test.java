public class test {
    import java.sql.*;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * This class demonstrates common Java security vulnerabilities.
 * Each method shows the UNSAFE way and the SAFE way to perform an operation.
 */
public class SecurityVulnerabilitiesDemo {

    // Imagine these are passed from a user (e.g., a web request)
    private static final String userInput = "105; DROP TABLE users;"; // Malicious input
    private static final String filename = "../../etc/passwd"; // Path Traversal input

    public static void main(String[] args) {
        System.out.println("=== Demonstrating Java Security Vulnerabilities ===\n");

        // 1. SQL Injection
        System.out.println("1. SQL Injection Demonstration:");
        System.out.println("Unsafe SQL: " + buildUnsafeSQLQuery(userInput));
        System.out.println("Safe SQL: " + buildSafeSQLQuery(userInput));
        System.out.println();

        // 2. Path Traversal
        System.out.println("2. Path Traversal Demonstration:");
        System.out.println("Unsafe Path: " + getUnsafeFileContent(filename));
        System.out.println("Safe Path: " + getSafeFileContent("data.txt")); // Using a safe, expected filename
        System.out.println();

        // 3. Hardcoded Sensitive Data (like passwords, API keys)
        System.out.println("3. Hardcoded Secrets Demonstration:");
        unsafeDatabaseConnection();
        safeDatabaseConnection(); // This would fail to connect, proving it's not hardcoded here.
    }

    // ========== VULNERABILITY 1: SQL INJECTION ==========

    /**
     * UNSAFE: Concatenates user input directly into a query.
     * VULNERABLE: The input can escape the data context and become part of the SQL command.
     */
    public static String buildUnsafeSQLQuery(String userId) {
        // This is extremely dangerous!
        return "SELECT * FROM users WHERE id = " + userId;
    }

    /**
     * SAFE: Uses a PreparedStatement to separate code from data.
     * The user input is automatically escaped and treated as a literal value, not executable code.
     */
    public static String buildSafeSQLQuery(String userId) {
        // This is just a simulation for demonstration.
        // In real code, you would use a PreparedStatement with a connection.
        String safeQuery = "SELECT * FROM users WHERE id = ?";
        // Then you would do: preparedStatement.setString(1, userId);
        return safeQuery + " [Parameter: " + userId + "]";
    }

    // ========== VULNERABILITY 2: PATH TRAVERSAL ==========

    /**
     * UNSAFE: Uses user input to directly access a file.
     * VULNERABLE: An attacker can use '../' sequences to escape the intended directory.
     */
    public static String getUnsafeFileContent(String filePath) {
        try {
            // An attacker can provide a path like "../../etc/passwd"
            byte[] bytes = Files.readAllBytes(Paths.get("./data/", filePath));
            return new String(bytes);
        } catch (IOException | java.nio.file.InvalidPathException e) {
            return "Error reading file: " + e.getMessage();
        }
    }

    /**
     * SAFE: Validates and sanitizes the filename before using it.
     * Uses a whitelist of allowed characters or a direct mapping to known-safe values.
     */
    public static String getSafeFileContent(String fileName) {
        // Simple validation: reject filenames with path characters
        if (fileName.contains("..") || fileName.contains("/") || fileName.contains("\\")) {
            return "Invalid filename: Path traversal characters detected.";
        }

        // Alternatively, use a whitelist of allowed filenames
        // if (!fileName.equals("data.txt") && !fileName.equals("config.txt")) { ... }

        try {
            // Now the path is safe
            byte[] bytes = Files.readAllBytes(Paths.get("./data/", fileName));
            return new String(bytes);
        } catch (IOException e) {
            return "Error reading file: " + e.getMessage();
        }
    }

    // ========== VULNERABILITY 3: HARDCODED SECRETS ==========

    /**
     * UNSAFE: Passwords, API keys, or secrets are written directly in the source code.
     * VULNERABLE: Anyone with access to the code (e.g., in a git repository) can see the secret.
     */
    public static void unsafeDatabaseConnection() {
        String url = "jdbc:mysql://localhost:3306/mydb";
        String user = "admin";
        String password = "MySuperSecretPassword123!"; // BAD! NEVER DO THIS!

        System.out.println("Unsafe Connection: Password is visible in the code.");
        // Connection conn = DriverManager.getConnection(url, user, password);
    }

    /**
     * SAFE: Sensitive data is read from a secure environment variable or config file
     * that is NOT checked into version control (e.g., added to .gitignore).
     */
    public static void safeDatabaseConnection() {
        String url = "jdbc:mysql://localhost:3306/mydb";
        String user = "admin";
        // Read the password from an environment variable
        String password = System.getenv("DB_PASSWORD");

        if (password == null || password.isEmpty()) {
            System.out.println("Safe Connection: Could not read DB_PASSWORD environment variable.");
            return;
        }

        System.out.println("Safe Connection: Password is loaded from environment.");
        // Connection conn = DriverManager.getConnection(url, user, password);
    }
}
}
