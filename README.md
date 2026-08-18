# SCA - Static Code Analysis Tool

A comprehensive security analysis tool for JavaScript and PHP code that integrates multiple security analysis modules into a single, professional CLI interface.

## 🚀 Features

- **Poor Error Handling Detection** - Identifies inadequate error handling patterns
- **Unsafe Functions Analysis** - Detects potentially dangerous function calls
- **Unsanitized Input Detection** - Finds taint analysis vulnerabilities
- **Weak Cryptography Analysis** - Detects insecure cryptographic practices
- **Rich CLI Interface** - Professional command-line interface with progress bars and tables
- **JSON Export** - Downloadable results in JSON format
- **Batch Processing** - Scan entire directories recursively
- **Comprehensive Reporting** - Detailed analysis with severity classification

## 📋 Requirements

- Python 3.8+
- All SCA modules must be accessible in their respective directories

## 🛠️ Installation

1. **Clone or download the SCA tool:**
   ```bash
   git clone <repository-url>
   cd SCA
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify installation:**
   ```bash
   python main.py --help
   ```

## 🎯 Usage

### Basic Commands

```bash
# Show help and available commands
python main.py --help

# Display tool information
python main.py info

# Analyze a single file
python main.py analyze <file.js|file.php>

# Scan a directory
python main.py scan <directory>

# Get help for specific commands
python main.py analyze --help
python main.py scan --help
```

### Analyze Single File

```bash
# Basic analysis with rich output
python main.py analyze test.js

# Save results to JSON file
python main.py analyze test.js --output results.json

# Output in JSON format only
python main.py analyze test.js --format json

# Disable progress bars
python main.py analyze test.js --no-progress
```

### Scan Directory

```bash
# Scan current directory for .js and .php files
python main.py scan .

# Scan with custom file extensions
python main.py scan ./src --extensions .js,.jsx,.ts,.php

# Recursive scan of subdirectories
python main.py scan ./src --recursive

# Save results to output directory
python main.py scan ./src --output ./results --recursive
```

## 📊 Output Formats

### Rich CLI Output
The tool provides beautiful, formatted output with:
- Progress bars for analysis steps
- Tables showing file information and analysis summary
- Severity-based findings classification
- Color-coded results (green for safe, yellow for warnings, red for high-severity issues)

### JSON Export
Results are automatically saved when using `--output` or `--format json`:
- Individual file results with timestamps
- Combined results for directory scans
- Structured data for integration with other tools
- Downloadable files for reporting and analysis

## 🔍 Analysis Modules

### 1. Poor Error Handling
- Detects missing error handling in critical operations
- Identifies inadequate exception handling patterns
- Reports potential error propagation issues

### 2. Unsafe Functions
- Identifies dangerous function calls (eval, exec, etc.)
- Detects potentially unsafe API usage
- Reports functions that could lead to security vulnerabilities

### 3. Unsanitized Input
- Performs taint analysis on user inputs
- Identifies data flow from sources to sinks
- Detects missing input validation and sanitization

### 4. Weak Cryptography
- Identifies insecure cryptographic algorithms
- Detects weak key generation practices
- Reports deprecated or broken crypto functions

### 5. Poor Authentication
- Identifies hard coded credentials in the source code
- Detects unsafe usage of passowords and other credentials
- Reports unsafe usage of authentication

## 📁 File Structure

```
SCA/
├── main.py                          # Main CLI tool
├── gui.py                           # Gui tool
├── requirements.txt                 # Python dependencies
├── README.md                       # This file
├── SCA_POOR_ERROR_HANDLING/       # Error handling analysis module
├── SCA_UNSAFE_FUNCTIONS/          # Unsafe functions analysis module
├── SCA_UNSANITIZED_INPUT/         # Input validation analysis module
├── SCA_WEAK_CRYPTO/              # Cryptography analysis module
├── SCA_POOR_AUTH/                 # Poor Authentication analysis module
└── test_comprehensive.js          # Test file
```

## 🧪 Testing

Test the tool with the included test file:

```bash
# Test basic functionality with json output
python main.py analyze test_comprehensive.js -f json

# Test with tabular output
python main.py analyze test_comprehensive.js

# Test directory scanning & json output
python main.py bulk-analyze test_comprehensive.js -f json

# Filtering 
python main.py analyze test_comprehensive.js --severity low
python main.py bulk-analyze test_comprehensive.js --severity medium
```

## 🔧 Troubleshooting

### Common Issues

1. **Import Errors**: Ensure all SCA modules are in their respective directories
2. **Tree-sitter Issues**: Install `tree-sitter-language-pack` if you encounter parsing errors
3. **File Permissions**: Ensure the tool has read access to target files and write access to output directories

### Error Messages

- `[!] Error importing SCA modules`: Check module directory structure
- `[!] Analysis failed`: Review the specific error message for details
- `[!] Failed to save results`: Check output directory permissions and existence

## 📈 Performance

- **Single File Analysis**: Typically completes in 1-5 seconds
- **Directory Scanning**: Performance scales with number of files and complexity
- **Memory Usage**: Minimal memory footprint for most analysis tasks

## 🤝 Contributing

To contribute to the SCA tool:

1. Ensure all modules are self-contained
2. Test with various file types and sizes
3. Maintain consistent error handling patterns
4. Follow the existing code structure and style

## 📄 License

This tool is provided as-is for security analysis purposes. Use responsibly and in accordance with applicable laws and regulations.

## 🆘 Support

For issues or questions:
1. Check the troubleshooting section above
2. Verify all dependencies are installed
3. Test with the included test file
4. Review error messages for specific guidance

---

**SCA Tool v1.0.0** - Making code security analysis accessible and professional.
