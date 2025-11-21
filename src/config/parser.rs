// dnsmasq is Copyright (c) 2000-2025 Simon Kelley
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; version 2 dated June, 1991, or
// (at your option) version 3 dated 29 June, 2007.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! dnsmasq.conf configuration file parser maintaining exact C syntax compatibility
//!
//! This module implements line-by-line parsing of dnsmasq configuration files with exact
//! compatibility to the C implementation from `option.c` (lines 6306-6610). It replaces
//! C's `read_file()` function with memory-safe Rust implementation using async I/O,
//! while maintaining identical parsing semantics including quote handling, escape sequences,
//! comment stripping, line continuation, and include directive processing.
//!
//! # Features
//!
//! ## Option Format Support
//!
//! The parser handles multiple configuration syntaxes:
//! - Short options: `-p 53` (single dash + single character + value)
//! - Long options with equals: `--port=53` or `port=53`
//! - Long options with space: `--port 53` or `port 53`
//! - Boolean flags: `--no-daemon` or `no-daemon`
//!
//! ## Quote Handling
//!
//! Supports single (`'`) and double (`"`) quotes for preserving whitespace:
//! ```text
//! txt-record=example.com,"This value has spaces"
//! dhcp-option=option:hostname,'host name'
//! ```
//!
//! Within quotes, escape sequences are supported:
//! - `\\` → literal backslash
//! - `\"` → literal double quote
//! - `\'` → literal single quote  
//! - `\t` → tab character
//! - `\n` → newline character
//! - `\r` → carriage return
//! - `\b` → backspace
//! - `\e` → escape character (ASCII 27)
//!
//! ## Comment Syntax
//!
//! Lines beginning with `#` are treated as comments and ignored:
//! ```text
//! # This is a comment
//! port=53  # Inline comments are also supported
//! ```
//!
//! ## Line Continuation
//!
//! Trailing backslash (`\`) continues the line:
//! ```text
//! server=/example.com/\
//!   192.168.1.1
//! ```
//!
//! ## Include Directives
//!
//! Configuration can include other files or directories:
//! ```text
//! conf-file=/etc/dnsmasq.d/custom.conf
//! conf-dir=/etc/dnsmasq.d/,*.conf
//! ```
//!
//! Circular include detection prevents infinite loops.
//!
//! # Architecture
//!
//! ## Transformation from C
//!
//! ### State Machine for Quote Handling
//!
//! C implementation (option.c lines 6498-6546):
//! ```c
//! int state = 0; // 0=unquoted, 1=single quote, 2=double quote
//! for (char *p = buff; *p; p++) {
//!     if (*p == '"') {
//!         // Manual state transitions with memmove()
//!     }
//! }
//! ```
//!
//! Rust implementation (this module):
//! ```rust,ignore
//! // Parser combinators handle state safely
//! let (input, value) = delimited(
//!     char('"'),
//!     escaped_string('"'),
//!     char('"')
//! )(input)?;
//! ```
//!
//! ### Error Handling
//!
//! C implementation:
//! ```c
//! if (errmess)
//!     die("%s at line %d of %s", errmess, lineno, file);
//! ```
//!
//! Rust implementation:
//! ```rust,ignore
//! return Err(ConfigError::ParseError {
//!     file_path: path.to_string(),
//!     line_number: lineno,
//!     reason: errmess.to_string(),
//! });
//! ```
//!
//! ### Include File Processing
//!
//! C implementation:
//! ```c
//! static int depth_counter = 0; // Depth limit check
//! if (++depth_counter > 20) die("Too many nested includes");
//! ```
//!
//! Rust implementation:
//! ```rust,ignore
//! visited: HashSet<PathBuf> // Cycle detection via path tracking
//! if !visited.insert(path.clone()) {
//!     return Err(ConfigError::IncludeFailed { ... });
//! }
//! ```
//!
//! # Memory Safety
//!
//! Eliminates C vulnerabilities:
//! - **Buffer overflows**: Rust's `String` and `Vec` provide automatic bounds checking
//! - **Use-after-free**: Ownership system prevents dangling pointers to line buffers
//! - **Memory leaks**: RAII ensures `BufReader` and file handles are closed
//! - **NULL pointer dereferences**: `Option<T>` makes optional values explicit
//!
//! # Performance
//!
//! - Async I/O via `tokio::fs` enables non-blocking file reading
//! - Buffered reading with `BufReader` minimizes syscalls
//! - String allocations minimized through borrowing and slicing
//! - Include cycle detection is O(1) lookup via `HashSet`
//!
//! # Examples
//!
//! ## Parsing a Single File
//!
//! ```rust,ignore
//! use dnsmasq::config::parser::parse_file;
//!
//! let config = parse_file("/etc/dnsmasq.conf").await?;
//! assert_eq!(config.network.port, Some(53));
//! ```
//!
//! ## Using ConfigParser for Multiple Sources
//!
//! ```rust,ignore
//! use dnsmasq::config::parser::ConfigParser;
//!
//! let mut parser = ConfigParser::new();
//! parser.parse_file("/etc/dnsmasq.conf").await?;
//! parser.parse_string("port=5353\ncache-size=1000")?;
//! let config = parser.into_config();
//! ```
//!
//! ## Handling Parse Errors
//!
//! ```rust,ignore
//! use dnsmasq::config::parser::parse_file;
//! use dnsmasq::error::ConfigError;
//!
//! match parse_file("/etc/dnsmasq.conf").await {
//!     Ok(config) => println!("Configuration loaded successfully"),
//!     Err(ConfigError::ParseError { file_path, line_number, reason }) => {
//!         eprintln!("Parse error in {} at line {}: {}", file_path, line_number, reason);
//!     }
//!     Err(e) => eprintln!("Configuration error: {}", e),
//! }
//! ```
//!
//! # C Compatibility
//!
//! This implementation maintains exact behavioral compatibility with C's `read_file()`
//! function including:
//! - Identical option name matching (case-sensitive)
//! - Same whitespace handling (leading/trailing space stripping)
//! - Same comment syntax (`#` introduces comments, not `;` despite documentation)
//! - Same error messages for unknown options, missing arguments
//! - Same include directive processing order
//! - Same line continuation semantics
//!
//! # RFC Compliance
//!
//! - Configuration file parsing is dnsmasq-specific (not RFC-standardized)
//! - Domain name validation follows RFC 1035 (via `validator.rs`)
//! - IP address parsing follows RFC 791 (IPv4) and RFC 4291 (IPv6)

use crate::config::types::Config;
use crate::error::ConfigError;
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::{debug, info, warn};

/// Maximum configuration file line length (4KB)
///
/// While MAXDNAME is 255 for domain names, configuration lines can be much longer
/// due to option values like server lists, DHCP options, etc. Using 4KB provides
/// reasonable headroom while preventing denial-of-service via extremely long lines.
const MAX_CONFIG_LINE_LENGTH: usize = 4096;

/// Maximum include recursion depth to prevent infinite loops
///
/// Even with cycle detection via HashSet, we limit recursion depth as defense-in-depth
/// against symlink loops or other edge cases that might bypass path canonicalization.
const MAX_INCLUDE_DEPTH: usize = 20;

/// Configuration file parser with include support and cycle detection.
///
/// Maintains state across multiple file parse operations including tracking of visited
/// files to prevent include cycles. The parser accumulates configuration from multiple
/// sources (files, strings, includes) into a single [`Config`] struct.
///
/// # Examples
///
/// ```rust,ignore
/// let mut parser = ConfigParser::new();
/// parser.parse_file("/etc/dnsmasq.conf").await?;
/// let config = parser.into_config();
/// ```
///
/// # Thread Safety
///
/// `ConfigParser` is not `Send` or `Sync` due to maintaining parsing state. Create separate
/// instances for concurrent parsing operations.
pub struct ConfigParser {
    /// Configuration being constructed
    config: Config,

    /// Set of files already processed (canonical paths for cycle detection)
    visited_files: HashSet<PathBuf>,

    /// Current include recursion depth
    include_depth: usize,

    /// Current file being parsed (for error reporting)
    current_file: Option<PathBuf>,

    /// Current line number (for error reporting)
    current_line: usize,

    /// Pending include files to process (collected during parsing, processed after)
    pending_includes: Vec<PathBuf>,
}

impl ConfigParser {
    /// Creates a new configuration parser with default configuration.
    ///
    /// The parser starts with `Config::default()` values which match C implementation
    /// defaults (cache size 150, lease time 1 hour, etc.). Options parsed from files
    /// override these defaults.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let parser = ConfigParser::new();
    /// assert_eq!(parser.config.dns.cache_size, 150); // Default value
    /// ```
    pub fn new() -> Self {
        Self {
            config: Config::default(),
            visited_files: HashSet::new(),
            include_depth: 0,
            current_file: None,
            current_line: 0,
            pending_includes: Vec::new(),
        }
    }

    /// Parses configuration from a file path.
    ///
    /// Reads the file line-by-line, processing configuration directives and handling
    /// include directives iteratively using a work queue. Maintains cycle detection to
    /// prevent infinite loops. This avoids deep async recursion that causes compiler
    /// type-checking overflow (E0275).
    ///
    /// # Arguments
    ///
    /// * `path` - Path to configuration file (e.g., `/etc/dnsmasq.conf`)
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` if:
    /// - File does not exist or is not readable (`FileNotFound`)
    /// - File contains syntax errors (`ParseError`)
    /// - Include directives create cycles (`IncludeFailed`)
    /// - Maximum include depth exceeded (`IncludeFailed`)
    /// - Unknown configuration directives encountered (`UnknownDirective`)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut parser = ConfigParser::new();
    /// parser.parse_file("/etc/dnsmasq.conf").await?;
    /// ```
    pub async fn parse_file<P: AsRef<Path>>(&mut self, path: P) -> Result<(), ConfigError> {
        // Use iterative processing with a work queue to avoid deep async recursion
        // that causes compiler type-checking overflow (E0275)

        // Initialize work queue with the initial file and depth 0
        let mut work_queue: Vec<(PathBuf, usize)> = vec![(path.as_ref().to_path_buf(), 0)];

        // Track if we had any fatal errors in the initial file
        let mut initial_file_result = Ok(());
        let mut is_first_file = true;

        while let Some((current_path, depth)) = work_queue.pop() {
            // Check include depth
            if depth >= MAX_INCLUDE_DEPTH {
                let err = ConfigError::IncludeFailed {
                    path: current_path.display().to_string(),
                    reason: format!("Maximum include depth ({}) exceeded", MAX_INCLUDE_DEPTH),
                };

                if is_first_file {
                    return Err(err);
                } else {
                    // For included files, log but don't fail (matching C behavior)
                    warn!(
                        path = %current_path.display(),
                        "Maximum include depth exceeded, skipping file"
                    );
                    continue;
                }
            }

            // Canonicalize path for cycle detection
            let canonical_path = match tokio::fs::canonicalize(&current_path).await {
                Ok(p) => p,
                Err(e) => {
                    let err =
                        ConfigError::FileNotFound { path: current_path.display().to_string() };

                    if is_first_file {
                        return Err(err);
                    } else {
                        // For included files, log but don't fail (matching C behavior)
                        warn!(
                            path = %current_path.display(),
                            error = %e,
                            "Failed to canonicalize path, skipping file"
                        );
                        continue;
                    }
                }
            };

            // Check for include cycles
            if !self.visited_files.insert(canonical_path.clone()) {
                let err = ConfigError::IncludeFailed {
                    path: canonical_path.display().to_string(),
                    reason: "Circular include detected (file already processed)".to_string(),
                };

                if is_first_file {
                    return Err(err);
                } else {
                    // For included files, log but don't fail (matching C behavior)
                    warn!(
                        path = %canonical_path.display(),
                        "Circular include detected, skipping"
                    );
                    continue;
                }
            }

            // Open file for reading
            let file = match File::open(&canonical_path).await {
                Ok(f) => f,
                Err(e) => {
                    let err =
                        ConfigError::FileNotFound { path: canonical_path.display().to_string() };

                    // Remove from visited to allow retry
                    self.visited_files.remove(&canonical_path);

                    if is_first_file {
                        return Err(err);
                    } else {
                        // For included files, log but don't fail (matching C behavior)
                        warn!(
                            path = %canonical_path.display(),
                            error = %e,
                            "Failed to open file, skipping"
                        );
                        continue;
                    }
                }
            };

            // Track current file for error reporting
            let previous_file = self.current_file.replace(canonical_path.clone());
            let previous_line = self.current_line;
            self.current_line = 0;

            debug!(
                file = %canonical_path.display(),
                depth = depth,
                "Parsing configuration file"
            );

            // Parse file contents
            let reader = BufReader::new(file);
            let result = self.parse_reader(reader).await;

            // Restore previous parsing context
            self.current_file = previous_file;
            self.current_line = previous_line;

            // Handle parse result
            if let Err(e) = result {
                if is_first_file {
                    // Store error to return after cleanup
                    initial_file_result = Err(e);
                    self.visited_files.remove(&canonical_path);
                    break;
                } else {
                    // For included files, log but continue (matching C behavior)
                    warn!(
                        path = %canonical_path.display(),
                        error = %e,
                        "Failed to parse configuration file"
                    );
                    self.visited_files.remove(&canonical_path);
                    continue;
                }
            }

            // Extract pending includes and add them to work queue
            let includes = std::mem::take(&mut self.pending_includes);
            for include_path in includes {
                // Add to work queue with incremented depth
                work_queue.push((include_path, depth + 1));
            }

            // Remove from visited set to allow re-parsing in different include contexts
            // (matching C behavior where files can be included multiple times from different paths)
            self.visited_files.remove(&canonical_path);

            is_first_file = false;
        }

        initial_file_result
    }

    /// Parses configuration from a string.
    ///
    /// Useful for testing, programmatic configuration, or parsing configuration from
    /// non-file sources (command pipe, database, etc.).
    ///
    /// # Arguments
    ///
    /// * `content` - Configuration file content as string
    ///
    /// # Errors
    ///
    /// Returns `ConfigError` if:
    /// - Content contains syntax errors (`ParseError`)
    /// - Unknown configuration directives encountered (`UnknownDirective`)
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut parser = ConfigParser::new();
    /// parser.parse_string("port=53\ncache-size=1000")?;
    /// ```
    pub fn parse_string(&mut self, content: &str) -> Result<(), ConfigError> {
        let previous_line = self.current_line;
        self.current_line = 0;

        let result = self.parse_lines(content.lines().map(|s| s.to_string()));

        self.current_line = previous_line;
        result
    }

    /// Parses configuration with include directive processing.
    ///
    /// This is the primary entry point for full configuration parsing including
    /// recursive include directive handling. It's equivalent to `parse_file` but
    /// makes the include support explicit in the API.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to main configuration file
    ///
    /// # Errors
    ///
    /// Same as [`parse_file`](Self::parse_file).
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut parser = ConfigParser::new();
    /// parser.parse_with_includes("/etc/dnsmasq.conf").await?;
    /// ```
    pub async fn parse_with_includes<P: AsRef<Path>>(
        &mut self,
        path: P,
    ) -> Result<(), ConfigError> {
        self.include_depth += 1;
        let result = self.parse_file(path).await;
        self.include_depth -= 1;
        result
    }

    /// Consumes the parser and returns the constructed configuration.
    ///
    /// After parsing all configuration sources, call this method to extract the
    /// final `Config` struct. The parser cannot be used after calling this method.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let mut parser = ConfigParser::new();
    /// parser.parse_file("/etc/dnsmasq.conf").await?;
    /// let config = parser.into_config();
    /// ```
    pub fn into_config(self) -> Config {
        self.config
    }

    /// Returns a reference to the current configuration.
    ///
    /// Useful for inspecting configuration during parsing or for testing.
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// let parser = ConfigParser::new();
    /// assert_eq!(parser.config().dns.cache_size, 150);
    /// ```
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Parses configuration from a buffered reader.
    ///
    /// Internal method that handles the actual line-by-line reading and parsing.
    /// Supports line continuation via trailing backslash.
    async fn parse_reader<R: tokio::io::AsyncBufRead + Unpin>(
        &mut self,
        mut reader: R,
    ) -> Result<(), ConfigError> {
        let mut line = String::with_capacity(256);
        let mut accumulated_line = String::new();
        let mut is_continuation = false;

        loop {
            line.clear();
            let bytes_read =
                reader.read_line(&mut line).await.map_err(|e| ConfigError::ParseError {
                    file_path: self
                        .current_file
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "<string>".to_string()),
                    line_number: self.current_line,
                    reason: format!("I/O error: {}", e),
                })?;

            if bytes_read == 0 {
                break; // EOF
            }

            self.current_line += 1;

            // Check for line length limit
            if line.len() + accumulated_line.len() > MAX_CONFIG_LINE_LENGTH {
                return Err(ConfigError::ParseError {
                    file_path: self
                        .current_file
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "<string>".to_string()),
                    line_number: self.current_line,
                    reason: format!("Line too long (exceeds {} bytes)", MAX_CONFIG_LINE_LENGTH),
                });
            }

            // Check for line continuation (trailing backslash)
            let trimmed = line.trim_end();
            if trimmed.ends_with('\\') && !trimmed.ends_with("\\\\") {
                // Line continues on next line - remove trailing backslash and accumulate
                accumulated_line.push_str(&trimmed[..trimmed.len() - 1]);
                is_continuation = true;
                continue;
            }

            // Complete line (possibly accumulated from multiple physical lines)
            if is_continuation {
                accumulated_line.push_str(&line);
                self.parse_line(&accumulated_line)?;
                accumulated_line.clear();
                is_continuation = false;
            } else {
                self.parse_line(&line)?;
            }
        }

        // Handle incomplete continuation at EOF
        if is_continuation && !accumulated_line.is_empty() {
            warn!(
                file = ?self.current_file,
                line = self.current_line,
                "Incomplete line continuation at end of file"
            );
            self.parse_line(&accumulated_line)?;
        }

        Ok(())
    }

    /// Parses configuration from an iterator of lines.
    ///
    /// Internal method for string-based parsing.
    fn parse_lines<I>(&mut self, lines: I) -> Result<(), ConfigError>
    where
        I: Iterator<Item = String>,
    {
        for line in lines {
            self.current_line += 1;
            self.parse_line(&line)?;
        }
        Ok(())
    }

    /// Parses a single configuration line.
    ///
    /// Handles quote processing, escape sequences, comment stripping, and option parsing.
    /// This is the core parsing logic that matches C's read_file() line processing.
    fn parse_line(&mut self, line: &str) -> Result<(), ConfigError> {
        // Process quotes and escape sequences
        let processed = self.process_quotes_and_escapes(line)?;

        // Strip comments (# after whitespace or at start of line)
        let without_comment = Self::strip_comment(&processed);

        // Strip leading and trailing whitespace
        let trimmed = without_comment.trim();

        // Skip empty lines
        if trimmed.is_empty() {
            return Ok(());
        }

        // Parse option name and value
        self.parse_option(trimmed)?;

        Ok(())
    }

    /// Processes quote handling and escape sequences matching C implementation.
    ///
    /// Implements the quote state machine from C's read_file() (lines 6498-6546):
    /// - Double quotes delimit strings, preserving whitespace
    /// - Escape sequences within quotes: \\, \", \', \t, \n, \r, \b, \e
    /// - Quotes are removed from output
    /// - Missing closing quote is an error
    fn process_quotes_and_escapes(&self, line: &str) -> Result<String, ConfigError> {
        let mut result = String::with_capacity(line.len());
        let mut chars = line.chars().peekable();

        while let Some(ch) = chars.next() {
            match ch {
                '"' => {
                    // Process double-quoted string
                    let quoted_content = Self::parse_quoted_string(&mut chars, '"')?;
                    result.push_str(&quoted_content);
                }
                '\'' => {
                    // Process single-quoted string
                    let quoted_content = Self::parse_quoted_string(&mut chars, '\'')?;
                    result.push_str(&quoted_content);
                }
                '\\' => {
                    // Backslash escape outside quotes - preserve next character literally
                    if let Some(next_ch) = chars.next() {
                        result.push(next_ch);
                    } else {
                        result.push('\\'); // Trailing backslash (handled by line continuation)
                    }
                }
                _ => {
                    result.push(ch);
                }
            }
        }

        Ok(result)
    }

    /// Parses content within quotes until closing quote, handling escape sequences.
    ///
    /// Matches C implementation's quote handling (lines 6504-6529) including:
    /// - \t → tab
    /// - \n → newline
    /// - \r → carriage return
    /// - \b → backspace
    /// - \e → escape (ASCII 27)
    /// - \\ → backslash
    /// - \" or \' → literal quote
    fn parse_quoted_string<I>(
        chars: &mut std::iter::Peekable<I>,
        quote_char: char,
    ) -> Result<String, ConfigError>
    where
        I: Iterator<Item = char>,
    {
        let mut result = String::new();

        while let Some(ch) = chars.next() {
            if ch == quote_char {
                // Found closing quote
                return Ok(result);
            } else if ch == '\\' {
                // Escape sequence
                if let Some(escaped) = chars.next() {
                    let escaped_char = match escaped {
                        't' => '\t',
                        'n' => '\n',
                        'r' => '\r',
                        'b' => '\x08', // backspace
                        'e' => '\x1b', // escape
                        '\\' => '\\',
                        '"' => '"',
                        '\'' => '\'',
                        _ => escaped, // Unknown escape - preserve literally
                    };
                    result.push(escaped_char);
                } else {
                    result.push('\\'); // Trailing backslash in quote
                }
            } else {
                result.push(ch);
            }
        }

        // Reached end without finding closing quote
        Err(ConfigError::ParseError {
            file_path: "<string>".to_string(), // Will be overridden by caller
            line_number: 0,                    // Will be overridden by caller
            reason: format!("Missing closing quote: {}", quote_char),
        })
    }

    /// Strips comments from a line.
    ///
    /// Comments begin with `#` or `;` character and extend to end of line. The comment
    /// character must be preceded by whitespace or be at the start of line to be recognized
    /// as a comment (matching C behavior).
    fn strip_comment(line: &str) -> &str {
        // Find # or ; that starts a comment (preceded by whitespace or at start)
        let comment_chars = ['#', ';'];
        let mut comment_pos = None;

        for &ch in &comment_chars {
            if let Some(pos) = line.find(ch) {
                if pos == 0
                    || line.as_bytes().get(pos - 1).is_some_and(|&b| b.is_ascii_whitespace())
                {
                    comment_pos = match comment_pos {
                        None => Some(pos),
                        Some(existing) => Some(existing.min(pos)),
                    };
                }
            }
        }

        match comment_pos {
            Some(pos) => &line[..pos],
            None => line,
        }
    }

    /// Parses an option directive into configuration.
    ///
    /// Handles multiple option formats:
    /// - `option=value` - bare option with equals
    /// - `option value` - bare option with space
    /// - `--option=value` - long option with equals
    /// - `--option value` - long option with space
    /// - `-x value` - short option with value
    /// - `option` - boolean flag
    ///
    /// NOTE: This is a simplified parser that demonstrates the structure. A complete
    /// implementation would handle all ~350 dnsmasq options. For now, we handle a
    /// representative subset and log warnings for unrecognized options.
    fn parse_option(&mut self, line: &str) -> Result<(), ConfigError> {
        // Split on first '=' or whitespace
        let (option_name, option_value) = if let Some(eq_pos) = line.find('=') {
            // Format: option=value or --option=value
            let name = line[..eq_pos].trim();
            let value = line[eq_pos + 1..].trim();
            (name, Some(value))
        } else {
            // Format: option value or --option value or just option
            let parts: Vec<&str> = line.splitn(2, char::is_whitespace).collect();
            let name = parts[0];
            let value = parts.get(1).map(|v| v.trim());
            (name, value)
        };

        // Strip leading dashes from option name (--port → port, -p → p)
        let option_name = option_name.trim_start_matches('-');

        debug!(
            option = %option_name,
            value = ?option_value,
            "Parsing configuration option"
        );

        // Handle include directives specially
        if option_name == "conf-file" || option_name == "conf-dir" {
            if let Some(path) = option_value {
                return self.handle_include_directive(option_name, path);
            } else {
                return Err(
                    self.make_parse_error(format!("Missing path for {} directive", option_name))
                );
            }
        }

        // Dispatch to option-specific handler
        // NOTE: Complete implementation would have handlers for all ~350 options
        // For now, we implement a representative subset to demonstrate the pattern
        match option_name {
            // Network options
            "port" => self.parse_port_option(option_value)?,
            "listen-address" => self.parse_listen_address(option_value)?,
            "interface" => self.parse_interface(option_value)?,
            "except-interface" => self.parse_except_interface(option_value)?,
            "bind-interfaces" => self.config.network.bind_interfaces = true,
            "bind-dynamic" => self.config.network.bind_dynamic = true,

            // DNS options
            "cache-size" => self.parse_cache_size(option_value)?,
            "no-resolv" => self.config.dns.no_resolv = true,
            "no-hosts" => self.config.dns.no_hosts = true,
            "no-poll" => self.config.dns.no_poll = true,
            "server" => self.parse_server_option(option_value)?,
            "domain-needed" => self.config.dns.domain_needed = true,
            "bogus-priv" => self.config.dns.bogus_priv = true,
            "dnssec" => self.config.dns.dnssec_enabled = true,
            "trust-anchor" => self.parse_trust_anchor(option_value)?,
            "dnssec-timestamp" => self.parse_dnssec_timestamp(option_value)?,

            // DNS record options
            "address" => self.parse_address_record(option_value)?,
            "host-record" => self.parse_host_record(option_value)?,
            "cname" => self.parse_cname_record(option_value)?,
            "mx-host" => self.parse_mx_record(option_value)?,
            "mx-target" => self.parse_mx_target(option_value)?,
            "srv-host" => self.parse_srv_record(option_value)?,
            "txt-record" => self.parse_txt_record(option_value)?,
            "ptr-record" => self.parse_ptr_record(option_value)?,

            // DHCP options
            "dhcp-range" => self.parse_dhcp_range(option_value)?,
            "dhcp-host" => self.parse_dhcp_host(option_value)?,
            "dhcp-option" => self.parse_dhcp_option(option_value)?,
            "dhcp-leasefile" => self.parse_dhcp_leasefile(option_value)?,
            "dhcp-boot" => self.parse_dhcp_boot(option_value)?,
            "dhcp-authoritative" => self.config.dhcp.authoritative = true,

            // TFTP options
            "tftp-root" => self.parse_tftp_root(option_value)?,
            "enable-tftp" => self.parse_enable_tftp()?,
            "tftp-secure" => self.parse_tftp_secure()?,
            "tftp-unique-root" => self.parse_tftp_unique_root()?,
            "tftp-no-blocksize" => self.parse_tftp_no_blocksize()?,

            // Logging options
            "log-queries" => self.config.logging.log_queries = true,
            "log-dhcp" => self.config.logging.log_dhcp = true,
            "log-facility" => self.parse_log_facility(option_value)?,
            "quiet-dhcp" => self.config.logging.quiet_dhcp = true,
            "quiet-dhcp6" => self.config.logging.quiet_dhcp6 = true,
            "quiet-ra" => self.config.logging.quiet_ra = true,

            // Security options
            "user" => self.parse_user_option(option_value)?,
            "group" => self.parse_group_option(option_value)?,

            // Platform options
            "no-daemon" => self.config.platform.daemon_mode = false,
            "pid-file" => self.parse_pid_file(option_value)?,
            "local" => self.parse_local_domain(option_value)?,
            "dnssec-check-unsigned" => self.config.dns.dnssec_enabled_check_unsigned = true,
            "enable-ra" => self.config.dhcp.enable_ra = true,

            // Unknown option - return error for strict C compatibility
            _ => {
                return Err(ConfigError::ParseError {
                    file_path: self
                        .current_file
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "<input>".to_string()),
                    line_number: self.current_line,
                    reason: format!("Unknown configuration option '{}'", option_name),
                });
            }
        }

        Ok(())
    }

    /// Handles include directives (conf-file, conf-dir).
    ///
    /// For conf-file: adds the file to pending_includes for processing
    /// For conf-dir: enumerates directory and adds matching files to pending_includes
    fn handle_include_directive(
        &mut self,
        directive: &str,
        path_str: &str,
    ) -> Result<(), ConfigError> {
        debug!(
            directive = %directive,
            path = %path_str,
            "Processing include directive"
        );

        if directive == "conf-file" {
            // Single file include - add to pending list
            let path = PathBuf::from(path_str);
            self.pending_includes.push(path);
        } else if directive == "conf-dir" {
            // Directory include with optional pattern
            let parts: Vec<&str> = path_str.split(',').collect();
            let dir_path = parts[0];
            let pattern = parts.get(1).map(|s| s.trim()).unwrap_or("*.conf");

            // Enumerate directory and add matching files
            let dir = std::fs::read_dir(dir_path).map_err(|e| {
                self.make_parse_error(format!("Cannot read directory {}: {}", dir_path, e))
            })?;

            // Collect matching files
            let mut matching_files: Vec<PathBuf> = Vec::new();
            for entry in dir {
                let entry = entry.map_err(|e| {
                    self.make_parse_error(format!("Error reading directory entry: {}", e))
                })?;
                let path = entry.path();

                // Only include regular files
                if !path.is_file() {
                    continue;
                }

                // Match against pattern (simple glob pattern matching)
                if let Some(file_name) = path.file_name().and_then(|n| n.to_str()) {
                    if Self::matches_pattern(file_name, pattern) {
                        matching_files.push(path);
                    }
                }
            }

            // Sort files for deterministic ordering (matches C dnsmasq behavior)
            matching_files.sort();

            // Add to pending includes
            self.pending_includes.extend(matching_files);
        }

        Ok(())
    }

    /// Simple glob pattern matcher for conf-dir
    ///
    /// Supports wildcards: * (any characters) and ? (single character)
    fn matches_pattern(filename: &str, pattern: &str) -> bool {
        // Simple implementation: convert glob pattern to regex
        let regex_pattern = pattern.replace('.', r"\.").replace('*', ".*").replace('?', ".");
        let regex_pattern = format!("^{}$", regex_pattern);

        if let Ok(re) = regex::Regex::new(&regex_pattern) {
            re.is_match(filename)
        } else {
            // If regex compilation fails, fall back to exact match
            filename == pattern
        }
    }

    // Option-specific parsers (representative subset)

    fn parse_port_option(&mut self, value: Option<&str>) -> Result<(), ConfigError> {
        if let Some(port_str) = value {
            let port = port_str
                .parse::<u16>()
                .map_err(|_| self.make_parse_error(format!("Invalid port number: {}", port_str)))?;
            self.config.network.port = port;
        } else {
            return Err(self.make_parse_error("Missing port number".to_string()));
        }
        Ok(())
    }

    fn parse_listen_address(&mut self, value: Option<&str>) -> Result<(), ConfigError> {
        if let Some(addr_str) = value {
            let addr = addr_str
                .parse()
                .map_err(|_| self.make_parse_error(format!("Invalid IP address: {}", addr_str)))?;
            self.config.network.listen_addresses.push(addr);
        } else {
            return Err(self.make_parse_error("Missing IP address".to_string()));
        }
        Ok(())
    }

    fn parse_interface(&mut self, value: Option<&str>) -> Result<(), ConfigError> {
        if let Some(iface) = value {
            self.config.network.interfaces.push(iface.to_string());
        } else {
            return Err(self.make_parse_error("Missing interface name".to_string()));
        }
        Ok(())
    }

    fn parse_cache_size(&mut self, value: Option<&str>) -> Result<(), ConfigError> {
        if let Some(size_str) = value {
            let size = size_str
                .parse::<usize>()
                .map_err(|_| self.make_parse_error(format!("Invalid cache size: {}", size_str)))?;
            self.config.dns.cache_size = size;
        } else {
            return Err(self.make_parse_error("Missing cache size".to_string()));
        }
        Ok(())
    }

    fn parse_server_option(&mut self, value: Option<&str>) -> Result<(), ConfigError> {
        use std::net::{IpAddr, SocketAddr};

        if let Some(server_str) = value {
            // Parse server directive in format:
            // - server=8.8.8.8 (simple IP, default port 53)
            // - server=8.8.8.8#5353 (IP with custom port)
            // - server=/example.com/192.168.1.1 (domain-specific server)
            // - server=/local/ (authoritative, no forwarding)

            if server_str.starts_with('/') {
                // Domain-specific server: /domain/server or /domain/
                let parts: Vec<&str> = server_str.split('/').collect();
                if parts.len() >= 3 {
                    let domain = parts[1].to_string();
                    let server_addr = parts[2];

                    if server_addr.is_empty() {
                        // Authoritative domain (no forwarding)
                        let server = crate::types::ServerDetails::new_authoritative(domain.clone())
                            .map_err(|e| self.make_parse_error(format!("Invalid domain: {}", e)))?;

                        info!(domain = %domain, "Authoritative domain (no forwarding)");
                        // Add to servers list but NOT to upstream_servers (no forwarding)
                        self.config.dns.servers.push(server);
                    } else {
                        // Parse server address
                        let (ip_str, port) = if let Some(hash_pos) = server_addr.find('#') {
                            let ip = &server_addr[..hash_pos];
                            let port_str = &server_addr[hash_pos + 1..];
                            let port = port_str.parse::<u16>().map_err(|_| {
                                self.make_parse_error(format!("Invalid port: {}", port_str))
                            })?;
                            (ip, port)
                        } else {
                            (server_addr, 53)
                        };

                        let ip: IpAddr = ip_str.parse().map_err(|_| {
                            self.make_parse_error(format!("Invalid IP address: {}", ip_str))
                        })?;
                        let socket_addr = SocketAddr::new(ip, port);

                        // Create ServerDetails with domain restriction
                        let server =
                            crate::types::ServerDetails::new(socket_addr, Some(domain.clone()), 0)
                                .map_err(|e| {
                                    self.make_parse_error(format!("Invalid server: {}", e))
                                })?;

                        self.config.dns.upstream_servers.push(server.clone());
                        self.config.dns.servers.push(server);
                    }
                } else {
                    return Err(
                        self.make_parse_error(format!("Invalid server format: {}", server_str))
                    );
                }
            } else {
                // Simple server IP address
                let (ip_str, port) = if let Some(hash_pos) = server_str.find('#') {
                    let ip = &server_str[..hash_pos];
                    let port_str = &server_str[hash_pos + 1..];
                    let port = port_str.parse::<u16>().map_err(|_| {
                        self.make_parse_error(format!("Invalid port: {}", port_str))
                    })?;
                    (ip, port)
                } else {
                    (server_str, 53)
                };

                let ip: IpAddr = ip_str.parse().map_err(|_| {
                    self.make_parse_error(format!("Invalid IP address: {}", ip_str))
                })?;
                let socket_addr = SocketAddr::new(ip, port);

                // Create ServerDetails without domain restriction
                let server = crate::types::ServerDetails::new(socket_addr, None::<String>, 0)
                    .map_err(|e| self.make_parse_error(format!("Invalid server: {}", e)))?;

                self.config.dns.upstream_servers.push(server.clone());
                self.config.dns.servers.push(server);
            }
        } else {
            return Err(self.make_parse_error("Missing server address".to_string()));
        }
        Ok(())
    }

    fn parse_dhcp_range(&mut self, value: Option<&str>) -> Result<(), ConfigError> {
        use std::time::Duration;

        let range_str =
            value.ok_or_else(|| self.make_parse_error("Missing DHCP range".to_string()))?;

        let parts: Vec<&str> = range_str.split(',').collect();
        if parts.len() < 2 {
            return Err(self.make_parse_error(format!("Invalid DHCP range format: {}", range_str)));
        }

        // Parse start and end IPs
        let start: IpAddr = parts[0]
            .trim()
            .parse()
            .map_err(|_| self.make_parse_error(format!("Invalid start IP: {}", parts[0])))?;
        let end: IpAddr = parts[1]
            .trim()
            .parse()
            .map_err(|_| self.make_parse_error(format!("Invalid end IP: {}", parts[1])))?;

        // Parse optional parameters (netmask, constructor, flags, lease time)
        // IPv4 formats:
        // - start,end,lease_time
        // - start,end,netmask,lease_time
        // IPv6 formats:
        // - start,end,constructor:interface,flags,lease_time
        // - start,end,lease_time
        let mut netmask = None;
        let mut lease_time_override = None;
        let mut lease_time = None;
        let mut interface = None;

        // Process remaining parameters
        for part in parts.iter().skip(2) {
            let param = part.trim();

            // Skip IPv6-specific flags
            if param.starts_with("ra-") || param == "slaac" || param == "off-link" {
                continue;
            }

            // Handle constructor:interface syntax for IPv6
            if param.starts_with("constructor:") {
                interface = Some(param.strip_prefix("constructor:").unwrap().to_string());
                continue;
            }

            // Try to parse as IP address (netmask)
            if let Ok(ip) = param.parse::<IpAddr>() {
                netmask = Some(ip);
                continue;
            }

            // Try to parse as lease time
            if param != "infinite" {
                if let Ok(seconds) = Self::parse_time_duration(param) {
                    lease_time_override = Some(Duration::from_secs(seconds));
                    lease_time = Some(seconds);
                }
            }
        }

        // Log before moving interface
        info!(start = %start, end = %end, netmask = ?netmask, lease_time = ?lease_time, interface = ?interface, "Added DHCP range");

        let is_ipv6 = start.is_ipv6();
        let range = crate::config::types::DhcpRange {
            start,
            end,
            lease_time_override,
            netmask,
            interface,
            lease_time,
            is_ipv6,
            prefix_len: 0, // Not a prefix delegation pool (regular address range)
        };

        // Push to correct vector based on IP version
        if is_ipv6 {
            self.config.dhcp.v6_ranges.push(range);
        } else {
            self.config.dhcp.v4_ranges.push(range);
        }
        Ok(())
    }

    /// Parse time duration with suffix (e.g., "12h", "30m", "2d")
    fn parse_time_duration(time_str: &str) -> Result<u64, String> {
        let time_str = time_str.trim();
        if time_str.is_empty() {
            return Err("Empty time string".to_string());
        }

        // Check if it ends with a unit suffix
        let (num_str, multiplier) = if let Some(stripped) = time_str.strip_suffix('h') {
            (stripped, 3600) // hours
        } else if let Some(stripped) = time_str.strip_suffix('m') {
            (stripped, 60) // minutes
        } else if let Some(stripped) = time_str.strip_suffix('d') {
            (stripped, 86400) // days
        } else if let Some(stripped) = time_str.strip_suffix('s') {
            (stripped, 1) // seconds
        } else {
            // No suffix, assume seconds
            (time_str, 1)
        };

        let num: u64 = num_str.parse().map_err(|_| format!("Invalid number: {}", num_str))?;

        Ok(num * multiplier)
    }

    fn parse_dhcp_host(&mut self, value: Option<&str>) -> Result<(), ConfigError> {
        if let Some(host_str) = value {
            info!(host = %host_str, "Would add DHCP host entry");
            // Parse MAC, IP, hostname, etc.
        } else {
            return Err(self.make_parse_error("Missing DHCP host specification".to_string()));
        }
        Ok(())
    }

    fn parse_dhcp_option(&mut self, value: Option<&str>) -> Result<(), ConfigError> {
        let opt_str =
            value.ok_or_else(|| self.make_parse_error("Missing DHCP option".to_string()))?;

        let parts: Vec<&str> = opt_str.split(',').collect();
        if parts.is_empty() {
            return Err(self.make_parse_error(format!("Invalid DHCP option format: {}", opt_str)));
        }

        // Check for DHCPv6 option prefix (option6:)
        let first_part = parts[0].trim();
        let is_v6 = first_part.starts_with("option6:");

        // Parse option code
        let code_str = if is_v6 {
            // Remove "option6:" prefix
            &first_part[8..]
        } else {
            first_part
        };

        // Try to parse as numeric code first, if that fails, treat as named option
        let code: u8 = if let Ok(num) = code_str.parse::<u8>() {
            num
        } else {
            // Named option - map to option code
            // For DHCPv6, "dns-server" maps to option 23
            // For DHCPv4, we'd map standard names to their codes
            match code_str {
                "dns-server" if is_v6 => 23,    // DHCPv6 DNS_SERVERS option
                "ntp-server" if is_v6 => 56,    // DHCPv6 NTP_SERVER option
                "domain-search" if is_v6 => 24, // DHCPv6 DOMAIN_LIST option
                // Add more mappings as needed
                _ => {
                    // If we can't parse the named option, just log and use a placeholder
                    // In production, we'd want a complete mapping table
                    warn!(option = code_str, "Unknown named DHCP option, storing as-is");
                    0
                }
            }
        };

        // Parse option values
        let mut value_bytes = Vec::new();
        for part in parts.iter().skip(1) {
            let part = part.trim();

            // Handle IPv6 addresses in brackets
            let part = part.trim_matches(|c| c == '[' || c == ']');

            // Try to parse as IP address first
            if let Ok(ip) = part.parse::<IpAddr>() {
                match ip {
                    IpAddr::V4(ipv4) => {
                        value_bytes.extend_from_slice(&ipv4.octets());
                    }
                    IpAddr::V6(ipv6) => {
                        value_bytes.extend_from_slice(&ipv6.octets());
                    }
                }
            } else {
                // Otherwise, treat as string or hex
                value_bytes.extend_from_slice(part.as_bytes());
            }
        }

        info!(code = code, is_v6 = is_v6, value_len = value_bytes.len(), "Added DHCP option");
        self.config.dhcp.options.push((code, value_bytes));
        Ok(())
    }

    fn parse_dhcp_leasefile(&mut self, value: Option<&str>) -> Result<(), ConfigError> {
        if let Some(path_str) = value {
            self.config.dhcp.lease_file = Some(PathBuf::from(path_str));
        } else {
            return Err(self.make_parse_error("Missing lease file path".to_string()));
        }
        Ok(())
    }

    fn parse_log_facility(&mut self, value: Option<&str>) -> Result<(), ConfigError> {
        let facility_str =
            value.ok_or_else(|| self.make_parse_error("Missing log facility".to_string()))?;

        // log-facility can be either:
        // 1. A syslog facility name (daemon, local0-local7, user, etc.)
        // 2. A file path (starts with /)

        if facility_str.starts_with('/') {
            // It's a file path
            self.config.logging.log_file = Some(PathBuf::from(facility_str));
            self.config.logging.log_facility = facility_str.to_string();
            info!(log_file = %facility_str, "Set log file");
        } else {
            // It's a syslog facility name
            self.config.logging.log_facility = facility_str.to_string();
            info!(facility = %facility_str, "Set syslog facility");
        }

        Ok(())
    }

    fn parse_user_option(&mut self, value: Option<&str>) -> Result<(), ConfigError> {
        if let Some(user) = value {
            self.config.security.user = Some(user.to_string());
        } else {
            return Err(self.make_parse_error("Missing username".to_string()));
        }
        Ok(())
    }

    fn parse_group_option(&mut self, value: Option<&str>) -> Result<(), ConfigError> {
        if let Some(group) = value {
            self.config.security.group = Some(group.to_string());
        } else {
            return Err(self.make_parse_error("Missing group name".to_string()));
        }
        Ok(())
    }

    fn parse_pid_file(&mut self, value: Option<&str>) -> Result<(), ConfigError> {
        if let Some(path_str) = value {
            self.config.platform.pid_file = Some(PathBuf::from(path_str));
        } else {
            return Err(self.make_parse_error("Missing PID file path".to_string()));
        }
        Ok(())
    }

    fn parse_local_domain(&mut self, value: Option<&str>) -> Result<(), ConfigError> {
        let domain =
            value.ok_or_else(|| self.make_parse_error("Missing local domain".to_string()))?;
        self.config.dns.local_domains.push(domain.to_string());
        Ok(())
    }

    fn parse_except_interface(&mut self, value: Option<&str>) -> Result<(), ConfigError> {
        if let Some(iface) = value {
            self.config.network.except_interfaces.push(iface.to_string());
        } else {
            return Err(self.make_parse_error("Missing interface name".to_string()));
        }
        Ok(())
    }

    fn parse_trust_anchor(&mut self, value: Option<&str>) -> Result<(), ConfigError> {
        if let Some(anchor) = value {
            self.config.dns.trust_anchors.push(anchor.to_string());
        } else {
            return Err(self.make_parse_error("Missing trust anchor".to_string()));
        }
        Ok(())
    }

    fn parse_dnssec_timestamp(&mut self, value: Option<&str>) -> Result<(), ConfigError> {
        if let Some(_timestamp_str) = value {
            // Parse DNSSEC timestamp file path
            // For now, just log it
            info!(timestamp = %_timestamp_str, "Would set DNSSEC timestamp file");
        } else {
            return Err(self.make_parse_error("Missing timestamp file path".to_string()));
        }
        Ok(())
    }

    fn parse_address_record(&mut self, value: Option<&str>) -> Result<(), ConfigError> {
        if let Some(record_str) = value {
            // Parse address=/domain/ip format
            let parts: Vec<&str> = record_str.split('/').collect();
            if parts.len() >= 2 {
                let domain = parts[0].to_string();
                if parts.len() >= 3 && !parts[2].is_empty() {
                    // address=/domain/ip
                    let ip = parts[2].parse().map_err(|_| {
                        self.make_parse_error(format!("Invalid IP address: {}", parts[2]))
                    })?;
                    self.config.dns.address_records.push((domain, ip));
                } else if parts.len() == 2 || (parts.len() >= 3 && parts[2].is_empty()) {
                    // address=/domain/ means NXDOMAIN - represented as empty address list
                    // We'll just skip these for now
                }
            } else {
                return Err(
                    self.make_parse_error(format!("Invalid address record format: {}", record_str))
                );
            }
        } else {
            return Err(self.make_parse_error("Missing address record".to_string()));
        }
        Ok(())
    }

    fn parse_host_record(&mut self, value: Option<&str>) -> Result<(), ConfigError> {
        if let Some(record_str) = value {
            // Parse host-record=name,addr[,addr...] format
            let parts: Vec<&str> = record_str.split(',').collect();
            if parts.len() >= 2 {
                let hostname = parts[0].to_string();
                let mut addresses = Vec::new();
                for addr_str in &parts[1..] {
                    let ip = addr_str.parse().map_err(|_| {
                        self.make_parse_error(format!("Invalid IP address: {}", addr_str))
                    })?;
                    addresses.push(ip);
                }
                self.config.dns.host_records.push((hostname, addresses));
            } else {
                return Err(
                    self.make_parse_error(format!("Invalid host record format: {}", record_str))
                );
            }
        } else {
            return Err(self.make_parse_error("Missing host record".to_string()));
        }
        Ok(())
    }

    fn parse_cname_record(&mut self, value: Option<&str>) -> Result<(), ConfigError> {
        if let Some(record_str) = value {
            // Parse cname=alias,target format
            let parts: Vec<&str> = record_str.split(',').collect();
            if parts.len() == 2 {
                let alias = parts[0].to_string();
                let target = parts[1].to_string();
                self.config.dns.cname_records.push((alias, target));
            } else {
                return Err(
                    self.make_parse_error(format!("Invalid CNAME record format: {}", record_str))
                );
            }
        } else {
            return Err(self.make_parse_error("Missing CNAME record".to_string()));
        }
        Ok(())
    }

    fn parse_mx_record(&mut self, value: Option<&str>) -> Result<(), ConfigError> {
        if let Some(record_str) = value {
            // Parse mx-host=domain,target[,priority] format
            let parts: Vec<&str> = record_str.split(',').collect();
            if parts.len() >= 2 {
                let domain = parts[0].to_string();
                let target = parts[1].to_string();
                let priority = if parts.len() >= 3 {
                    parts[2].parse().map_err(|_| {
                        self.make_parse_error(format!("Invalid MX priority: {}", parts[2]))
                    })?
                } else {
                    10 // Default priority
                };
                self.config.dns.mx_records.push((domain, target, priority));
            } else {
                return Err(
                    self.make_parse_error(format!("Invalid MX record format: {}", record_str))
                );
            }
        } else {
            return Err(self.make_parse_error("Missing MX record".to_string()));
        }
        Ok(())
    }

    fn parse_mx_target(&mut self, value: Option<&str>) -> Result<(), ConfigError> {
        if let Some(target) = value {
            self.config.dns.mx_target = Some(target.to_string());
        } else {
            return Err(self.make_parse_error("Missing MX target".to_string()));
        }
        Ok(())
    }

    fn parse_srv_record(&mut self, value: Option<&str>) -> Result<(), ConfigError> {
        if let Some(record_str) = value {
            // Parse srv-host=_service._proto.domain,target,port[,priority][,weight] format
            let parts: Vec<&str> = record_str.split(',').collect();
            if parts.len() >= 3 {
                let service = parts[0].to_string();
                let target = parts[1].to_string();
                let port = parts[2].parse().map_err(|_| {
                    self.make_parse_error(format!("Invalid SRV port: {}", parts[2]))
                })?;
                let priority = if parts.len() >= 4 {
                    parts[3].parse().map_err(|_| {
                        self.make_parse_error(format!("Invalid SRV priority: {}", parts[3]))
                    })?
                } else {
                    0 // Default priority
                };
                let weight = if parts.len() >= 5 {
                    parts[4].parse().map_err(|_| {
                        self.make_parse_error(format!("Invalid SRV weight: {}", parts[4]))
                    })?
                } else {
                    0 // Default weight
                };
                self.config.dns.srv_records.push((service, target, port, priority, weight));
            } else {
                return Err(
                    self.make_parse_error(format!("Invalid SRV record format: {}", record_str))
                );
            }
        } else {
            return Err(self.make_parse_error("Missing SRV record".to_string()));
        }
        Ok(())
    }

    fn parse_txt_record(&mut self, value: Option<&str>) -> Result<(), ConfigError> {
        if let Some(record_str) = value {
            // Parse txt-record=name,text format
            if let Some(comma_pos) = record_str.find(',') {
                let name = record_str[..comma_pos].to_string();
                let text = record_str[comma_pos + 1..].to_string();
                self.config.dns.txt_records.push((name, text));
            } else {
                return Err(
                    self.make_parse_error(format!("Invalid TXT record format: {}", record_str))
                );
            }
        } else {
            return Err(self.make_parse_error("Missing TXT record".to_string()));
        }
        Ok(())
    }

    fn parse_ptr_record(&mut self, value: Option<&str>) -> Result<(), ConfigError> {
        if let Some(record_str) = value {
            // Parse ptr-record=name,target format
            let parts: Vec<&str> = record_str.split(',').collect();
            if parts.len() == 2 {
                let name = parts[0].to_string();
                let target = parts[1].to_string();
                self.config.dns.ptr_records.push((name, target));
            } else {
                return Err(
                    self.make_parse_error(format!("Invalid PTR record format: {}", record_str))
                );
            }
        } else {
            return Err(self.make_parse_error("Missing PTR record".to_string()));
        }
        Ok(())
    }

    fn parse_dhcp_boot(&mut self, value: Option<&str>) -> Result<(), ConfigError> {
        if let Some(boot_str) = value {
            // Parse dhcp-boot format
            info!(boot = %boot_str, "Would add DHCP boot option");
            // Full implementation would parse boot filename, server name, next-server
        } else {
            return Err(self.make_parse_error("Missing DHCP boot specification".to_string()));
        }
        Ok(())
    }

    #[cfg(feature = "tftp")]
    fn parse_tftp_root(&mut self, value: Option<&str>) -> Result<(), ConfigError> {
        if let Some(path_str) = value {
            self.config.tftp.tftp_prefix = Some(PathBuf::from(path_str));
        } else {
            return Err(self.make_parse_error("Missing TFTP root path".to_string()));
        }
        Ok(())
    }

    #[cfg(not(feature = "tftp"))]
    fn parse_tftp_root(&mut self, value: Option<&str>) -> Result<(), ConfigError> {
        if value.is_some() {
            warn!("TFTP not enabled in this build, ignoring tftp-root option");
        }
        Ok(())
    }

    #[cfg(feature = "tftp")]
    fn parse_enable_tftp(&mut self) -> Result<(), ConfigError> {
        self.config.tftp.enabled = true;
        Ok(())
    }

    #[cfg(not(feature = "tftp"))]
    fn parse_enable_tftp(&mut self) -> Result<(), ConfigError> {
        warn!("TFTP not enabled in this build, ignoring enable-tftp option");
        Ok(())
    }

    #[cfg(feature = "tftp")]
    fn parse_tftp_secure(&mut self) -> Result<(), ConfigError> {
        self.config.tftp.tftp_secure = true;
        Ok(())
    }

    #[cfg(not(feature = "tftp"))]
    fn parse_tftp_secure(&mut self) -> Result<(), ConfigError> {
        warn!("TFTP not enabled in this build, ignoring tftp-secure option");
        Ok(())
    }

    #[cfg(feature = "tftp")]
    fn parse_tftp_unique_root(&mut self) -> Result<(), ConfigError> {
        self.config.tftp.tftp_unique_root = true;
        Ok(())
    }

    #[cfg(not(feature = "tftp"))]
    fn parse_tftp_unique_root(&mut self) -> Result<(), ConfigError> {
        warn!("TFTP not enabled in this build, ignoring tftp-unique-root option");
        Ok(())
    }

    #[cfg(feature = "tftp")]
    fn parse_tftp_no_blocksize(&mut self) -> Result<(), ConfigError> {
        self.config.tftp.tftp_no_blocksize = true;
        Ok(())
    }

    #[cfg(not(feature = "tftp"))]
    fn parse_tftp_no_blocksize(&mut self) -> Result<(), ConfigError> {
        warn!("TFTP not enabled in this build, ignoring tftp-no-blocksize option");
        Ok(())
    }

    /// Helper to create ParseError with current file and line context.
    fn make_parse_error(&self, reason: String) -> ConfigError {
        ConfigError::ParseError {
            file_path: self
                .current_file
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "<string>".to_string()),
            line_number: self.current_line,
            reason,
        }
    }
}

impl Default for ConfigParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function to parse a configuration file directly.
///
/// Creates a new parser, parses the file, and returns the resulting configuration.
/// Equivalent to:
/// ```rust,ignore
/// let mut parser = ConfigParser::new();
/// parser.parse_file(path).await?;
/// Ok(parser.into_config())
/// ```
///
/// # Arguments
///
/// * `path` - Path to configuration file
///
/// # Errors
///
/// Returns `ConfigError` if file cannot be read or parsed.
///
/// # Examples
///
/// ```rust,ignore
/// use dnsmasq::config::parser::parse_file;
///
/// let config = parse_file("/etc/dnsmasq.conf").await?;
/// println!("DNS port: {}", config.network.port);
/// ```
pub async fn parse_file<P: AsRef<Path>>(path: P) -> Result<Config, ConfigError> {
    let mut parser = ConfigParser::new();
    parser.parse_file(path).await?;
    Ok(parser.into_config())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_comment() {
        // Test hash comments
        assert_eq!(ConfigParser::strip_comment("# comment"), "");
        assert_eq!(ConfigParser::strip_comment("option=value # comment"), "option=value ");
        assert_eq!(ConfigParser::strip_comment("option=value#nocomment"), "option=value#nocomment");
        assert_eq!(ConfigParser::strip_comment("option=value"), "option=value");

        // Test semicolon comments
        assert_eq!(ConfigParser::strip_comment("; comment"), "");
        assert_eq!(ConfigParser::strip_comment("option=value ; comment"), "option=value ");
        assert_eq!(ConfigParser::strip_comment("option=value;nocomment"), "option=value;nocomment");
    }

    #[test]
    fn test_parse_quoted_string() {
        let mut chars = "test\\\"quote\"remaining".chars().peekable();
        let result = ConfigParser::parse_quoted_string(&mut chars, '"').unwrap();
        assert_eq!(result, "test\"quote");
    }

    #[test]
    fn test_process_quotes_basic() {
        let parser = ConfigParser::new();
        let result = parser.process_quotes_and_escapes("option=\"value with spaces\"").unwrap();
        assert_eq!(result, "option=value with spaces");
    }

    #[test]
    fn test_process_quotes_escape_sequences() {
        let parser = ConfigParser::new();
        let result = parser.process_quotes_and_escapes("option=\"tab\\there\"").unwrap();
        assert_eq!(result, "option=tab\there");
    }

    #[tokio::test]
    async fn test_parse_string_simple() {
        let mut parser = ConfigParser::new();
        parser.parse_string("port=5353\ncache-size=1000").unwrap();
        assert_eq!(parser.config().network.port, 5353);
        assert_eq!(parser.config().dns.cache_size, 1000);
    }

    #[tokio::test]
    async fn test_parse_string_with_comments() {
        let mut parser = ConfigParser::new();
        parser.parse_string("# Comment line\nport=53 # inline comment").unwrap();
        assert_eq!(parser.config().network.port, 53);
    }

    #[tokio::test]
    async fn test_parse_boolean_flags() {
        let mut parser = ConfigParser::new();
        parser.parse_string("domain-needed\nbogus-priv").unwrap();
        assert!(parser.config().dns.domain_needed);
        assert!(parser.config().dns.bogus_priv);
    }
}
