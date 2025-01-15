# Mirage

**Ephemeral File Overlay with FUSE**

Mirage allows you to dynamically overlay file content at runtime using FUSE, without modifying the original file.

---

## Features
- **Static Content Replacement:** Replace file content with a fixed string.
- **Dynamic Content Execution:** Generate file content by running a shell command.
- **Pattern Replacement:** Replace patterns in the original content.
- **Command-based Replacement:** Replace patterns using command output.

---

## Installation

### Prerequisites
- [Rust](https://www.rust-lang.org/tools/install) (for building Mirage)
- **FUSE** (Filesystem in Userspace)
  - **Linux:**
    - Ubuntu/Debian: `sudo apt-get install fuse`
    - Arch Linux: `sudo pacman -S fuse`
    - Fedora: `sudo dnf install fuse`
  - **macOS:**
    ```bash
    brew install macfuse
    ```

### Install Mirage
```bash
cargo install --path .
```

---

## Usage

```bash
mirage <file_path> [OPTIONS]
```

### Options & Examples

- `--content <STRING>`  
  Replace the file's content with the provided string.
  
  **Example:**
  ```bash
  mirage /path/to/file --content "This is fake content!"
  ```

- `--exec <COMMAND>`  
  Use the output of a command as the file content.
  
  **Example:**
  ```bash
  mirage /path/to/file --exec "tr a-z A-Z"
  ```

- `--replace-regex <PATTERN=REPLACEMENT>`  
  Replace all occurrences of `PATTERN` with `REPLACEMENT` in the file content. Can be used multiple times.
  
  **Example:**
  ```bash
  mirage /path/to/file --replace-regex "foo=bar" --replace-regex "baz=qux"
  ```

- `--replace-exec <PATTERN=COMMAND>`  
  Replace occurrences of `PATTERN` by running `COMMAND`. Can be used multiple times.
  
  **Example:**
  ```bash
  mirage /path/to/file --replace-exec "DATE=date +%Y-%m-%d"
  ```

