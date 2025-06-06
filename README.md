# Rust URL Parser

A comprehensive URL parsing tool built with Rust using the `url` and `tldextract` crates.

## Features

- **Complete URL parsing** - extracts all URL components (scheme, host, path, query, fragment, etc.)
- **TLD extraction** - intelligently separates subdomain, domain, and suffix (including multi-level TLDs like `.co.uk`)
- **Query parameter parsing** - automatically decodes and structures query parameters
- **Path segment extraction** - splits paths into individual components
- **Authentication support** - extracts username and password from URLs
- **URL encoding/decoding** - handles percent-encoded URLs automatically
- **Multiple protocols** - supports HTTP, HTTPS, FTP, SFTP, and more
- **Nested URL detection** - finds embedded URLs in query parameters and paths
- **JSON output** - structured, machine-readable results

## Usage

```bash
cargo run
```

## Output Format

The tool outputs JSON with the following structure:

```json
{
  "original_url": "https://example.com/path?param=value",
  "url_components": {
    "scheme": "https",
    "username": "",
    "password": null,
    "host": "example.com",
    "port": null,
    "path": "/path",
    "query": "param=value",
    "fragment": null,
    "query_params": [["param", "value"]],
    "path_segments": ["path"]
  },
  "tld_components": {
    "domain": "example",
    "subdomain": null,
    "suffix": "com"
  }
}
```

## Dependencies

- `url` - Robust URL parsing following web standards
- `tldextract` - Intelligent TLD and domain extraction
- `serde` - Serialization framework for clean JSON output

## Test Cases

The project includes test cases for:
- Basic URL parsing
- Multi-level TLDs (`.co.uk`, etc.)
- URLs with authentication credentials
- URL-encoded parameters
- Nested/embedded URLs
- Multiple protocols (HTTP, HTTPS, FTP, SFTP)

Built with ❤️ in Rust 