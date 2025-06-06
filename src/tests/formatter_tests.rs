use crate::{ComprehensiveUrlAnalyzer, UrlAnalyzer, OutputFormatter, JsonFormatter, CompactJsonFormatter, WhoisFormatter};

fn create_analyzer() -> ComprehensiveUrlAnalyzer {
    ComprehensiveUrlAnalyzer::new()
}

#[test]
fn test_json_formatters() -> Result<(), Box<dyn std::error::Error>> {
    let analyzer = create_analyzer();
    let analysis = analyzer.analyze("https://example.com")?;
    
    let json_formatter = JsonFormatter;
    let compact_formatter = CompactJsonFormatter;
    
    let pretty_json = json_formatter.format(&analysis)?;
    let compact_json = compact_formatter.format(&analysis)?;
    
    assert!(pretty_json.contains('\n')); // Pretty format has newlines
    assert!(!compact_json.contains('\n')); // Compact format doesn't
    
    Ok(())
}

#[test]
fn test_whois_formatter_basic() -> Result<(), Box<dyn std::error::Error>> {
    let analyzer = create_analyzer();
    let analyses = vec![
        analyzer.analyze("https://subdomain.example.com")?,
        analyzer.analyze("https://test.site.org/redirect?target=https://github.com")?,
    ];
    
    let whois_formatter = WhoisFormatter::new();
    let result = whois_formatter.format(&analyses)?;
    
    assert!(result.contains("example.com"));
    assert!(result.contains("site.org"));
    assert!(result.contains("github.com"));
    
    Ok(())
}

#[test]
fn test_whois_formatter_with_subdomains() -> Result<(), Box<dyn std::error::Error>> {
    let analyzer = create_analyzer();
    let analysis = analyzer.analyze("https://mail.subdomain.example.com")?;
    
    let whois_formatter = WhoisFormatter::new().with_subdomains();
    let result = whois_formatter.format(&analysis)?;
    
    assert!(result.contains("mail.subdomain.example.com"));
    
    Ok(())
}

#[test]
fn test_whois_formatter_extracts_embedded_domains() -> Result<(), Box<dyn std::error::Error>> {
    let analyzer = create_analyzer();
    let analysis = analyzer.analyze("https://proxy.com/api?redirect=https://facebook.com&backup=twitter.com")?;
    
    let whois_formatter = WhoisFormatter::new();
    let result = whois_formatter.format(&analysis)?;
    
    assert!(result.contains("proxy.com"));
    assert!(result.contains("facebook.com"));
    assert!(result.contains("twitter.com"));
    
    Ok(())
}

#[test]
fn test_whois_formatter_extracts_path_domains() -> Result<(), Box<dyn std::error::Error>> {
    let analyzer = create_analyzer();
    let analysis = analyzer.analyze("https://proxy.com/api/github.com/user")?;
    
    let whois_formatter = WhoisFormatter::new();
    let result = whois_formatter.format(&analysis)?;
    
    assert!(result.contains("proxy.com"));
    assert!(result.contains("github.com"));
    
    Ok(())
}

#[test]
fn test_whois_formatter_deduplicates_domains() -> Result<(), Box<dyn std::error::Error>> {
    let analyzer = create_analyzer();
    let analyses = vec![
        analyzer.analyze("https://example.com/path1")?,
        analyzer.analyze("https://subdomain.example.com/path2")?,
        analyzer.analyze("https://other.example.com/path3")?,
    ];
    
    let whois_formatter = WhoisFormatter::new();
    let result = whois_formatter.format(&analyses)?;
    
    // Should only contain example.com once (deduplicated)
    let domain_count = result.lines().filter(|line| *line == "example.com").count();
    assert_eq!(domain_count, 1);
    
    Ok(())
}

#[test]
fn test_whois_formatter_sorts_domains() -> Result<(), Box<dyn std::error::Error>> {
    let analyzer = create_analyzer();
    let analyses = vec![
        analyzer.analyze("https://zebra.com")?,
        analyzer.analyze("https://apple.com")?,
        analyzer.analyze("https://microsoft.com")?,
    ];
    
    let whois_formatter = WhoisFormatter::new();
    let result = whois_formatter.format(&analyses)?;
    
    let lines: Vec<&str> = result.lines().collect();
    assert!(lines[0] < lines[1]); // Should be sorted alphabetically
    assert!(lines[1] < lines[2]);
    
    Ok(())
}

#[test]
fn test_whois_formatter_handles_complex_nested_urls() -> Result<(), Box<dyn std::error::Error>> {
    let analyzer = create_analyzer();
    let analysis = analyzer.analyze("https://redirect.com/api/proxy/github.com/user?fallback=https://twitter.com&backup=linkedin.com")?;
    
    let whois_formatter = WhoisFormatter::new();
    let result = whois_formatter.format(&analysis)?;
    
    assert!(result.contains("redirect.com"));
    assert!(result.contains("github.com"));
    assert!(result.contains("twitter.com"));
    assert!(result.contains("linkedin.com"));
    
    Ok(())
} 