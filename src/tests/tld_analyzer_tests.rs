use crate::TldAnalyzer;

#[test]
fn test_tld_analyzer_separately() -> Result<(), Box<dyn std::error::Error>> {
    let tld_analyzer = TldAnalyzer::new();
    let components = tld_analyzer.extract("subdomain.example.com")?;
    
    assert_eq!(components.subdomain, Some("subdomain".to_string()));
    assert_eq!(components.domain, Some("example".to_string()));
    assert_eq!(components.suffix, Some("com".to_string()));
    
    Ok(())
}

#[test]
fn test_tld_analyzer_multi_level_tld() -> Result<(), Box<dyn std::error::Error>> {
    let tld_analyzer = TldAnalyzer::new();
    let components = tld_analyzer.extract("subdomain.domain.co.uk")?;
    
    assert_eq!(components.subdomain, Some("subdomain".to_string()));
    assert_eq!(components.domain, Some("domain".to_string()));
    assert_eq!(components.suffix, Some("co.uk".to_string()));
    
    Ok(())
}

#[test]
fn test_tld_analyzer_no_subdomain() -> Result<(), Box<dyn std::error::Error>> {
    let tld_analyzer = TldAnalyzer::new();
    let components = tld_analyzer.extract("example.com")?;
    
    assert_eq!(components.subdomain, None);
    assert_eq!(components.domain, Some("example".to_string()));
    assert_eq!(components.suffix, Some("com".to_string()));
    
    Ok(())
}

#[test]
fn test_tld_analyzer_multiple_subdomains() -> Result<(), Box<dyn std::error::Error>> {
    let tld_analyzer = TldAnalyzer::new();
    let components = tld_analyzer.extract("api.mail.subdomain.example.org")?;
    
    assert_eq!(components.subdomain, Some("api.mail.subdomain".to_string()));
    assert_eq!(components.domain, Some("example".to_string()));
    assert_eq!(components.suffix, Some("org".to_string()));
    
    Ok(())
}

#[test]
fn test_tld_analyzer_various_tlds() -> Result<(), Box<dyn std::error::Error>> {
    let tld_analyzer = TldAnalyzer::new();
    
    // Test .org
    let components = tld_analyzer.extract("test.example.org")?;
    assert_eq!(components.suffix, Some("org".to_string()));
    
    // Test .net
    let components = tld_analyzer.extract("test.example.net")?;
    assert_eq!(components.suffix, Some("net".to_string()));
    
    // Test .edu
    let components = tld_analyzer.extract("test.university.edu")?;
    assert_eq!(components.suffix, Some("edu".to_string()));
    
    Ok(())
} 