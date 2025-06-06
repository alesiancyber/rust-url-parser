use crate::{ComprehensiveUrlAnalyzer, UrlAnalyzer, analyze_url, analyze_urls};

#[test]
fn test_analyze_co_uk_domain() -> Result<(), Box<dyn std::error::Error>> {
    let analyzer = ComprehensiveUrlAnalyzer::new();
    let analysis = analyzer.analyze("https://subdomain.domain.co.uk")?;
    
    assert_eq!(analysis.tld_components.subdomain, Some("subdomain".to_string()));
    assert_eq!(analysis.tld_components.domain, Some("domain".to_string()));
    assert_eq!(analysis.tld_components.suffix, Some("co.uk".to_string()));
    assert_eq!(analysis.url_components.scheme, "https");
    
    Ok(())
}

#[test]
fn test_analyze_with_query_params() -> Result<(), Box<dyn std::error::Error>> {
    let analyzer = ComprehensiveUrlAnalyzer::new();
    let analysis = analyzer.analyze("https://example.com/path?key=value&foo=bar")?;
    
    assert_eq!(analysis.url_components.query_params.len(), 2);
    assert!(analysis.url_components.query_params.contains(&("key".to_string(), "value".to_string())));
    assert!(analysis.url_components.query_params.contains(&("foo".to_string(), "bar".to_string())));
    
    Ok(())
}

#[test]
fn test_analyze_with_path_segments() -> Result<(), Box<dyn std::error::Error>> {
    let analyzer = ComprehensiveUrlAnalyzer::new();
    let analysis = analyzer.analyze("https://example.com/api/v1/users")?;
    
    assert_eq!(analysis.url_components.path_segments, vec!["api", "v1", "users"]);
    
    Ok(())
}

#[test]
fn test_convenience_functions() -> Result<(), Box<dyn std::error::Error>> {
    // Test single URL analysis
    let analysis = analyze_url("https://example.com")?;
    assert_eq!(analysis.url_components.scheme, "https");
    
    // Test multiple URL analysis
    let urls = &["https://example.com", "https://test.org"];
    let results = analyze_urls(urls);
    assert_eq!(results.len(), 2);
    assert!(results[0].is_ok());
    assert!(results[1].is_ok());
    
    Ok(())
}

#[test]
fn test_complex_nested_url_analysis() -> Result<(), Box<dyn std::error::Error>> {
    let complex_url = "https://proxy.domain.com/api/v1/redirect/facebook.com/profile?fallback=https://twitter.com&backup=linkedin.com&final=https://github.com/user";
    
    let analysis = analyze_url(complex_url)?;
    
    // Check main URL components
    assert_eq!(analysis.url_components.scheme, "https");
    assert_eq!(analysis.url_components.host, Some("proxy.domain.com".to_string()));
    assert_eq!(analysis.tld_components.domain, Some("domain".to_string()));
    assert_eq!(analysis.tld_components.suffix, Some("com".to_string()));
    
    // Check that embedded domains are in query params
    assert!(analysis.url_components.query_params.iter().any(|(_, v)| v.contains("twitter.com")));
    assert!(analysis.url_components.query_params.iter().any(|(_, v)| v.contains("github.com")));
    
    // Check path segments contain embedded domain
    assert!(analysis.url_components.path_segments.contains(&"facebook.com".to_string()));
    
    Ok(())
}

#[test]
fn test_encoded_url_analysis() -> Result<(), Box<dyn std::error::Error>> {
    let encoded_url = "https://encoded.redirect.com/api%2Fproxy%2Fgithub.com%2Fuser/redirect?primary=https%3A%2F%2Fexample.com%2Fpath%3Fquery%3Dtest&secondary=http%3A%2F%2Ffacebook.com";
    
    let analysis = analyze_url(encoded_url)?;
    
    // Main URL should be parsed correctly
    assert_eq!(analysis.url_components.scheme, "https");
    assert_eq!(analysis.url_components.host, Some("encoded.redirect.com".to_string()));
    assert_eq!(analysis.tld_components.domain, Some("redirect".to_string()));
    
    // Query parameters should contain URL-encoded URLs
    assert!(analysis.url_components.query_params.iter().any(|(_, v)| v.contains("example.com")));
    assert!(analysis.url_components.query_params.iter().any(|(_, v)| v.contains("facebook.com")));
    
    Ok(())
}

#[test]
fn test_authentication_url_analysis() -> Result<(), Box<dyn std::error::Error>> {
    let auth_url = "https://admin:secret123@auth.proxy.com/redirect?target1=https://user1:pass1@database.example.com/api";
    
    let analysis = analyze_url(auth_url)?;
    
    // Check main URL authentication
    assert_eq!(analysis.url_components.username, "admin");
    assert_eq!(analysis.url_components.password, Some("secret123".to_string()));
    assert_eq!(analysis.url_components.host, Some("auth.proxy.com".to_string()));
    
    // Check that embedded authenticated URL is in query params
    assert!(analysis.url_components.query_params.iter().any(|(_, v)| v.contains("user1:pass1")));
    assert!(analysis.url_components.query_params.iter().any(|(_, v)| v.contains("database.example.com")));
    
    Ok(())
}

#[test]
fn test_various_schemes() -> Result<(), Box<dyn std::error::Error>> {
    let test_urls = vec![
        ("https://example.com", "https"),
        ("http://example.com", "http"),
        ("ftp://files.example.com", "ftp"),
    ];
    
    for (url, expected_scheme) in test_urls {
        let analysis = analyze_url(url)?;
        assert_eq!(analysis.url_components.scheme, expected_scheme);
    }
    
    Ok(())
}

#[test]
fn test_error_handling() {
    // Test invalid URL
    let result = analyze_url("not-a-valid-url");
    assert!(result.is_err());
    
    // Test multiple URLs with some invalid
    let urls = &["https://valid.com", "invalid-url", "https://another-valid.com"];
    let results = analyze_urls(urls);
    
    assert_eq!(results.len(), 3);
    assert!(results[0].is_ok());
    assert!(results[1].is_err());
    assert!(results[2].is_ok());
} 