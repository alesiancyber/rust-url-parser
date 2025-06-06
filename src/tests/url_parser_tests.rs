use crate::UrlParser;

#[test]
fn test_url_parser_separately() -> Result<(), Box<dyn std::error::Error>> {
    let parser = UrlParser::new();
    let (parsed_url, components) = parser.parse("https://example.com/path")?;
    
    assert_eq!(parsed_url.scheme(), "https");
    assert_eq!(components.path, "/path");
    
    Ok(())
}

#[test]
fn test_url_parser_with_authentication() -> Result<(), Box<dyn std::error::Error>> {
    let parser = UrlParser::new();
    let (parsed_url, components) = parser.parse("https://user:pass@example.com/path")?;
    
    assert_eq!(parsed_url.scheme(), "https");
    assert_eq!(components.username, "user");
    assert_eq!(components.password, Some("pass".to_string()));
    
    Ok(())
}

#[test]
fn test_url_parser_with_query_params() -> Result<(), Box<dyn std::error::Error>> {
    let parser = UrlParser::new();
    let (_, components) = parser.parse("https://example.com/path?key=value&foo=bar")?;
    
    assert_eq!(components.query_params.len(), 2);
    assert!(components.query_params.contains(&("key".to_string(), "value".to_string())));
    assert!(components.query_params.contains(&("foo".to_string(), "bar".to_string())));
    
    Ok(())
}

#[test]
fn test_url_parser_with_path_segments() -> Result<(), Box<dyn std::error::Error>> {
    let parser = UrlParser::new();
    let (_, components) = parser.parse("https://example.com/api/v1/users")?;
    
    assert_eq!(components.path_segments, vec!["api", "v1", "users"]);
    
    Ok(())
}

#[test]
fn test_url_parser_edge_cases() -> Result<(), Box<dyn std::error::Error>> {
    let parser = UrlParser::new();
    
    // Test with port
    let (_, components) = parser.parse("https://example.com:8080/path")?;
    assert_eq!(components.port, Some(8080));
    
    // Test with fragment
    let (_, components) = parser.parse("https://example.com/path#section")?;
    assert_eq!(components.fragment, Some("section".to_string()));
    
    // Test FTP
    let (_, components) = parser.parse("ftp://files.example.com/download")?;
    assert_eq!(components.scheme, "ftp");
    
    Ok(())
} 