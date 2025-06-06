use url::Url;
use tldextract::{TldExtractor, TldOption};
use serde::{Serialize, Deserialize};

// ===== TRAITS =====

/// Trait for analyzing URLs
trait UrlAnalyzer {
    type Output;
    type Error;
    
    fn analyze(&self, url: &str) -> Result<Self::Output, Self::Error>;
}

/// Trait for formatting output
trait OutputFormatter<T> {
    type Error;
    
    fn format(&self, data: &T) -> Result<String, Self::Error>;
}

// ===== DATA STRUCTURES =====

#[derive(Serialize, Deserialize, Debug)]
struct UrlAnalysis {
    original_url: String,
    url_components: UrlComponents,
    tld_components: TldComponents,
}

#[derive(Serialize, Deserialize, Debug)]
struct UrlComponents {
    scheme: String,
    username: String,
    password: Option<String>,
    host: Option<String>,
    port: Option<u16>,
    path: String,
    query: Option<String>,
    fragment: Option<String>,
    // Extracted query parameters as key-value pairs
    query_params: Vec<(String, String)>,
    // Path segments split by '/'
    path_segments: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct TldComponents {
    domain: Option<String>,
    subdomain: Option<String>,
    suffix: Option<String>,
}

// ===== URL PARSER (Single Responsibility) =====

/// Handles pure URL parsing without TLD extraction
struct UrlParser;

impl UrlParser {
    fn new() -> Self {
        Self
    }
    
    fn parse(&self, url_str: &str) -> Result<(Url, UrlComponents), Box<dyn std::error::Error>> {
        let parsed_url = Url::parse(url_str)?;
        
        let components = UrlComponents {
            scheme: parsed_url.scheme().to_string(),
            username: parsed_url.username().to_string(),
            password: parsed_url.password().map(|s| s.to_string()),
            host: parsed_url.host_str().map(|s| s.to_string()),
            port: parsed_url.port(),
            path: parsed_url.path().to_string(),
            query: parsed_url.query().map(|s| s.to_string()),
            fragment: parsed_url.fragment().map(|s| s.to_string()),
            query_params: parsed_url.query_pairs()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            path_segments: parsed_url.path_segments()
                .map(|segments| segments.filter(|s| !s.is_empty()).map(|s| s.to_string()).collect())
                .unwrap_or_default(),
        };
        
        Ok((parsed_url, components))
    }
}

// ===== TLD ANALYZER (Single Responsibility) =====

/// Handles TLD extraction separately from URL parsing
struct TldAnalyzer {
    extractor: TldExtractor,
}

impl TldAnalyzer {
    fn new() -> Self {
        Self {
            extractor: TldExtractor::new(TldOption::default()),
        }
    }
    
    fn extract(&self, host: &str) -> Result<TldComponents, Box<dyn std::error::Error>> {
        let extracted = self.extractor.extract(host)?;
        
        Ok(TldComponents {
            domain: extracted.domain.filter(|s| !s.is_empty()),
            subdomain: extracted.subdomain.filter(|s| !s.is_empty()),
            suffix: extracted.suffix.filter(|s| !s.is_empty()),
        })
    }
}

// ===== COMPOSITE ANALYZER =====

/// Combines URL parsing and TLD extraction
struct ComprehensiveUrlAnalyzer {
    url_parser: UrlParser,
    tld_analyzer: TldAnalyzer,
}

impl ComprehensiveUrlAnalyzer {
    fn new() -> Self {
        Self {
            url_parser: UrlParser::new(),
            tld_analyzer: TldAnalyzer::new(),
        }
    }
}

impl UrlAnalyzer for ComprehensiveUrlAnalyzer {
    type Output = UrlAnalysis;
    type Error = Box<dyn std::error::Error>;
    
    fn analyze(&self, url_str: &str) -> Result<Self::Output, Self::Error> {
        let (parsed_url, url_components) = self.url_parser.parse(url_str)?;
        
        let tld_components = if let Some(host) = parsed_url.host_str() {
            self.tld_analyzer.extract(host)?
        } else {
            TldComponents {
                domain: None,
                subdomain: None,
                suffix: None,
            }
        };
        
        Ok(UrlAnalysis {
            original_url: url_str.to_string(),
            url_components,
            tld_components,
        })
    }
}

// ===== OUTPUT FORMATTERS =====

/// JSON formatter
struct JsonFormatter;

impl<T> OutputFormatter<T> for JsonFormatter 
where 
    T: Serialize 
{
    type Error = serde_json::Error;
    
    fn format(&self, data: &T) -> Result<String, Self::Error> {
        serde_json::to_string_pretty(data)
    }
}

/// Compact JSON formatter  
struct CompactJsonFormatter;

impl<T> OutputFormatter<T> for CompactJsonFormatter 
where 
    T: Serialize 
{
    type Error = serde_json::Error;
    
    fn format(&self, data: &T) -> Result<String, Self::Error> {
        serde_json::to_string(data)
    }
}

// ===== MAIN =====

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let test_urls = vec![
        "https://subdomain.domain.co.uk",
        "https://www.example.com",
        "https://mail.google.com",
        "https://api.subdomain.domain.co.uk/path",
        "https://test.subdomain.example.org",
        "https://example.com",
        "https://subdomain.domain.com",
        "https://subdomain.domain.com/redirect?url=google.com",
        "https://subdomain.domain.com/redirect?target=https://google.com",
        "https://proxy.domain.com/proxy/google.com/search",
        "https://complex.redirect.com/api/v1/redirect/facebook.com/profile?fallback=https://twitter.com&backup=linkedin.com&final=https://github.com/user",
        "https://encoded.redirect.com/api%2Fproxy%2Fgithub.com%2Fuser/redirect?primary=https%3A%2F%2Fexample.com%2Fpath%3Fquery%3Dtest&secondary=http%3A%2F%2Ffacebook.com&tertiary=linkedin.com%2Fin%2Fusername&quaternary=https%3A%2F%2Ftwitter.com%2Fuser%3Fref%3Dsearch",
        "https://admin:secret123@auth.proxy.com/redirect?target1=https://user1:pass1@database.example.com/api&target2=http://admin:admin@legacy.system.org/auth",
        "ftp://ftpuser:ftppass@files.company.com/download?backup=https://backup:secure456@backup.site.net/restore&mirror=sftp://mirror:key789@mirror.backup.co.uk/sync",
    ];

    let analyzer = ComprehensiveUrlAnalyzer::new();
    let formatter = JsonFormatter;
    let mut analyses = Vec::new();

    for url_str in test_urls {
        match analyzer.analyze(url_str) {
            Ok(analysis) => analyses.push(analysis),
            Err(e) => eprintln!("Error analyzing {}: {}", url_str, e),
        }
    }

    // Output using formatter trait
    println!("{}", formatter.format(&analyses)?);
    
    Ok(())
}

// ===== TESTS =====

#[cfg(test)]
mod tests {
    use super::*;

    fn create_analyzer() -> ComprehensiveUrlAnalyzer {
        ComprehensiveUrlAnalyzer::new()
    }

    #[test]
    fn test_analyze_co_uk_domain() -> Result<(), Box<dyn std::error::Error>> {
        let analyzer = create_analyzer();
        let analysis = analyzer.analyze("https://subdomain.domain.co.uk")?;
        
        assert_eq!(analysis.tld_components.subdomain, Some("subdomain".to_string()));
        assert_eq!(analysis.tld_components.domain, Some("domain".to_string()));
        assert_eq!(analysis.tld_components.suffix, Some("co.uk".to_string()));
        assert_eq!(analysis.url_components.scheme, "https");
        
        Ok(())
    }

    #[test]
    fn test_analyze_with_query_params() -> Result<(), Box<dyn std::error::Error>> {
        let analyzer = create_analyzer();
        let analysis = analyzer.analyze("https://example.com/path?key=value&foo=bar")?;
        
        assert_eq!(analysis.url_components.query_params.len(), 2);
        assert!(analysis.url_components.query_params.contains(&("key".to_string(), "value".to_string())));
        assert!(analysis.url_components.query_params.contains(&("foo".to_string(), "bar".to_string())));
        
        Ok(())
    }

    #[test]
    fn test_analyze_with_path_segments() -> Result<(), Box<dyn std::error::Error>> {
        let analyzer = create_analyzer();
        let analysis = analyzer.analyze("https://example.com/api/v1/users")?;
        
        assert_eq!(analysis.url_components.path_segments, vec!["api", "v1", "users"]);
        
        Ok(())
    }

    #[test]
    fn test_formatters() -> Result<(), Box<dyn std::error::Error>> {
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
    fn test_url_parser_separately() -> Result<(), Box<dyn std::error::Error>> {
        let parser = UrlParser::new();
        let (parsed_url, components) = parser.parse("https://example.com/path")?;
        
        assert_eq!(parsed_url.scheme(), "https");
        assert_eq!(components.path, "/path");
        
        Ok(())
    }

    #[test]
    fn test_tld_analyzer_separately() -> Result<(), Box<dyn std::error::Error>> {
        let tld_analyzer = TldAnalyzer::new();
        let components = tld_analyzer.extract("subdomain.example.com")?;
        
        assert_eq!(components.subdomain, Some("subdomain".to_string()));
        assert_eq!(components.domain, Some("example".to_string()));
        assert_eq!(components.suffix, Some("com".to_string()));
        
        Ok(())
    }
} 