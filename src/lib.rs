use url::Url;
use tldextract::{TldExtractor, TldOption};
use serde::{Serialize, Deserialize};

// ===== TRAITS =====

/// Trait for analyzing URLs
pub trait UrlAnalyzer {
    type Output;
    type Error;
    
    fn analyze(&self, url: &str) -> Result<Self::Output, Self::Error>;
}

/// Trait for formatting output
pub trait OutputFormatter<T> {
    type Error;
    
    fn format(&self, data: &T) -> Result<String, Self::Error>;
}

// ===== DATA STRUCTURES =====

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UrlAnalysis {
    pub original_url: String,
    pub url_components: UrlComponents,
    pub tld_components: TldComponents,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UrlComponents {
    pub scheme: String,
    pub username: String,
    pub password: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub path: String,
    pub query: Option<String>,
    pub fragment: Option<String>,
    pub query_params: Vec<(String, String)>,
    pub path_segments: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TldComponents {
    pub domain: Option<String>,
    pub subdomain: Option<String>,
    pub suffix: Option<String>,
}

// ===== URL PARSER (Single Responsibility) =====

/// Handles pure URL parsing without TLD extraction
pub struct UrlParser;

impl UrlParser {
    pub fn new() -> Self {
        Self
    }
    
    pub fn parse(&self, url_str: &str) -> Result<(Url, UrlComponents), Box<dyn std::error::Error>> {
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

impl Default for UrlParser {
    fn default() -> Self {
        Self::new()
    }
}

// ===== TLD ANALYZER (Single Responsibility) =====

/// Handles TLD extraction separately from URL parsing
pub struct TldAnalyzer {
    extractor: TldExtractor,
}

impl TldAnalyzer {
    pub fn new() -> Self {
        Self {
            extractor: TldExtractor::new(TldOption::default()),
        }
    }
    
    pub fn extract(&self, host: &str) -> Result<TldComponents, Box<dyn std::error::Error>> {
        let extracted = self.extractor.extract(host)?;
        
        Ok(TldComponents {
            domain: extracted.domain.filter(|s| !s.is_empty()),
            subdomain: extracted.subdomain.filter(|s| !s.is_empty()),
            suffix: extracted.suffix.filter(|s| !s.is_empty()),
        })
    }
}

impl Default for TldAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ===== COMPOSITE ANALYZER =====

/// Combines URL parsing and TLD extraction
pub struct ComprehensiveUrlAnalyzer {
    url_parser: UrlParser,
    tld_analyzer: TldAnalyzer,
}

impl ComprehensiveUrlAnalyzer {
    pub fn new() -> Self {
        Self {
            url_parser: UrlParser::new(),
            tld_analyzer: TldAnalyzer::new(),
        }
    }
}

impl Default for ComprehensiveUrlAnalyzer {
    fn default() -> Self {
        Self::new()
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
pub struct JsonFormatter;

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
pub struct CompactJsonFormatter;

impl<T> OutputFormatter<T> for CompactJsonFormatter 
where 
    T: Serialize 
{
    type Error = serde_json::Error;
    
    fn format(&self, data: &T) -> Result<String, Self::Error> {
        serde_json::to_string(data)
    }
}

/// Whois-specific formatter - extracts domains for whois lookup
pub struct WhoisFormatter {
    include_subdomains: bool,
}

impl WhoisFormatter {
    pub fn new() -> Self {
        Self {
            include_subdomains: false,
        }
    }
    
    pub fn with_subdomains(mut self) -> Self {
        self.include_subdomains = true;
        self
    }
}

impl Default for WhoisFormatter {
    fn default() -> Self {
        Self::new()
    }
}

impl OutputFormatter<Vec<UrlAnalysis>> for WhoisFormatter {
    type Error = std::fmt::Error;
    
    fn format(&self, analyses: &Vec<UrlAnalysis>) -> Result<String, Self::Error> {
        let mut domains = std::collections::HashSet::new();
        
        for analysis in analyses {
            // Extract the main domain for whois lookup
            if let Some(host) = &analysis.url_components.host {
                if self.include_subdomains {
                    // Include full domain with subdomains
                    domains.insert(host.clone());
                } else {
                    // Extract just the registrable domain (domain + suffix)
                    if let (Some(domain), Some(suffix)) = (&analysis.tld_components.domain, &analysis.tld_components.suffix) {
                        domains.insert(format!("{}.{}", domain, suffix));
                    } else {
                        // Fallback to full host if TLD extraction failed
                        domains.insert(host.clone());
                    }
                }
            }
            
            // Also extract domains from embedded URLs in query params
            for (_, value) in &analysis.url_components.query_params {
                // First try to parse as a full URL
                if let Ok(embedded_url) = Url::parse(value) {
                    if let Some(embedded_host) = embedded_url.host_str() {
                        if self.include_subdomains {
                            domains.insert(embedded_host.to_string());
                        } else {
                            // Try to extract domain from embedded URL
                            let analyzer = TldAnalyzer::new();
                            if let Ok(tld_components) = analyzer.extract(embedded_host) {
                                if let (Some(domain), Some(suffix)) = (tld_components.domain, tld_components.suffix) {
                                    domains.insert(format!("{}.{}", domain, suffix));
                                }
                            } else {
                                domains.insert(embedded_host.to_string());
                            }
                        }
                    }
                } else if value.contains('.') && !value.starts_with('%') {
                    // If it's not a valid URL but looks like a domain, try to extract it
                    let analyzer = TldAnalyzer::new();
                    if let Ok(tld_components) = analyzer.extract(value) {
                        if self.include_subdomains {
                            // For subdomains, try to reconstruct the full domain if possible
                            if let (Some(subdomain), Some(domain), Some(suffix)) = (&tld_components.subdomain, &tld_components.domain, &tld_components.suffix) {
                                domains.insert(format!("{}.{}.{}", subdomain, domain, suffix));
                            } else if let (Some(domain), Some(suffix)) = (&tld_components.domain, &tld_components.suffix) {
                                domains.insert(format!("{}.{}", domain, suffix));
                            }
                        } else {
                            // Extract just the registrable domain
                            if let (Some(domain), Some(suffix)) = (&tld_components.domain, &tld_components.suffix) {
                                domains.insert(format!("{}.{}", domain, suffix));
                            }
                        }
                    }
                }
            }
            
            // Extract domains from path segments that look like domains
            for segment in &analysis.url_components.path_segments {
                if segment.contains('.') && !segment.starts_with('%') {
                    // This might be a domain in the path
                    if self.include_subdomains {
                        domains.insert(segment.clone());
                    } else {
                        let analyzer = TldAnalyzer::new();
                        if let Ok(tld_components) = analyzer.extract(segment) {
                            if let (Some(domain), Some(suffix)) = (tld_components.domain, tld_components.suffix) {
                                domains.insert(format!("{}.{}", domain, suffix));
                            }
                        }
                    }
                }
            }
        }
        
        let mut sorted_domains: Vec<_> = domains.into_iter().collect();
        sorted_domains.sort();
        Ok(sorted_domains.join("\n"))
    }
}

impl OutputFormatter<UrlAnalysis> for WhoisFormatter {
    type Error = std::fmt::Error;
    
    fn format(&self, analysis: &UrlAnalysis) -> Result<String, Self::Error> {
        self.format(&vec![analysis.clone()])
    }
}

// ===== UTILITY FUNCTIONS =====

/// Convenience function to analyze a single URL
pub fn analyze_url(url: &str) -> Result<UrlAnalysis, Box<dyn std::error::Error>> {
    let analyzer = ComprehensiveUrlAnalyzer::new();
    analyzer.analyze(url)
}

/// Convenience function to analyze multiple URLs
pub fn analyze_urls(urls: &[&str]) -> Vec<Result<UrlAnalysis, Box<dyn std::error::Error>>> {
    let analyzer = ComprehensiveUrlAnalyzer::new();
    urls.iter().map(|url| analyzer.analyze(url)).collect()
}

// ===== TESTS =====

#[cfg(test)]
mod tests; 