use rust_url_parser::{ComprehensiveUrlAnalyzer, UrlAnalyzer, OutputFormatter, WhoisFormatter};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let test_urls = vec![
        "https://subdomain.domain.co.uk",
        "https://www.example.com",
        "https://mail.google.com",
        "https://proxy.domain.com/proxy/facebook.com/search",
        "https://complex.redirect.com/api/v1/redirect/github.com/profile?fallback=https://twitter.com&backup=linkedin.com&final=https://stackoverflow.com/user",
        "https://encoded.redirect.com/api%2Fproxy%2Fgithub.com%2Fuser/redirect?primary=https%3A%2F%2Fexample.com%2Fpath%3Fquery%3Dtest&secondary=http%3A%2F%2Ffacebook.com",
        "https://admin:secret123@auth.proxy.com/redirect?target1=https://user1:pass1@database.example.com/api&target2=http://admin:admin@legacy.system.org/auth",
    ];

    let analyzer = ComprehensiveUrlAnalyzer::new();
    let mut analyses = Vec::new();

    // Analyze all URLs
    for url_str in test_urls {
        match analyzer.analyze(url_str) {
            Ok(analysis) => analyses.push(analysis),
            Err(e) => eprintln!("Error analyzing {}: {}", url_str, e),
        }
    }

    println!("=== WHOIS FORMAT (Registrable Domains Only) ===");
    let whois_formatter = WhoisFormatter::new();
    println!("{}", whois_formatter.format(&analyses)?);

    println!("\n=== WHOIS FORMAT (Including Subdomains) ===");
    let whois_with_subdomains = WhoisFormatter::new().with_subdomains();
    println!("{}", whois_with_subdomains.format(&analyses)?);

    Ok(())
} 