use rust_url_parser::{ComprehensiveUrlAnalyzer, UrlAnalyzer, OutputFormatter, JsonFormatter};

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