use rust_url_parser::{ComprehensiveUrlAnalyzer, UrlAnalyzer, OutputFormatter, JsonFormatter};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Simple usage example - for more examples see examples/
    let url = "https://subdomain.domain.co.uk/path?query=value";
    
    let analyzer = ComprehensiveUrlAnalyzer::new();
    let formatter = JsonFormatter;
    
    match analyzer.analyze(url) {
        Ok(analysis) => {
            println!("{}", formatter.format(&analysis)?);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
    
    Ok(())
} 