#[derive(Debug, Parser, Clone)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Debug, Clone, Subcommand)]
pub enum Commands {
    Build(Build),
    Publish(Publish),
}

impl Commands {
    pub async fn execute(&self) -> PackageResult<()> {
        match self {
            Commands::Build(b) => b.execute().await,
            Commands::Publish(u) => p.execute().await,
        }
    }
}

impl Cli {
    pub async fn execute(&self) -> PackageResult<()> {
        self.command.execute().await
    }
}

#[tokio::main]
async fn main() -> PackageResult<()> {
    let cli = Cli::parse();
    cli.execute().await
}
