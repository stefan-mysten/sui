use clap::Parser;
use std::net::Ipv4Addr;

pub const DEFAULT_AMOUNT: u64 = 100_000_000_000;
pub const DEFAULT_NUM_OF_COINS: usize = 5;

#[derive(Parser, Clone)]
#[clap(
    name = "Sui Faucet",
    about = "Faucet for requesting test tokens on Sui",
    rename_all = "kebab-case"
)]
pub struct FaucetConfig {
    #[clap(long, default_value_t = 5003)]
    pub port: u16,

    #[clap(long, default_value = "127.0.0.1")]
    pub host_ip: Ipv4Addr,

    /// Amount of SUI per each dispensed coin.
    #[clap(long, default_value_t = DEFAULT_AMOUNT)]
    pub amount: u64,

    /// Num of coins to dispense per request.
    #[clap(long, default_value_t = DEFAULT_NUM_OF_COINS)]
    pub num_coins: usize,

    #[clap(long, default_value_t = 10)]
    pub request_buffer_size: usize,

    #[clap(long, default_value_t = 10)]
    pub max_request_per_second: u64,

    #[clap(long, default_value_t = 60)]
    pub wallet_client_timeout_secs: u64,

    #[clap(long, default_value_t = 300)]
    pub ttl_expiration: u64,

    /// Testnet faucet requires authentication via the Web UI at <https://faucet.sui.io>
    /// This flag is used to indicate that authentication mode is enabled.
    #[clap(long)]
    pub authenticated: bool,

    /// Must be set for when a local faucet is running.
    #[clap(long, conflicts_with = "authenticated")]
    pub local: bool,

    /// Maximum number of requests per IP address. This is used for the authenticated mode.
    #[clap(long, default_value_t = 3)]
    pub max_requests_per_ip: u64,

    /// This is the amount of time to wait before adding one more quota to the rate limiter. Basically,
    /// it ensures that we're not allowing too many requests all at once. This is very specific to
    /// governor and tower-governor crates. This is used primarily for authenticated mode. A small
    /// value will allow more requests to be processed in a short period of time.
    #[clap(long, default_value_t = 10)]
    pub replenish_quota_interval_ms: u64,

    /// The amount of seconds to wait before resetting the request count for the IP addresses recorded
    /// by the rate limit layer. Default is 12 hours. This is used for authenticated mode.
    #[clap(long, default_value_t = 3600*12)]
    pub reset_time_interval_secs: u64,

    /// Interval time to run the task to clear the banned IP addresses by the rate limiter. This is
    /// used for authenticated mode.
    #[clap(long, default_value_t = 60)]
    pub rate_limiter_cleanup_interval_secs: u64,
}

impl Default for FaucetConfig {
    fn default() -> Self {
        Self {
            port: 5003,
            host_ip: Ipv4Addr::new(127, 0, 0, 1),
            amount: DEFAULT_AMOUNT,
            request_buffer_size: 10,
            max_request_per_second: 10,
            wallet_client_timeout_secs: 60,
            ttl_expiration: 300,
            authenticated: false,
            local: false,
            num_coins: 10,
            max_requests_per_ip: 3,
            replenish_quota_interval_ms: 10,
            reset_time_interval_secs: 3600 * 12,
            rate_limiter_cleanup_interval_secs: 60,
        }
    }
}
