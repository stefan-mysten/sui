// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::config::{MAX_CONCURRENT_REQUESTS, RPC_TIMEOUT_ERR_SLEEP_RETRY_PERIOD};
use crate::context_data::package_cache::DbPackageStore;
use crate::data::Db;
use crate::metrics::Metrics;
use crate::mutation::Mutation;
use crate::{
    config::ServerConfig,
    context_data::db_data_provider::PgManager,
    error::Error,
    extensions::{
        feature_gate::FeatureGate,
        logger::Logger,
        query_limits_checker::{QueryLimitsChecker, ShowUsage},
        timeout::Timeout,
    },
    server::version::{check_version_middleware, set_version_middleware},
    types::query::{Query, SuiGraphQLSchema},
};
use async_graphql::extensions::ApolloTracing;
use async_graphql::extensions::Tracing;
use async_graphql::EmptySubscription;
use async_graphql::{extensions::ExtensionFactory, Schema, SchemaBuilder};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::extract::{connect_info::IntoMakeServiceWithConnectInfo, ConnectInfo, State};
use axum::http::HeaderMap;
use axum::middleware::{self};
use axum::response::IntoResponse;
use axum::routing::{post, MethodRouter, Route};
use axum::{headers::Header, Router};
use http::Request;
use hyper::server::conn::AddrIncoming as HyperAddrIncoming;
use hyper::Body;
use hyper::Server as HyperServer;
use std::convert::Infallible;
use std::{any::Any, net::SocketAddr, time::Instant};
use sui_package_resolver::{PackageStoreWithLruCache, Resolver};
use sui_sdk::SuiClientBuilder;
use tokio::sync::OnceCell;
use tower::{Layer, Service};
use tracing::{info, warn};
use uuid::Uuid;

pub struct Server {
    pub server: HyperServer<HyperAddrIncoming, IntoMakeServiceWithConnectInfo<Router, SocketAddr>>,
}

impl Server {
    pub async fn run(self) -> Result<(), Error> {
        get_or_init_server_start_time().await;
        self.server
            .await
            .map_err(|e| Error::Internal(format!("Server run failed: {}", e)))
    }
}

pub(crate) struct ServerBuilder {
    port: u16,
    host: String,

    schema: SchemaBuilder<Query, Mutation, EmptySubscription>,
    router: Option<Router>,
    metrics: Metrics,
}

impl ServerBuilder {
    pub fn new(port: u16, host: String, metrics: Metrics) -> Self {
        Self {
            port,
            host,
            schema: async_graphql::Schema::build(Query, Mutation, EmptySubscription),
            router: None,
            metrics,
        }
    }

    pub fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    pub fn context_data(mut self, context_data: impl Any + Send + Sync) -> Self {
        self.schema = self.schema.data(context_data);
        self
    }

    pub fn extension(mut self, extension: impl ExtensionFactory) -> Self {
        self.schema = self.schema.extension(extension);
        self
    }

    fn build_schema(self) -> Schema<Query, Mutation, EmptySubscription> {
        self.schema.finish()
    }

    fn build_components(self) -> (String, Schema<Query, Mutation, EmptySubscription>, Router) {
        let address = self.address();
        let ServerBuilder { schema, router, .. } = self;
        (
            address,
            schema.finish(),
            router.expect("Router not initialized"),
        )
    }

    fn init_router(&mut self) {
        if self.router.is_none() {
            let router: Router = Router::new()
                .route("/", post(graphql_handler))
                .route("/graphql", post(graphql_handler))
                .route("/health", axum::routing::get(health_checks))
                .with_state(self.metrics.clone())
                .route_layer(middleware::from_fn_with_state(
                    self.metrics.clone(),
                    check_version_middleware,
                ))
                .layer(middleware::from_fn(set_version_middleware));
            self.router = Some(router);
        }
    }

    pub fn route(mut self, path: &str, method_handler: MethodRouter) -> Self {
        self.init_router();
        self.router = self.router.map(|router| router.route(path, method_handler));
        self
    }

    pub fn layer<L>(mut self, layer: L) -> Self
    where
        L: Layer<Route> + Clone + Send + 'static,
        L::Service: Service<Request<Body>> + Clone + Send + 'static,
        <L::Service as Service<Request<Body>>>::Response: IntoResponse + 'static,
        <L::Service as Service<Request<Body>>>::Error: Into<Infallible> + 'static,
        <L::Service as Service<Request<Body>>>::Future: Send + 'static,
    {
        self.init_router();
        self.router = self.router.map(|router| router.layer(layer));
        self
    }

    pub fn build(self) -> Result<Server, Error> {
        let (address, schema, router) = self.build_components();

        let app = router.layer(axum::extract::Extension(schema));

        Ok(Server {
            server: axum::Server::bind(
                &address
                    .parse()
                    .map_err(|_| Error::Internal(format!("Failed to parse address {}", address)))?,
            )
            .serve(app.into_make_service_with_connect_info::<SocketAddr>()),
        })
    }

    pub async fn from_yaml_config(path: &str) -> Result<(Self, ServerConfig), Error> {
        let config = ServerConfig::from_yaml(path)?;
        Self::from_config(&config)
            .await
            .map(|builder| (builder, config))
    }

    pub async fn from_config(config: &ServerConfig) -> Result<Self, Error> {
        // PROMETHEUS
        let prom_addr: SocketAddr = format!(
            "{}:{}",
            config.connection.prom_url, config.connection.prom_port
        )
        .parse()
        .map_err(|_| {
            Error::Internal(format!(
                "Failed to parse url {}, port {} into socket address",
                config.connection.prom_url, config.connection.prom_port
            ))
        })?;
        let registry_service = mysten_metrics::start_prometheus_server(prom_addr);
        info!("Starting Prometheus HTTP endpoint at {}", prom_addr);
        let registry = registry_service.default_registry();

        // METRICS
        let metrics = Metrics::new(&registry);

        let mut builder = ServerBuilder::new(
            config.connection.port,
            config.connection.host.clone(),
            metrics.clone(),
        );

        let name_service_config = config.name_service.clone();
        let reader = PgManager::reader_with_config(
            config.connection.db_url.clone(),
            config.connection.db_pool_size,
        )
        .map_err(|e| Error::Internal(format!("Failed to create pg connection pool: {}", e)))?;

        // DB
        let db = Db::new(reader.clone(), config.service.limits, metrics.clone());
        let pg_conn_pool = PgManager::new(reader.clone(), config.service.limits);
        let package_store = DbPackageStore(reader);
        let package_cache = PackageStoreWithLruCache::new(package_store);

        // SDK for talking to fullnode. Used for executing transactions only
        // TODO: fail fast if no url, once we enable mutations fully
        let sui_sdk_client = if let Some(url) = &config.tx_exec_full_node.node_rpc_url {
            Some(
                SuiClientBuilder::default()
                    .request_timeout(RPC_TIMEOUT_ERR_SLEEP_RETRY_PERIOD)
                    .max_concurrent_requests(MAX_CONCURRENT_REQUESTS)
                    .build(url)
                    .await
                    .map_err(|e| Error::Internal(format!("Failed to create SuiClient: {}", e)))?,
            )
        } else {
            warn!("No fullnode url found in config. Mutations will not work");
            None
        };

        builder = builder
            .context_data(config.service.clone())
            .context_data(db)
            .context_data(pg_conn_pool)
            .context_data(Resolver::new_with_limits(
                package_cache,
                config.service.limits.package_resolver_limits(),
            ))
            .context_data(sui_sdk_client)
            .context_data(name_service_config)
            .context_data(metrics.clone())
            .context_data(config.clone());

        if config.internal_features.feature_gate {
            builder = builder.extension(FeatureGate);
        }
        if config.internal_features.logger {
            builder = builder.extension(Logger::default());
        }
        if config.internal_features.query_limits_checker {
            builder = builder.extension(QueryLimitsChecker::default());
        }
        if config.internal_features.query_timeout {
            builder = builder.extension(Timeout);
        }
        if config.internal_features.tracing {
            builder = builder.extension(Tracing);
        }
        if config.internal_features.apollo_tracing {
            builder = builder.extension(ApolloTracing);
        }

        // TODO: uncomment once impl
        // if config.internal_features.open_telemetry { }

        Ok(builder)
    }
}

async fn graphql_handler(
    State(metrics): State<Metrics>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    schema: axum::Extension<SuiGraphQLSchema>,
    headers: HeaderMap,
    req: GraphQLRequest,
) -> GraphQLResponse {
    metrics.request_metrics.inflight_requests.inc();
    metrics.inc_num_queries();
    let instant = Instant::now();
    let mut req = req.into_inner();
    req.data.insert(Uuid::new_v4());
    if headers.contains_key(ShowUsage::name()) {
        req.data.insert(ShowUsage)
    }
    // Capture the IP address of the client
    // Note: if a load balancer is used it must be configured to forward the client IP address
    req.data.insert(addr);
    let result = schema.execute(req).await;
    let elapsed = instant.elapsed().as_millis() as u64;
    metrics.query_latency(elapsed);
    if result.is_err() {
        metrics.inc_errors(result.errors.clone());
    }
    metrics.request_metrics.inflight_requests.dec();
    result.into()
}

async fn health_checks(
    schema: axum::Extension<SuiGraphQLSchema>,
) -> impl axum::response::IntoResponse {
    // Simple request to check if the DB is up
    // TODO: add more checks
    let req = r#"
        query {
            chainIdentifier
        }
        "#;
    let db_up = match schema.execute(req).await.is_ok() {
        true => "UP",
        false => "DOWN",
    };
    let uptime = get_or_init_server_start_time()
        .await
        .elapsed()
        .as_secs_f64();
    format!(
        r#"{{"status": "UP","uptime": {},"checks": {{"DB": "{}",}}}}
        "#,
        uptime, db_up
    )
}

// One server per proc, so this is okay
async fn get_or_init_server_start_time() -> &'static Instant {
    static ONCE: OnceCell<Instant> = OnceCell::const_new();
    ONCE.get_or_init(|| async move { Instant::now() }).await
}

pub mod tests {
    use super::*;
    use crate::{
        config::{ConnectionConfig, Limits, ServiceConfig},
        context_data::db_data_provider::PgManager,
        extensions::query_limits_checker::QueryLimitsChecker,
        extensions::timeout::Timeout,
        test_infra::cluster::{serve_executor, ExecutorCluster, DEFAULT_INTERNAL_DATA_SOURCE_PORT},
    };
    use async_graphql::{
        extensions::{Extension, ExtensionContext, NextExecute},
        Response,
    };
    use prometheus::{proto::MetricFamily, Registry};
    use rand::{rngs::StdRng, SeedableRng};
    use simulacrum::Simulacrum;
    use std::time::Duration;
    use std::{collections::HashMap, sync::Arc};
    use uuid::Uuid;

    async fn prep_cluster() -> (ConnectionConfig, ExecutorCluster) {
        let rng = StdRng::from_seed([12; 32]);
        let mut sim = Simulacrum::new_with_rng(rng);

        sim.create_checkpoint();

        let connection_config = ConnectionConfig::ci_integration_test_cfg();

        (
            connection_config.clone(),
            serve_executor(
                connection_config,
                DEFAULT_INTERNAL_DATA_SOURCE_PORT,
                Arc::new(sim),
                None,
            )
            .await,
        )
    }

    fn metrics() -> Metrics {
        let binding_address: SocketAddr = "0.0.0.0:9185".parse().unwrap();
        let registry = mysten_metrics::start_prometheus_server(binding_address).default_registry();
        Metrics::new(&registry)
    }

    fn ip_address() -> SocketAddr {
        let binding_address: SocketAddr = "0.0.0.0:51515".parse().unwrap();
        binding_address
    }

    fn query_id() -> Uuid {
        Uuid::new_v4()
    }

    pub async fn test_timeout_impl() {
        let (connection_config, _cluster) = prep_cluster().await;

        struct TimedExecuteExt {
            pub min_req_delay: Duration,
        }

        impl ExtensionFactory for TimedExecuteExt {
            fn create(&self) -> Arc<dyn Extension> {
                Arc::new(TimedExecuteExt {
                    min_req_delay: self.min_req_delay,
                })
            }
        }

        #[async_trait::async_trait]
        impl Extension for TimedExecuteExt {
            async fn execute(
                &self,
                ctx: &ExtensionContext<'_>,
                operation_name: Option<&str>,
                next: NextExecute<'_>,
            ) -> Response {
                tokio::time::sleep(self.min_req_delay).await;
                next.run(ctx, operation_name).await
            }
        }

        async fn test_timeout(
            delay: Duration,
            timeout: Duration,
            connection_config: &ConnectionConfig,
        ) -> Response {
            let db_url: String = connection_config.db_url.clone();
            let reader = PgManager::reader(db_url).expect("Failed to create pg connection pool");
            let mut cfg = ServiceConfig::default();
            cfg.limits.request_timeout_ms = timeout.as_millis() as u64;

            let metrics = metrics();
            let db = Db::new(reader.clone(), cfg.limits, metrics.clone());
            let pg_conn_pool = PgManager::new(reader, cfg.limits);
            let schema = ServerBuilder::new(8000, "127.0.0.1".to_string(), metrics)
                .context_data(db)
                .context_data(pg_conn_pool)
                .context_data(cfg)
                .context_data(query_id())
                .context_data(ip_address())
                .extension(TimedExecuteExt {
                    min_req_delay: delay,
                })
                .extension(Timeout)
                .build_schema();

            schema.execute("{ chainIdentifier }").await
        }

        let timeout = Duration::from_millis(1000);
        let delay = Duration::from_millis(100);

        // Should complete successfully
        let resp = test_timeout(delay, timeout, &connection_config).await;
        assert!(resp.is_ok());

        // Should timeout
        let errs: Vec<_> = test_timeout(timeout, timeout, &connection_config)
            .await
            .into_result()
            .unwrap_err()
            .into_iter()
            .map(|e| e.message)
            .collect();
        let exp = format!("Request timed out. Limit: {}s", timeout.as_secs_f32());
        assert_eq!(errs, vec![exp]);
    }

    pub async fn test_query_depth_limit_impl() {
        let (connection_config, _cluster) = prep_cluster().await;

        async fn exec_query_depth_limit(
            depth: u32,
            query: &str,
            connection_config: &ConnectionConfig,
        ) -> Response {
            let db_url: String = connection_config.db_url.clone();
            let reader = PgManager::reader(db_url).expect("Failed to create pg connection pool");
            let service_config = ServiceConfig {
                limits: Limits {
                    max_query_depth: depth,
                    ..Default::default()
                },
                ..Default::default()
            };
            let metrics = metrics();
            let db = Db::new(reader.clone(), service_config.limits, metrics.clone());
            let pg_conn_pool = PgManager::new(reader, service_config.limits);
            let schema = ServerBuilder::new(8000, "127.0.0.1".to_string(), metrics.clone())
                .context_data(db)
                .context_data(pg_conn_pool)
                .context_data(service_config)
                .context_data(query_id())
                .context_data(ip_address())
                .context_data(metrics.clone())
                .extension(QueryLimitsChecker::default())
                .build_schema();
            schema.execute(query).await
        }

        // Should complete successfully
        let resp = exec_query_depth_limit(1, "{ chainIdentifier }", &connection_config).await;
        assert!(resp.is_ok());
        let resp = exec_query_depth_limit(
            5,
            "{ chainIdentifier protocolConfig { configs { value key }} }",
            &connection_config,
        )
        .await;
        assert!(resp.is_ok());

        // Should fail
        let errs: Vec<_> = exec_query_depth_limit(0, "{ chainIdentifier }", &connection_config)
            .await
            .into_result()
            .unwrap_err()
            .into_iter()
            .map(|e| e.message)
            .collect();

        assert_eq!(
            errs,
            vec!["Query has too many levels of nesting 1. The maximum allowed is 0".to_string()]
        );
        let errs: Vec<_> = exec_query_depth_limit(
            2,
            "{ chainIdentifier protocolConfig { configs { value key }} }",
            &connection_config,
        )
        .await
        .into_result()
        .unwrap_err()
        .into_iter()
        .map(|e| e.message)
        .collect();
        assert_eq!(
            errs,
            vec!["Query has too many levels of nesting 3. The maximum allowed is 2".to_string()]
        );
    }

    pub async fn test_query_node_limit_impl() {
        let (connection_config, _cluster) = prep_cluster().await;

        async fn exec_query_node_limit(
            nodes: u32,
            query: &str,
            connection_config: &ConnectionConfig,
        ) -> Response {
            let db_url: String = connection_config.db_url.clone();
            let reader = PgManager::reader(db_url).expect("Failed to create pg connection pool");
            let service_config = ServiceConfig {
                limits: Limits {
                    max_query_nodes: nodes,
                    ..Default::default()
                },
                ..Default::default()
            };
            let metrics = metrics();
            let db = Db::new(reader.clone(), service_config.limits, metrics.clone());
            let pg_conn_pool = PgManager::new(reader, service_config.limits);
            let schema = ServerBuilder::new(8000, "127.0.0.1".to_string(), metrics.clone())
                .context_data(db)
                .context_data(pg_conn_pool)
                .context_data(service_config)
                .context_data(query_id())
                .context_data(ip_address())
                .context_data(metrics.clone())
                .extension(QueryLimitsChecker::default())
                .build_schema();
            schema.execute(query).await
        }

        // Should complete successfully
        let resp = exec_query_node_limit(1, "{ chainIdentifier }", &connection_config).await;
        assert!(resp.is_ok());
        let resp = exec_query_node_limit(
            5,
            "{ chainIdentifier protocolConfig { configs { value key }} }",
            &connection_config,
        )
        .await;
        assert!(resp.is_ok());

        // Should fail
        let err: Vec<_> = exec_query_node_limit(0, "{ chainIdentifier }", &connection_config)
            .await
            .into_result()
            .unwrap_err()
            .into_iter()
            .map(|e| e.message)
            .collect();
        assert_eq!(
            err,
            vec!["Query has too many nodes 1. The maximum allowed is 0".to_string()]
        );

        let err: Vec<_> = exec_query_node_limit(
            4,
            "{ chainIdentifier protocolConfig { configs { value key }} }",
            &connection_config,
        )
        .await
        .into_result()
        .unwrap_err()
        .into_iter()
        .map(|e| e.message)
        .collect();
        assert_eq!(
            err,
            vec!["Query has too many nodes 5. The maximum allowed is 4".to_string()]
        );
    }

    pub async fn test_query_default_page_limit_impl() {
        let rng = StdRng::from_seed([12; 32]);
        let mut sim = Simulacrum::new_with_rng(rng);

        sim.create_checkpoint();
        sim.create_checkpoint();

        let connection_config = ConnectionConfig::ci_integration_test_cfg();
        let service_config = ServiceConfig {
            limits: Limits {
                default_page_size: 1,
                ..Default::default()
            },
            ..Default::default()
        };
        let metrics = metrics();
        let db_url: String = connection_config.db_url.clone();
        let reader = PgManager::reader(db_url).expect("Failed to create pg connection pool");
        let db = Db::new(reader.clone(), service_config.limits, metrics.clone());
        let pg_conn_pool = PgManager::new(reader, service_config.limits);
        let schema = ServerBuilder::new(8000, "127.0.0.1".to_string(), metrics.clone())
            .context_data(db)
            .context_data(pg_conn_pool)
            .context_data(service_config)
            .context_data(query_id())
            .context_data(ip_address())
            .context_data(metrics.clone())
            .build_schema();

        let resp = schema
            .execute("{ checkpoints { nodes { sequenceNumber } } }")
            .await;
        let data = resp.data.clone().into_json().unwrap();
        let checkpoints = data
            .get("checkpoints")
            .unwrap()
            .get("nodes")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(
            checkpoints.len(),
            1,
            "Checkpoints should have exactly one element"
        );

        let resp = schema
            .execute("{ checkpoints(first: 2) { nodes { sequenceNumber } } }")
            .await;
        let data = resp.data.clone().into_json().unwrap();
        let checkpoints = data
            .get("checkpoints")
            .unwrap()
            .get("nodes")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(
            checkpoints.len(),
            2,
            "Checkpoints should return two elements"
        );
    }

    pub async fn test_query_max_page_limit_impl() {
        let (connection_config, _cluster) = prep_cluster().await;

        let service_config = ServiceConfig::default();
        let db_url: String = connection_config.db_url.clone();
        let reader = PgManager::reader(db_url).expect("Failed to create pg connection pool");
        let metrics = metrics();
        let db = Db::new(reader.clone(), service_config.limits, metrics.clone());
        let pg_conn_pool = PgManager::new(reader, service_config.limits);
        let schema = ServerBuilder::new(8000, "127.0.0.1".to_string(), metrics.clone())
            .context_data(db)
            .context_data(pg_conn_pool)
            .context_data(service_config)
            .context_data(query_id())
            .context_data(ip_address())
            .context_data(metrics.clone())
            .build_schema();

        // Should complete successfully
        let resp = schema
            .execute("{ objects(first: 1) { nodes { version } } }")
            .await;
        assert!(resp.is_ok());

        // Should fail
        let err: Vec<_> = schema
            .execute("{ objects(first: 51) { nodes { version } } }")
            .await
            .into_result()
            .unwrap_err()
            .into_iter()
            .map(|e| e.message)
            .collect();
        assert_eq!(
            err,
            vec!["Connection's page size of 51 exceeds max of 50".to_string()]
        );
    }

    pub async fn test_query_complexity_metrics_impl() {
        let (connection_config, _cluster) = prep_cluster().await;

        let binding_address: SocketAddr = "0.0.0.0:9185".parse().unwrap();
        let registry_service = mysten_metrics::start_prometheus_server(binding_address);
        let registry = registry_service.default_registry();
        let metrics = Metrics::new(&registry);
        mysten_metrics::init_metrics(&registry);
        let service_config = ServiceConfig::default();
        let db_url: String = connection_config.db_url.clone();
        let reader = PgManager::reader(db_url).expect("Failed to create pg connection pool");
        let db = Db::new(reader.clone(), service_config.limits, metrics.clone());
        let pg_conn_pool = PgManager::new(reader, service_config.limits);
        let schema = ServerBuilder::new(8000, "127.0.0.1".to_string(), metrics.clone())
            .context_data(db)
            .context_data(pg_conn_pool)
            .context_data(service_config)
            .context_data(metrics.clone())
            .context_data(query_id())
            .context_data(ip_address())
            .extension(QueryLimitsChecker::default())
            .build_schema();
        let _ = schema.execute("{ chainIdentifier }").await;

        tokio::time::sleep(Duration::from_millis(1500)).await;
        println!("{:?}", registry_service.gather_all());

        metrics.request_metrics.input_nodes.report(5);
        tokio::time::sleep(Duration::from_millis(1500)).await;
        println!("{:?}", registry_service.gather_all());
        // tokio::time::sleep(Duration::from_millis(1500)).await;
        // println!("{:?}", registry_service.gather_all());
        // TODO these do not get properly triggered. Need more investigation, seems to be
        // because of the Histogram and HistogramVec that comes from mysten-metrics.
        // running the binary is fine, just the testing is funky.
        // let (_input_hist, input_sum, input_count) = _get_sample("input_nodes", &registry);
        // assert_eq!(input_sum.len(), 1);
        // assert_eq!(input_count.len(), 1);
        // let (_input_hist, input_sum, input_count) = get_sample("output_nodes", &registry);
        // assert_eq!(input_sum.len(), 1);
        // assert_eq!(input_count.len(), 1);
        // let (_input_hist, input_sum, input_count) = get_sample("query_depth", &registry);
        // assert_eq!(input_sum.len(), 1);
        // assert_eq!(input_count.len(), 1);
        // let _ = schema
        //     .execute("{ chainIdentifier protocolConfig { configs { value key }} }")
        //     .await;

        // let (_input_hist, input_sum, input_count) = get_sample("input_nodes", &registry);
        // assert_eq!(input_sum.len(), 2);
        // assert_eq!(input_count.len(), 2);
        // let (_input_hist, input_sum, input_count) = get_sample("output_nodes", &registry);
        // assert_eq!(input_sum.len(), 2);
        // assert_eq!(input_count.len(), 2);
        // let (_input_hist, input_sum, input_count) = get_sample("query_depth", &registry);
        // assert_eq!(input_sum.len(), 2);
        // assert_eq!(input_count.len(), 2);
    }

    // TODO Add these convenience functions to mysten-metrics/src/histogram.rs to enable
    // easier testing
    fn _get_sample(
        name: &str,
        registry: &Registry,
    ) -> (
        HashMap<String, f64>,
        HashMap<String, f64>,
        HashMap<String, f64>,
    ) {
        let gather = registry.gather();
        println!("{gather:?}");
        let gather: HashMap<_, _> = gather
            .into_iter()
            .map(|f| (f.get_name().to_string(), f))
            .collect();
        let hist = gather.get(name).unwrap();
        let sum = gather.get("{name}_sum").unwrap();
        let count = gather.get("{name}_count").unwrap();
        let hist = _aggregate_gauge_by_label(hist);
        let sum = _aggregate_counter_by_label(sum);
        let count = _aggregate_counter_by_label(count);
        (hist, sum, count)
    }
    // copied from mysten-metrics histogram tests

    fn _aggregate_gauge_by_label(family: &MetricFamily) -> HashMap<String, f64> {
        family
            .get_metric()
            .iter()
            .map(|m| {
                let value = m.get_gauge().get_value();
                let mut key = String::new();
                for label in m.get_label() {
                    key.push_str("::");
                    key.push_str(label.get_value());
                }
                (key, value)
            })
            .collect()
    }

    fn _aggregate_counter_by_label(family: &MetricFamily) -> HashMap<String, f64> {
        family
            .get_metric()
            .iter()
            .map(|m| {
                let value = m.get_counter().get_value();
                let mut key = String::new();
                for label in m.get_label() {
                    key.push_str("::");
                    key.push_str(label.get_value());
                }
                (key, value)
            })
            .collect()
    }
}
