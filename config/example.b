use("hanabi", [:section])

def declaration()
  [
    section(:environment, {environment: "staging"}),
    section(
      :csp,
      {
        api_domains: [],
        ws_domains: [],
        additional_connect_src: [
          "https://viacep.com.br",
          "https://api.stripe.com"
        ],
        script_sources: [
          "https://js.stripe.com",
          "https://static.cloudflareinsights.com"
        ],
        font_sources: ["https://fonts.gstatic.com"],
        style_sources: ["https://fonts.googleapis.com"],
        frame_sources: ["https://js.stripe.com", "https://hooks.stripe.com"]
      }
    ),
    section(
      :cors,
      {
        allowed_origins: [
          "https://staging.example.com",
          "https://www.staging.example.com"
        ],
        allow_credentials: true,
        max_age_secs: 3600,
        additional_allowed_headers: [],
        additional_exposed_headers: []
      }
    ),
    section(
      :hsts,
      {max_age: 31_536_000, include_subdomains: true, preload: true}
    ),
    section(
      :headers,
      {
        x_frame_options: "DENY",
        referrer_policy: "strict-origin-when-cross-origin",
        permissions_policy: "geolocation=(), microphone=(), camera=(), payment=()"
      }
    ),
    section(:api, {graphql_url: "/graphql", ws_url: "/graphql"}),
    section(
      :bff,
      {
        mode: "proxy",
        hive_router_url: "http://hive-router.your-product-staging.svc.cluster.local:4000/graphql"
      }
    ),
    section(
      :bff_cache,
      {
        enabled: false,
        redis_host: "localhost",
        redis_port: 6379,
        default_ttl_secs: 60,
        strategies: []
      }
    ),
    section(
      :federation,
      {
        enabled: true,
        supergraph_url: "file:///etc/supergraph.graphql",
        poll_interval_secs: 0
      }
    ),
    section(
      :server,
      {
        static_dir: "/app/static",
        http_port: 80,
        health_port: 8080,
        service_name: "your-product-web",
        service_version: "1.0.0",
        bind_address: "0.0.0.0",
        request_timeout_secs: 30,
        keepalive_timeout_secs: 75
      }
    ),
    section(
      :compression,
      {enable_brotli: true, enable_gzip: true, min_compress_size: 1024}
    ),
    section(
      :cache,
      {
        enable_cache_headers: true,
        static_max_age: 31_536_000,
        html_max_age: 3600
      }
    ),
    section(
      :health,
      {
        disk_warn_threshold: 10.0,
        disk_critical_threshold: 5.0,
        memory_warn_threshold: 10.0,
        memory_critical_threshold: 5.0
      }
    ),
    section(
      :metrics,
      {
        enabled: true,
        vector_host: "127.0.0.1",
        vector_port: 8125,
        prefix: "your_product_web"
      }
    ),
    section(
      :logging,
      {
        format: "json",
        level: "info",
        include_location: true,
        include_thread_ids: false
      }
    ),
    section(
      :features,
      {
        enable_bug_reports: true,
        enable_metrics: true,
        enable_detailed_health_checks: true,
        enable_bff: true
      }
    )
  ]
end
