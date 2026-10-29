use("hanabi", [:section])

def declaration()
  [
    section(:environment, {environment: "production"}),
    section(
      :server,
      {
        static_dir: "/usr/share/nginx/html",
        http_port: 8000,
        health_port: 8080,
        bind_address: "0.0.0.0",
        service_name: "spa"
      }
    ),
    section(
      :features,
      {
        enable_bff: false,
        enable_metrics: false,
        enable_bug_reports: false,
        enable_detailed_health_checks: false
      }
    ),
    section(
      :transport,
      {require_https: "redirect-forwarded-http", trust_forwarded_headers: true}
    ),
    section(
      :headers,
      {
        x_frame_options: "DENY",
        referrer_policy: "strict-origin-when-cross-origin",
        permissions_policy: "geolocation=(), microphone=(), camera=(), payment=()",
        cross_origin_opener_policy: "same-origin-allow-popups",
        cross_origin_resource_policy: "same-origin",
        cross_origin_embedder_policy: "credentialless"
      }
    ),
    section(
      :hsts,
      {max_age: 31_536_000, include_subdomains: true, preload: true}
    ),
    section(
      :cors,
      {
        allowed_origins: ["https://console.example.com"],
        allow_credentials: false,
        max_age_secs: 3600,
        additional_allowed_headers: [],
        additional_exposed_headers: []
      }
    ),
    section(
      :csp,
      {
        api_domains: [],
        ws_domains: [],
        additional_connect_src: %w[
          *.example.com
          https://*.s3.us-east-2.amazonaws.com
        ],
        script_sources: ["https://www.googletagmanager.com"],
        style_sources: ["https://fonts.googleapis.com"],
        font_sources: ["https://fonts.gstatic.com"],
        frame_sources: ["https://www.youtube.com"],
        img_sources: ["'self'", "data:"]
      }
    ),
    section(:compression, {enable_gzip: true})
  ]
end
