use("hanabi", %i[off section tune])
use("kousei", [:entry])

def declaration()
  [
    section(:environment, {environment: "staging"}),
    section(:server, {static_dir: ".", http_port: 0, health_port: 8080}),
    section(:federation, {enabled: true, hmac_secret: ""}),
    section(:headers, {cross_origin_opener_policy: "same-origin-allow-popups"}),
    section(:hsts, {max_age: 600, include_subdomains: false, preload: false}),
    tune(:hsts, {max_age: 31_536_000}),
    section(:compression, {enable_gzip: false}),
    off(:compression),
    section(:widget, {}),
    entry_named_wrong
  ]
end

def entry_named_wrong()
  entry(:metrics, "statsd", {enabled: true})
end
