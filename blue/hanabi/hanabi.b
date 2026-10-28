use(
  "kousei",
  [
    :entry,
    :field,
    :flag,
    :int_in,
    :judge,
    :kind_of,
    :list_of,
    :name_of,
    :one_of,
    :overlay,
    :record_whys,
    :refuse,
    :required,
    :text,
    :value_of,
    :verdict
  ]
)

use("retsu", [:first, :is_empty, :rest])

# hanabi's configuration as kousei entries: one entry per section, each checked, configured off, tuned or refused alone.

def whole()
  int_in(0, 9_007_199_254_740_991)
end

def port()
  int_in(1, 65535)
end

def percent()
  fn(v)
    verdict(
      number?(v) and v >= 0 and v <= 100,
      "#{v} is not a number in 0..100"
    )
  end
end

def record(table)
  fn(v)
    whys = record_whys(table, v)
    if is_empty(whys)
      nil
    else
      join(whys, "; ")
    end
  end
end

def sources()
  list_of(text)
end

def schema()
  {
    environment: [required(field(:environment, text))],
    csp: [
      field(:api_domains, sources),
      field(:ws_domains, sources),
      field(:additional_connect_src, sources),
      field(:script_sources, sources),
      field(:font_sources, sources),
      field(:style_sources, sources),
      field(:img_sources, sources),
      field(:frame_sources, sources)
    ],
    cors: [
      field(:allowed_origins, sources),
      field(:allow_credentials, flag),
      field(:max_age_secs, whole),
      field(:additional_allowed_headers, sources),
      field(:additional_exposed_headers, sources)
    ],
    hsts: [
      field(:max_age, whole),
      field(:include_subdomains, flag),
      field(:preload, flag)
    ],
    headers: [
      field(:x_frame_options, one_of(["DENY", "SAMEORIGIN"])),
      field(:referrer_policy, text),
      field(:permissions_policy, text),
      field(
        :cross_origin_opener_policy,
        one_of(["unsafe-none", "same-origin-allow-popups", "same-origin"])
      ),
      field(
        :cross_origin_embedder_policy,
        one_of(["unsafe-none", "credentialless", "require-corp"])
      ),
      field(
        :cross_origin_resource_policy,
        one_of(["same-site", "same-origin", "cross-origin"])
      )
    ],
    transport: [
      field(:require_https, one_of(["off", "redirect-forwarded-http"])),
      field(:trust_forwarded_headers, flag)
    ],
    api: [field(:graphql_url, text), field(:ws_url, text)],
    bff: [
      field(:mode, one_of(["disabled", "proxy", "cache", "aggregate"])),
      field(:product, text),
      field(:hive_router_url, text),
      field(:hive_router_ws_url, text),
      field(:auth_service_url, text),
      field(:backend_rest_url, text),
      field(:backend_graphql_url, text),
      field(:nats_url, text)
    ],
    bff_cache: [
      field(:enabled, flag),
      field(:redis_host, text),
      field(:redis_port, port),
      field(:pool_min_size, whole),
      field(:pool_max_size, whole),
      field(:connection_timeout_secs, whole),
      field(:command_timeout_secs, whole),
      field(:default_ttl_secs, whole),
      field(
        :strategies,
        list_of(
          record(
            [
              required(field(:query_pattern, text)),
              required(field(:ttl_secs, whole))
            ]
          )
        )
      ),
      field(:cache_only_success, flag),
      field(:max_value_size, whole)
    ],
    federation: [
      field(:enabled, flag),
      field(:performance_mode, flag),
      field(:supergraph_url, text),
      field(:hot_reload, flag),
      field(:poll_interval_secs, whole),
      field(:enable_load_shedding, flag),
      field(:use_hive_planner, flag),
      field(:subgraph_default_port, port),
      field(:subgraph_default_path, text)
    ],
    server: [
      field(:static_dir, text),
      field(:http_port, port),
      field(:health_port, port),
      field(:service_name, text),
      field(:service_version, text),
      field(:bind_address, text),
      field(:request_timeout_secs, int_in(1, 300)),
      field(:keepalive_timeout_secs, whole),
      field(:max_concurrent_connections, int_in(1, 9_007_199_254_740_991)),
      field(:worker_threads, whole),
      field(:tcp_nodelay, flag),
      field(:role, one_of(["standalone", "sidecar"])),
      field(:no_static, flag)
    ],
    compression: [
      field(:enable_brotli, flag),
      field(:enable_gzip, flag),
      field(:min_compress_size, whole)
    ],
    cache: [
      field(:enable_cache_headers, flag),
      field(:static_max_age, int_in(0, 4_294_967_295)),
      field(:html_max_age, int_in(0, 4_294_967_295))
    ],
    health: [
      field(:disk_warn_threshold, percent),
      field(:disk_critical_threshold, percent),
      field(:memory_warn_threshold, percent),
      field(:memory_critical_threshold, percent)
    ],
    metrics: [
      field(:enabled, flag),
      field(:vector_host, text),
      field(:vector_port, port),
      field(:prefix, text)
    ],
    logging: [
      field(:format, one_of(["json", "pretty"])),
      field(:level, one_of(["trace", "debug", "info", "warn", "error"])),
      field(:include_location, flag),
      field(:include_thread_ids, flag),
      field(:include_timestamps, flag),
      field(:include_target, flag)
    ],
    features: [
      field(:enable_bug_reports, flag),
      field(:enable_metrics, flag),
      field(:enable_detailed_health_checks, flag),
      field(:enable_bff, flag)
    ]
  }
end

def placement()
  {
    environment: [],
    csp: [:security, :csp],
    cors: [:security, :cors],
    hsts: [:security, :hsts],
    headers: [:security, :headers],
    transport: [:security, :transport],
    api: [:api],
    bff: [:bff],
    bff_cache: [:bff, :cache],
    federation: [:bff, :federation],
    server: [:server],
    compression: [:compression],
    cache: [:cache],
    health: [:health],
    metrics: [:metrics],
    logging: [:logging],
    features: [:features]
  }
end

def section_name(kind)
  replace("#{kind}", ":", "")
end

def section(kind, fields)
  entry(kind, section_name(kind), fields)
end

def tune(kind, fields)
  kousei::tune(kind, section_name(kind), fields)
end

def off(kind)
  kousei::off(kind, section_name(kind))
end

def put_at(m, path, v)
  if is_empty(path)
    overlay(m, v)
  else
    here = get(m, first(path))
    inner = if here.nil?
      {}
    else
      here
    end
    assoc(m, first(path), put_at(inner, rest(path), v))
  end
end

def settle(declaration)
  j = judge(schema, declaration)
  misnamed = filter((e) -> name_of(e) != section_name(kind_of(e)), j[:accepted])
  standing = filter((e) -> not member?(e, misnamed), j[:accepted])
  tree = reduce(
    (acc, e) -> put_at(acc, get(placement, kind_of(e)), value_of(e)),
    {},
    standing
  )
  refusals = append(
    j[:refusals],
    map(
      (e) -> refuse(:invalid, e, "a section is named after its kind"),
      misnamed
    )
  )
  {
    config: tree,
    off: map(section_name, map(kind_of, j[:off])),
    refusals: map((r) -> {fault: r[0], why: r[1]}, refusals)
  }
end

def settle_json(declaration)
  json_stringify(settle(declaration))
end

def operation_fault(hash, operation)
  if not (string?(hash) and length(hash) == 64)
    "#{hash} is not a sha256 hex digest"
  elsif not (string?(operation) and length(operation) > 0)
    "#{hash}: the operation is not text"
  end
end

def persisted(table)
  pairs = map_entries(table)
  bad = filter((p) -> operation_fault(p[0], p[1]) != nil, pairs)
  {
    operations: reduce(
      (acc, p) -> assoc(acc, p[0], p[1]),
      {},
      filter((p) -> not member?(p, bad), pairs)
    ),
    refusals: map(
      (p) -> {fault: :invalid, why: operation_fault(p[0], p[1])},
      bad
    )
  }
end

def persisted_json(table)
  json_stringify(table)
end
