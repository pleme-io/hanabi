{
  # Kept in step with README.md's opening line, which is the source of truth
  # for what hanabi is. This string and the public GitHub description in
  # pangea-architectures' org.yaml were byte-identical ("Web server and BFF
  # platform service") and had both drifted behind it — leading with the
  # smallest of the jobs and naming neither GraphQL nor federation. Corrected
  # together 2026-09-24; if one changes, change all three.
  description = "Hanabi — GraphQL Federation BFF platform service (Rust/Axum): federation query planning, OAuth/session auth, WebSocket subscriptions, rate limiting, webhooks, static serving, X-Product multi-tenancy";

  # substrate.rust.service dispatches over Cargo.gen.lock (the slim gen delta,
  # reconstructed to the full BuildSpec in pure Nix) — no crate2nix, no Cargo.nix.
  inputs.substrate.url = "github:pleme-io/substrate";

  outputs = { substrate, ... }: substrate.rust.service {
    src = ./.;
  };
}
