{
  description = "Hanabi - Web server and BFF (Backend for Frontend) platform service";

  # substrate.rust.service dispatches over Cargo.gen.lock (the slim gen delta,
  # reconstructed to the full BuildSpec in pure Nix) — no crate2nix, no Cargo.nix.
  inputs.substrate.url = "github:pleme-io/substrate";

  outputs = { substrate, ... }: substrate.rust.service {
    src = ./.;
  };
}
