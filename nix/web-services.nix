# Automatic web service discovery and packaging
#
# This module:
# - Auto-discovers all web projects in pkgs/products/*/web/
# - Builds Vite frontends with npm
# - Builds Rust web-servers with crane
# - Generates Docker images for each web project
# - Creates release apps for each web project
# - Fully general - works for any product and any web project
{
  self,
  lib,
  inputs,
  ...
}: {
  perSystem = {
    config,
    system,
    pkgs,
    inputs',
    ...
  }: let
    # Import crate2nix for service building
    crate2nix = inputs'.crate2nix.packages.default;

    # Import nix-lib for host system
    # Also provides mkRustOverlay for creating consistent Rust toolchain overlays
    nixLibHost = import (self + "/pkgs/products/novaskyn/services/rust/nix-lib/lib/default.nix") {
      inherit pkgs system crate2nix;
    };

    # On Mac, target Linux for service images
    targetSystem =
      if pkgs.stdenv.isDarwin
      then "x86_64-linux"
      else system;
    targetPkgs =
      if pkgs.stdenv.isDarwin
      then
        import inputs.nixpkgs.outPath {
          system = "x86_64-linux";
          overlays = [
            (nixLibHost.mkRustOverlay {
              fenix = inputs.fenix;
              system = "x86_64-linux";
            })
          ];
        }
      else pkgs;

    # Import nix-lib for target system
    nixLibTarget = import (self + "/pkgs/products/novaskyn/services/rust/nix-lib/lib/default.nix") {
      pkgs = targetPkgs;
      system = targetSystem;
      inherit crate2nix;
    };

    # Build nexus-deploy wrapper
    nexusDeployBinary = config.packages.nexus-deploy or null;
    nexusDeployWrapper =
      if nexusDeployBinary != null
      then
        pkgs.writeShellScriptBin "nexus-deploy" ''
          exec ${nexusDeployBinary}/bin/nexus-deploy "$@"
        ''
      else throw "nexus-deploy binary not found in packages";

    # Parse YAML file to Nix attrset using remarshal
    parseYaml = yamlPath:
      if !builtins.pathExists yamlPath
      then {}
      else let
        # Convert YAML to JSON using remarshal
        jsonFile =
          pkgs.runCommand "yaml-to-json" {
            buildInputs = [pkgs.remarshal];
          } ''
            yaml2json < ${yamlPath} > $out
          '';
        # Read and parse JSON
        jsonContent = builtins.readFile jsonFile;
      in
        builtins.fromJSON jsonContent;

    # Read and parse product deploy.yaml
    readProductConfig = productName: let
      productDir = self + "/pkgs/products/${productName}";
      deployYamlPath = productDir + "/deploy.yaml";
      parsed = parseYaml deployYamlPath;
    in
      parsed;

    # Shared Hanabi (花火) web server location
    # All products use the same Hanabi binary with product-specific configs
    hanabiSrc = self + "/pkgs/platform/hanabi";

    # Auto-discover all web projects in a product
    # Products now use shared Hanabi instead of per-product web-server
    discoverWebProjects = productName: let
      productsDir = self + "/pkgs/products";
      productDir = productsDir + "/${productName}";
      webDir = productDir + "/web";
      productConfig = readProductConfig productName;

      # Check if web directory exists with frontend code
      # Products no longer need web-server subdirectory - they use shared Hanabi
      webDirExists = builtins.pathExists webDir;
      hasPackageJson = webDirExists && builtins.pathExists (webDir + "/package.json");

      # Check if this is a valid web project (just needs frontend, Hanabi is shared)
      isValidWebProject = webDirExists && hasPackageJson;
    in
      if isValidWebProject
      then [
        {
          name = "${productName}-web";
          value = {
            product = productName;
            service = "web";
            src = webDir;
            webServerSrc = hanabiSrc; # Use shared Hanabi for all products
            productConfig = productConfig;
          };
        }
      ]
      else [];

    # Discover web projects for all products
    allWebProjects = lib.fold (
      product: acc:
        acc ++ (discoverWebProjects product)
    ) [] ["novaskyn" "lilitu"];

    # Convert list to attrset
    allWebProjectsAttrset = lib.listToAttrs allWebProjects;

    # Build pleme-linker tool for linking TypeScript libraries
    # We need TWO versions:
    # 1. plemeLinker: for targetPkgs (runs inside Linux derivation builds on remote builder)
    # 2. plemeLinkerHost: for host pkgs (runs locally for development commands like regen)

    # Target version - runs inside Linux builds on remote builder
    plemeLinker = let
      cargoNix = self + "/pkgs/tools/rust/pleme-linker/Cargo.nix";
      project = import cargoNix {
        pkgs = targetPkgs; # Must match the platform where it runs (inside Linux derivations)
        defaultCrateOverrides =
          targetPkgs.defaultCrateOverrides
          // {
            pleme-linker = oldAttrs: {
              nativeBuildInputs = (oldAttrs.nativeBuildInputs or []) ++ (with targetPkgs; [cmake perl git]);
            };
          };
      };
    in
      project.rootCrate.build;

    # Host version - runs locally for development commands (regen, etc.)
    plemeLinkerHost = let
      cargoNix = self + "/pkgs/tools/rust/pleme-linker/Cargo.nix";
      project = import cargoNix {
        inherit pkgs; # Use host pkgs (native to developer's machine)
        defaultCrateOverrides =
          pkgs.defaultCrateOverrides
          // {
            pleme-linker = oldAttrs: {
              nativeBuildInputs = (oldAttrs.nativeBuildInputs or []) ++ (with pkgs; [cmake perl git]);
            };
          };
      };
    in
      project.rootCrate.build;

    # ============================================================================
    # Discover and build workspace libraries (@pleme/* packages)
    # ============================================================================
    # These are local TypeScript libraries in pkgs/libraries/typescript/
    # They're declared as file: dependencies in package.json
    #
    # WORKFLOW (pleme-linker full lifecycle):
    # 1. Each library has its own deps.nix (nix run .#regen:lib:<name>)
    # 2. Libraries are built as Nix derivations via pleme-linker build-library
    # 3. Product builds depend on library derivations
    # 4. No committed dist/ needed - everything built on-demand from source
    #
    # See: .claude/skills/pleme-linker-builds for details
    librariesDir = self + "/pkgs/libraries/typescript";

    # Build a single @pleme/* library as a Nix derivation
    # Uses pleme-linker build-library to run tsdown and produce dist/
    # IMPORTANT: Uses targetPkgs so builds run on the Linux remote builder
    mkPlemeLibrary = {
      name,
      src,
    }: let
      depsNixPath = src + "/deps.nix";
      hasDepsNix = builtins.pathExists depsNixPath;

      # If library has deps.nix, build via pleme-linker
      # Otherwise, fall back to source directory (must have committed dist/)
      builtLibrary =
        if hasDepsNix
        then let
          manifest = import depsNixPath;

          # Fetch all packages for the library's devDependencies
          # fetchurl is a FOD so it works with any pkgs
          fetchedPackages =
            lib.mapAttrs (
              key: pkg:
                targetPkgs.fetchurl {
                  inherit (pkg) url;
                  hash = pkg.integrity;
                  name = "${pkg.pname}-${pkg.version}.tgz";
                }
            )
            manifest.packages;

          # Generate manifest JSON for pleme-linker
          manifestJson = builtins.toJSON {
            packages =
              lib.mapAttrsToList (key: pkg: {
                pname = pkg.pname;
                version = pkg.version;
                tarball = fetchedPackages.${key};
                dependencies = pkg.dependencies or [];
                hasBin = pkg.hasBin or false;
              })
              manifest.packages;
            workspacePackages = []; # Libraries don't depend on other workspace packages during build
            # Root dependencies for proper hoisting (pnpm-style)
            rootDependencies = manifest.rootDependencies or [];
          };

          manifestFile = targetPkgs.writeText "${name}-manifest.json" manifestJson;
        in
          targetPkgs.runCommand "${name}-built" {
            nativeBuildInputs = [plemeLinker targetPkgs.nodejs_20];
          } ''
            ${plemeLinker}/bin/pleme-linker build-library \
              --src ${src} \
              --manifest ${manifestFile} \
              --output $out \
              --node-bin ${targetPkgs.nodejs_20}/bin/node
          ''
        else
          # Fallback: use source directory directly (must have committed dist/)
          src;
    in
      builtLibrary;

    # Auto-discover and build all @pleme/* libraries
    plemeLibraries = let
      libDir = self + "/pkgs/libraries/typescript";
      entries = builtins.readDir libDir;
      # Filter to directories that start with "pleme-"
      libNames =
        lib.filterAttrs (
          name: type:
            type == "directory" && lib.hasPrefix "pleme-" name
        )
        entries;
    in
      lib.mapAttrs (name: _:
        mkPlemeLibrary {
          inherit name;
          src = libDir + "/${name}";
        })
      libNames;

    # ============================================================================
    # Build Vite frontend using per-dependency fetching (pleme-linker resolve)
    # ============================================================================
    #
    # This follows our Nix-native package manager pattern:
    # 1. Developer runs `nix run .#regen:product:web` after changing package.json
    # 2. pleme-linker resolve queries npm registry directly (HTTP)
    # 3. Generates deps.nix with per-dependency URLs + integrity hashes
    # 4. Nix fetches each package individually using those hashes
    # 5. pleme-linker build assembles node_modules (pure Rust, no npm/pnpm)
    # 6. pleme-linker links workspace libraries (@pleme/*) at build time
    #
    # BUILD MODES (controlled by PLEME_BUILD_MODE env var):
    # - DEFAULT: Vite build (stable, production-tested)
    # - "rust": Experimental OXC bundler via pleme-linker (in development)
    #
    # Benefits:
    # - NO NPM/PNPM in sandbox - pure Rust tooling
    # - Per-dependency caching in Attic (better cache efficiency)
    # - Hashes from npm registry (no package manager lockfiles needed)
    # - Platform-aware: filters out darwin-only packages
    # - Complete dependency tree resolution with transitive deps
    # - Workspace packages handled by pleme-linker (not shell script)
    # ============================================================================

    # Check build mode from environment
    # DEFAULT: Vite build (stable, production-tested)
    # Set PLEME_BUILD_MODE=rust to use experimental OXC bundler
    buildMode = builtins.getEnv "PLEME_BUILD_MODE";
    useViteBuild = buildMode != "rust";

    # ============================================================================
    # Build frontend using pure Rust toolchain (pleme-linker build-project)
    # ============================================================================
    # DEFAULT build mode - uses pleme-linker with OXC for everything:
    # - node_modules built from deps.nix
    # - TypeScript compilation via OXC (Oxidation Compiler - pure Rust)
    # - No Vite or external Node.js dependencies for compilation
    #
    # OXC is the same technology that powers Rolldown (Vite's future bundler).
    # https://oxc.rs
    # ============================================================================
    mkRustFrontend = {
      product,
      service,
      src,
    }: let
      # Import the generated deps.nix (from pleme-linker resolve)
      depsNixPath = "${src}/deps.nix";
      manifest =
        if builtins.pathExists depsNixPath
        then import depsNixPath
        else
          throw ''
            No deps.nix found at ${depsNixPath}

            Run: nix run .#regen:${product}:${service}

            This will generate deps.nix with per-dependency hashes.
            (pleme-linker resolve queries npm registry directly)
          '';

      # Fetch all packages (same as Vite mode)
      fetchedPackages =
        lib.mapAttrs (
          name: pkg:
            pkgs.fetchurl {
              inherit (pkg) url;
              hash = pkg.integrity;
              name = "${pkg.pname}-${pkg.version}.tgz";
            }
        )
        manifest.packages;

      # Generate manifest JSON for pleme-linker
      manifestJson = builtins.toJSON {
        packages =
          lib.mapAttrsToList (key: pkg: {
            pname = pkg.pname;
            version = pkg.version;
            tarball = fetchedPackages.${key};
            dependencies = pkg.dependencies or [];
            hasBin = pkg.hasBin or false;
          })
          manifest.packages;

        workspacePackages =
          lib.mapAttrsToList (name: path: {
            name = "@pleme/${lib.removePrefix "pleme-" name}";
            path = path;
          })
          plemeLibraries;

        # Root dependencies for proper hoisting (pnpm-style)
        rootDependencies = manifest.rootDependencies or [];
      };

      manifestFile = pkgs.writeText "${product}-${service}-rust-manifest.json" manifestJson;

      # Build using pleme-linker build-project (pure Rust compilation)
      # Uses --use-tsc for now since Rolldown is stubbed
      rustApp = pkgs.stdenv.mkDerivation {
        name = "${product}-${service}-rust-build";
        inherit src;

        nativeBuildInputs = with pkgs; [
          plemeLinker
          nodejs_20
          gzip
          brotli
        ];

        configurePhase = ''
          runHook preConfigure

          # Set git metadata (build-time information from Nix)
          export VITE_GIT_SHA="${self.rev or self.dirtyRev or "development"}"
          export VITE_BUILD_TIMESTAMP="${toString self.lastModified}"

          runHook postConfigure
        '';

        buildPhase = ''
          runHook preBuild

          # Use pleme-linker build-project for TypeScript compilation
          # Uses OXC (Oxidation Compiler) - pure Rust, no Node.js dependency for compilation
          ${plemeLinker}/bin/pleme-linker build-project \
            --project . \
            --output $TMPDIR/build-output \
            --manifest ${manifestFile} \
            --node-bin ${pkgs.nodejs_20}/bin/node

          runHook postBuild
        '';

        installPhase = ''
          runHook preInstall
          mkdir -p $out

          # Copy the built output (dist directory from pleme-linker build-project)
          if [ -d "$TMPDIR/build-output/lib/dist" ]; then
            cp -r $TMPDIR/build-output/lib/dist/* $out/
          else
            echo "Error: dist directory not found in build output"
            ls -la $TMPDIR/build-output/
            exit 1
          fi

          runHook postInstall
        '';
      };
    in
      rustApp;

    # IMPORTANT: All derivations use targetPkgs so they run on the Linux builder
    mkViteFrontend = {
      product,
      service,
      src,
    }: let
      # Import the generated deps.nix (from pleme-linker resolve)
      depsNixPath = "${src}/deps.nix";
      manifest =
        if builtins.pathExists depsNixPath
        then import depsNixPath
        else
          throw ''
            No deps.nix found at ${depsNixPath}

            Run: nix run .#regen:${product}:${service}

            This will generate deps.nix with per-dependency hashes.
            (pleme-linker resolve queries npm registry directly)
          '';

      # ====================================================================
      # STEP 1: Fetch all packages (Fixed-Output Derivations with network)
      # ====================================================================
      # Each package is a separate fetchurl derivation, cached in Attic
      fetchedPackages =
        lib.mapAttrs (
          name: pkg:
            targetPkgs.fetchurl {
              inherit (pkg) url;
              # Nix accepts SRI hashes directly (sha512-base64...)
              hash = pkg.integrity;
              name = "${pkg.pname}-${pkg.version}.tgz";
            }
        )
        manifest.packages;

      # ====================================================================
      # STEP 2: Build node_modules directly (no npm/pnpm in sandbox)
      # ====================================================================
      # Instead of running a package manager in the sandbox, we build
      # node_modules directly using pleme-linker (pure Rust).
      #
      # This follows pnpm's virtual store pattern:
      # - Extract tarballs to .pnpm/{name}@{version}/node_modules/{name}/
      # - Create symlinks from node_modules/{name} to the correct version
      #
      # For multiple versions of the same package, we pick ONE to hoist to
      # the root node_modules (the first one encountered). Nested versions
      # would require full dependency resolution - skip for now.

      # Generate manifest JSON for pleme-linker
      # Includes both npm packages (tarballs) and workspace packages (source paths)
      manifestJson = builtins.toJSON {
        packages =
          lib.mapAttrsToList (key: pkg: {
            pname = pkg.pname;
            version = pkg.version;
            tarball = fetchedPackages.${key};
            # Include dependencies for nested symlink creation
            dependencies = pkg.dependencies or [];
            # Include hasBin for binary linking
            hasBin = pkg.hasBin or false;
          })
          manifest.packages;

        # Workspace packages: @pleme/* libraries from pkgs/libraries/typescript/
        # pleme-linker will symlink these into node_modules/@pleme/
        workspacePackages =
          lib.mapAttrsToList (name: path: {
            # pleme-hooks -> @pleme/hooks
            name = "@pleme/${lib.removePrefix "pleme-" name}";
            path = path;
          })
          plemeLibraries;

        # Root dependencies for proper hoisting (pnpm-style)
        # These are hoisted to root node_modules with priority over transitive deps
        rootDependencies = manifest.rootDependencies or [];
      };

      manifestFile = targetPkgs.writeText "${product}-${service}-manifest.json" manifestJson;

      nodeModules =
        targetPkgs.runCommand "${product}-${service}-node_modules" {
          nativeBuildInputs = [
            plemeLinker
          ];
        } ''
          # Use pleme-linker to build node_modules (pure Rust, no shell logic)
          ${plemeLinker}/bin/pleme-linker build-node-modules \
            --manifest ${manifestFile} \
            --output $out \
            --node-bin ${targetPkgs.nodejs_20}/bin/node
        '';

      # Build the Vite app using the node_modules
      # node_modules is pre-built by pleme-linker build command
      # NO PATH manipulation - directly reference binaries from derivations
      viteApp = targetPkgs.stdenv.mkDerivation {
        name = "${product}-${service}-build";
        inherit src;

        nativeBuildInputs = with targetPkgs; [
          nodejs_20
          gzip
          brotli
        ];

        configurePhase = ''
          runHook preConfigure

          # Symlink node_modules from the pre-built derivation
          # pleme-linker build already includes workspace packages
          ln -s ${nodeModules}/node_modules node_modules

          # Set git metadata (build-time information from Nix)
          export VITE_GIT_SHA="${self.rev or self.dirtyRev or "development"}"
          export VITE_BUILD_TIMESTAMP="${toString self.lastModified}"

          runHook postConfigure
        '';

        buildPhase = ''
          runHook preBuild

          # GraphQL codegen files (gql/*.ts) are now COMMITTED to the repo
          # This avoids running graphql-codegen in sandbox (has dependency issues)
          # Regenerate with: nix run .#codegen:lilitu

          # Call vite directly from the derivation - no PATH manipulation
          # Vite binary is at node_modules/.bin/vite (symlink to ../vite/bin/vite.js)
          ${nodeModules}/node_modules/.bin/vite build

          runHook postBuild
        '';

        installPhase = ''
          runHook preInstall
          mkdir -p $out
          cp -r dist/* $out/
          runHook postInstall
        '';
      };
    in
      viteApp;

    # Build Hanabi (shared BFF web server) using crate2nix (matching rust-services standards)
    mkWebServer = {
      product,
      service,
      webServerSrc,
    }: let
      architecture = "amd64";
      muslTarget = "x86_64-unknown-linux-musl";
      targetEnvNameUpper = "X86_64_UNKNOWN_LINUX_MUSL";
      cargoNix = webServerSrc + "/Cargo.nix";

      # Import crate2nix tools
      crate2nixTools = import "${crate2nix}/tools.nix" {pkgs = targetPkgs;};

      # Import pre-generated Cargo.nix
      project = import cargoNix {
        pkgs = targetPkgs;

        # Configure per-crate build overrides for musl static linking
        defaultCrateOverrides =
          targetPkgs.defaultCrateOverrides
          // {
            # Hanabi binary: static musl linking
            # NOTE: GIT_SHA is intentionally NOT set here to preserve cache stability.
            # Setting GIT_SHA via builtins.getEnv would bust the entire crate cache on every commit.
            # Instead, GIT_SHA is passed at runtime via environment variables.
            hanabi = oldAttrs: {
              nativeBuildInputs = (oldAttrs.nativeBuildInputs or []) ++ (with targetPkgs; [cmake perl git]);

              # Static linking configuration
              CARGO_BUILD_TARGET = muslTarget;
              "CARGO_TARGET_${targetEnvNameUpper}_RUSTFLAGS" = "-C target-feature=+crt-static -C link-arg=-s";
            };
          };
      };

      # Extract the built service binary
      # Hanabi is a single crate, not a workspace, so use rootCrate
      serviceBinary =
        if project ? workspaceMembers
        then project.workspaceMembers.hanabi.build
        else project.rootCrate.build;
    in
      serviceBinary;

    # Generate docker image for a web project
    mkWebProjectImage = {
      product,
      service,
      src,
      webServerSrc,
    }: let
      # Build frontend using selected build mode
      # DEFAULT: Vite build (stable, production-tested)
      # PLEME_BUILD_MODE=rust: Experimental OXC bundler via pleme-linker
      frontend =
        if useViteBuild
        then mkViteFrontend {inherit product service src;}
        else mkRustFrontend {inherit product service src;};

      # Build web-server
      webServer = mkWebServer {
        inherit product service webServerSrc;
      };

      # Create Docker image using nix-lib
      dockerImage = nixLibTarget.mkNodeDockerImage {
        appName = "${product}-${service}";
        builtApp = frontend;
        webServer = webServer;
        architecture = "amd64";
      };
    in
      dockerImage;

    # Generate all apps for a web project
    mkWebProjectApps = {
      product,
      service,
      src,
      webServerSrc,
      productConfig,
      dockerImage,
    }: let
      # Determine registry URL from product config
      registry =
        if productConfig ? registry && productConfig.registry ? url
        then productConfig.registry.url
        else "ghcr.io/pleme-io/nexus/${product}-${service}";

      # Determine namespace from product config
      namespace =
        if productConfig ? kubernetes && productConfig.kubernetes ? namespace
        then productConfig.kubernetes.namespace
        else "${product}-staging";

      # Create deployment apps using nix-lib
      deploymentApps = nixLibHost.mkWebDeploymentApps {
        appName = "${product}-${service}";
        inherit registry namespace;
        nexusDeploy = nexusDeployWrapper;
      };

      # Add a unified release app (build + push + deploy)
      # Docker image is pre-built by Nix (no nix build inside nexus-deploy)
      # Uses orchestrate-release command (same as rust services)
      # Manifest path is read from deploy.yaml (no shell logic needed)
      #
      # TEST ORDER: Pre-deployment tests are configured in deploy.yaml
      # and executed by nexus-deploy before push/deployment
      releaseApp = {
        type = "app";
        program = toString (pkgs.writeShellScript "${product}-${service}-release" ''
          set -euo pipefail

          # Add tools needed by nexus-deploy to PATH
          export PATH="${pkgs.skopeo}/bin:$PATH"

          # CRITICAL: Use inherited RELEASE_GIT_SHA if set (from combined product-release),
          # otherwise capture from git. This ensures all services in a combined release
          # use the same SHA, even if commits happen between service pushes.
          export RELEASE_GIT_SHA="''${RELEASE_GIT_SHA:-$(${pkgs.git}/bin/git rev-parse --short HEAD)}"

          # Get repo root and service directory
          REPO_ROOT=$(${pkgs.git}/bin/git rev-parse --show-toplevel 2>/dev/null || echo "$PWD")
          SERVICE_DIR="$REPO_ROOT/pkgs/products/${product}/${service}"

          # Ensure workspace dependencies are built (required before Nix build)
          ${nexusDeployWrapper}/bin/nexus-deploy ensure-workspace-deps --repo-root "$REPO_ROOT"

          echo "🚀 ${product}-${service} Release Workflow"
          echo "=================================================="
          echo ""
          echo "📦 Release Git SHA: $RELEASE_GIT_SHA"
          echo "📦 Docker image built by Nix: ${dockerImage}"
          echo "📦 Product: ${product}"
          echo "📦 Namespace: ${namespace}"
          echo ""
          echo "📂 Git repository: $REPO_ROOT"
          echo "📂 Service directory: $SERVICE_DIR"
          echo ""

          # Run nexus-deploy orchestrate-release
          # Pre-deployment tests are configured in deploy.yaml (pre_deployment_tests section)
          # Manifest path is read from deploy.yaml (manifests.kustomization field)
          exec ${nexusDeployWrapper}/bin/nexus-deploy orchestrate-release \
            --service ${service} \
            --service-dir "$SERVICE_DIR" \
            --repo-root "$REPO_ROOT" \
            --registry ${registry} \
            --namespace ${namespace} \
            --image-path ${dockerImage} \
            --watch \
            "$@"
        '');
      };

      # Regenerate deps.nix AND Cargo.nix for web project
      # Uses nexus-deploy web-regenerate command which handles:
      # 1. deps.nix (queries npm registry via pleme-linker)
      # 2. Cargo.nix for Hanabi (shared BFF web server via crate2nix)
      # Uses plemeLinkerHost (native to developer's machine) since this runs locally
      # (plemeLinker is for Linux builds inside derivations)
      regenerateApp = {
        type = "app";
        program = toString (pkgs.writeShellScript "${product}-${service}-regenerate" ''
          set -euo pipefail
          export PATH="${plemeLinkerHost}/bin:${crate2nix}/bin:$PATH"
          REPO_ROOT="$(${pkgs.git}/bin/git rev-parse --show-toplevel)"
          exec ${nexusDeployWrapper}/bin/nexus-deploy web-regenerate \
            --product ${product} \
            --service ${service} \
            --repo-root "$REPO_ROOT"
        '');
      };

      # Cargo update for Hanabi (shared BFF web server)
      # Updates Cargo.lock and regenerates Cargo.nix
      # NO SHELL SCRIPTS - all logic in Rust (nexus-deploy)
      cargoUpdateApp = {
        type = "app";
        program = toString (pkgs.writeShellScript "${product}-${service}-cargo-update" ''
          set -euo pipefail
          export PATH="${pkgs.cargo}/bin:${crate2nix}/bin:$PATH"
          REPO_ROOT="$(${pkgs.git}/bin/git rev-parse --show-toplevel)"
          exec ${nexusDeployWrapper}/bin/nexus-deploy web-cargo-update \
            --product ${product} \
            --service ${service} \
            --repo-root "$REPO_ROOT"
        '');
      };

      # Run tests (unit + integration) for web projects
      # Usage: nix run .#test:novaskyn:web [-- [unit|integration|all]]
      # Default: runs both unit and integration tests
      testApp = {
        type = "app";
        program = toString (pkgs.writeShellScript "${product}-${service}-test" ''
          set -euo pipefail

          # Resolve paths
          REPO_ROOT=$(${pkgs.git}/bin/git rev-parse --show-toplevel)
          SERVICE_DIR="$REPO_ROOT/pkgs/products/${product}/${service}"

          exec ${nexusDeployWrapper}/bin/nexus-deploy test \
            --service ${service} \
            --service-dir "$SERVICE_DIR" \
            --repo-root "$REPO_ROOT" \
            --service-type web \
            "$@"
        '');
      };

      # Show deployed status (reads config from deploy.yaml)
      statusApp = {
        type = "app";
        program = toString (pkgs.writeShellScript "${product}-${service}-status" ''
          set -euo pipefail

          # Resolve paths
          REPO_ROOT=$(${pkgs.git}/bin/git rev-parse --show-toplevel)
          SERVICE_DIR="$REPO_ROOT/pkgs/products/${product}/${service}"

          exec ${nexusDeployWrapper}/bin/nexus-deploy status \
            --service ${service} \
            --service-dir "$SERVICE_DIR" \
            --repo-root "$REPO_ROOT" \
            "$@"
        '');
      };

      # Development server (bun run dev)
      devApp = {
        type = "app";
        program = toString (pkgs.writeShellScript "${product}-${service}-dev" ''
          set -euo pipefail

          # Resolve paths
          REPO_ROOT=$(${pkgs.git}/bin/git rev-parse --show-toplevel)
          SERVICE_DIR="$REPO_ROOT/pkgs/products/${product}/${service}"

          cd "$SERVICE_DIR"

          # Ensure dependencies are installed
          if [ ! -d "node_modules" ]; then
            echo "📦 Installing dependencies with bun..."
            ${pkgs.bun}/bin/bun install
          fi

          echo "🚀 Starting ${product} ${service} development server..."
          exec ${pkgs.bun}/bin/bun run dev
        '');
      };

      # Production build (bun run build)
      buildApp = {
        type = "app";
        program = toString (pkgs.writeShellScript "${product}-${service}-build" ''
          set -euo pipefail

          # Resolve paths
          REPO_ROOT=$(${pkgs.git}/bin/git rev-parse --show-toplevel)
          SERVICE_DIR="$REPO_ROOT/pkgs/products/${product}/${service}"

          cd "$SERVICE_DIR"

          # Ensure dependencies are installed
          if [ ! -d "node_modules" ]; then
            echo "📦 Installing dependencies with bun..."
            ${pkgs.bun}/bin/bun install
          fi

          echo "🔨 Building ${product} ${service}..."
          exec ${pkgs.bun}/bin/bun run build
        '');
      };

      # TypeScript type checking (bun run type-check)
      typeCheckApp = {
        type = "app";
        program = toString (pkgs.writeShellScript "${product}-${service}-type-check" ''
          set -euo pipefail

          # Resolve paths
          REPO_ROOT=$(${pkgs.git}/bin/git rev-parse --show-toplevel)
          SERVICE_DIR="$REPO_ROOT/pkgs/products/${product}/${service}"

          cd "$SERVICE_DIR"

          # Ensure dependencies are installed
          if [ ! -d "node_modules" ]; then
            echo "📦 Installing dependencies with bun..."
            ${pkgs.bun}/bin/bun install
          fi

          echo "🔍 Type checking ${product} ${service}..."
          exec ${pkgs.bun}/bin/bun run type-check
        '');
      };

      # Linting (bun run lint)
      lintApp = {
        type = "app";
        program = toString (pkgs.writeShellScript "${product}-${service}-lint" ''
          set -euo pipefail

          # Resolve paths
          REPO_ROOT=$(${pkgs.git}/bin/git rev-parse --show-toplevel)
          SERVICE_DIR="$REPO_ROOT/pkgs/products/${product}/${service}"

          cd "$SERVICE_DIR"

          # Ensure dependencies are installed
          if [ ! -d "node_modules" ]; then
            echo "📦 Installing dependencies with bun..."
            ${pkgs.bun}/bin/bun install
          fi

          echo "🧹 Linting ${product} ${service}..."
          exec ${pkgs.bun}/bin/bun run lint "$@"
        '');
      };

      # Install dependencies (bun install)
      installApp = {
        type = "app";
        program = toString (pkgs.writeShellScript "${product}-${service}-install" ''
          set -euo pipefail

          # Resolve paths
          REPO_ROOT=$(${pkgs.git}/bin/git rev-parse --show-toplevel)
          SERVICE_DIR="$REPO_ROOT/pkgs/products/${product}/${service}"

          cd "$SERVICE_DIR"

          echo "📦 Installing ${product} ${service} dependencies with bun..."
          exec ${pkgs.bun}/bin/bun install "$@"
        '');
      };

      # Push pre-built Docker image to GHCR (build+push, no deploy)
      # Uses nexus-deploy push command
      pushImageApp = {
        type = "app";
        program = toString (pkgs.writeShellScript "${product}-${service}-push-image" ''
          set -euo pipefail

          # Add tools needed by nexus-deploy to PATH
          export PATH="${pkgs.skopeo}/bin:$PATH"

          # Get repo root for workspace deps check
          REPO_ROOT=$(${pkgs.git}/bin/git rev-parse --show-toplevel 2>/dev/null || echo "$PWD")

          # Ensure workspace dependencies are built (required before Nix build)
          ${nexusDeployWrapper}/bin/nexus-deploy ensure-workspace-deps --repo-root "$REPO_ROOT"

          echo "📦 Pushing ${product}-${service} image to GHCR"
          echo "$(printf '=%.0s' {1..50})"
          echo ""
          echo "📦 Docker image (Nix-built): ${dockerImage}"
          echo "🏷️  Registry: ${registry}"
          echo ""

          export GHCR_TOKEN="''${GITHUB_TOKEN:-}"
          if [ -z "$GHCR_TOKEN" ]; then
            GHCR_TOKEN=$(${pkgs.gh}/bin/gh auth token 2>/dev/null || echo "")
          fi

          if [ -z "$GHCR_TOKEN" ]; then
            echo "❌ GHCR_TOKEN not set. Set GITHUB_TOKEN or login with 'gh auth login'"
            exit 1
          fi
          export GHCR_TOKEN

          exec ${nexusDeployWrapper}/bin/nexus-deploy push \
            --image-path "${dockerImage}" \
            --registry "${registry}" \
            --auto-tags \
            --retries 3
        '');
      };
    in
      deploymentApps
      // {
        release = releaseApp;
        regenerate = regenerateApp;
        cargo-update = cargoUpdateApp;
        test = testApp;
        status = statusApp;
        dev = devApp;
        build = buildApp;
        type-check = typeCheckApp;
        lint = lintApp;
        install = installApp;
        push-image = pushImageApp;
      };

    # Generate docker images for all web projects
    webProjectImages =
      lib.mapAttrs (
        name: cfg:
          mkWebProjectImage {
            inherit (cfg) product service src webServerSrc;
          }
      )
      allWebProjectsAttrset;

    # Generate all apps for all web projects
    allWebProjectApps =
      lib.mapAttrs (
        name: cfg:
          mkWebProjectApps {
            inherit (cfg) product service src webServerSrc productConfig;
            dockerImage = webProjectImages.${name};
          }
      )
      allWebProjectsAttrset;

    # Extract release apps with product/service metadata
    webProjectReleases =
      lib.mapAttrs (name: apps: {
        app = apps.release;
        product = allWebProjectsAttrset.${name}.product;
        service = allWebProjectsAttrset.${name}.service;
      })
      allWebProjectApps;

    # Extract regenerate apps with product/service metadata
    webProjectRegenerates =
      lib.mapAttrs (name: apps: {
        app = apps.regenerate;
        product = allWebProjectsAttrset.${name}.product;
        service = allWebProjectsAttrset.${name}.service;
      })
      allWebProjectApps;

    # Extract cargo-update apps with product/service metadata
    webProjectCargoUpdates =
      lib.mapAttrs (name: apps: {
        app = apps.cargo-update;
        product = allWebProjectsAttrset.${name}.product;
        service = allWebProjectsAttrset.${name}.service;
      })
      allWebProjectApps;

    # Extract test apps with product/service metadata
    webProjectTests =
      lib.mapAttrs (name: apps: {
        app = apps.test;
        product = allWebProjectsAttrset.${name}.product;
        service = allWebProjectsAttrset.${name}.service;
      })
      allWebProjectApps;

    # Extract status apps with product/service metadata
    webProjectStatuses =
      lib.mapAttrs (name: apps: {
        app = apps.status;
        product = allWebProjectsAttrset.${name}.product;
        service = allWebProjectsAttrset.${name}.service;
      })
      allWebProjectApps;

    # Extract dev apps with product/service metadata
    webProjectDevs =
      lib.mapAttrs (name: apps: {
        app = apps.dev;
        product = allWebProjectsAttrset.${name}.product;
        service = allWebProjectsAttrset.${name}.service;
      })
      allWebProjectApps;

    # Extract build apps with product/service metadata
    webProjectBuilds =
      lib.mapAttrs (name: apps: {
        app = apps.build;
        product = allWebProjectsAttrset.${name}.product;
        service = allWebProjectsAttrset.${name}.service;
      })
      allWebProjectApps;

    # Extract type-check apps with product/service metadata
    webProjectTypeChecks =
      lib.mapAttrs (name: apps: {
        app = apps.type-check;
        product = allWebProjectsAttrset.${name}.product;
        service = allWebProjectsAttrset.${name}.service;
      })
      allWebProjectApps;

    # Extract lint apps with product/service metadata
    webProjectLints =
      lib.mapAttrs (name: apps: {
        app = apps.lint;
        product = allWebProjectsAttrset.${name}.product;
        service = allWebProjectsAttrset.${name}.service;
      })
      allWebProjectApps;

    # Extract install apps with product/service metadata
    webProjectInstalls =
      lib.mapAttrs (name: apps: {
        app = apps.install;
        product = allWebProjectsAttrset.${name}.product;
        service = allWebProjectsAttrset.${name}.service;
      })
      allWebProjectApps;

    # Extract push-image apps with product/service metadata
    webProjectPushImages =
      lib.mapAttrs (name: apps: {
        app = apps.push-image;
        product = allWebProjectsAttrset.${name}.product;
        service = allWebProjectsAttrset.${name}.service;
      })
      allWebProjectApps;
  in {
    # Export docker images as packages
    packages = webProjectImages;

    # Export release, regenerate, cargo-update, test, status, dev, build, type-check, lint, and install apps
    # Format: command:product:service (matching rust-services.nix pattern)
    apps =
      # Release apps: release:product:service
      (lib.mapAttrs' (name: data: {
          name = "release:${data.product}:${data.service}";
          value = data.app;
        })
        webProjectReleases)
      # Regenerate apps: regen:product:service
      // (lib.mapAttrs' (name: data: {
          name = "regen:${data.product}:${data.service}";
          value = data.app;
        })
        webProjectRegenerates)
      # Cargo-update apps: update:product:service
      // (lib.mapAttrs' (name: data: {
          name = "update:${data.product}:${data.service}";
          value = data.app;
        })
        webProjectCargoUpdates)
      # Test apps: test:product:service
      // (lib.mapAttrs' (name: data: {
          name = "test:${data.product}:${data.service}";
          value = data.app;
        })
        webProjectTests)
      # Status apps: status:product:service
      // (lib.mapAttrs' (name: data: {
          name = "status:${data.product}:${data.service}";
          value = data.app;
        })
        webProjectStatuses)
      # Dev apps: dev:product:service (start development server)
      // (lib.mapAttrs' (name: data: {
          name = "dev:${data.product}:${data.service}";
          value = data.app;
        })
        webProjectDevs)
      # Build apps: build:product:service (production build)
      // (lib.mapAttrs' (name: data: {
          name = "build:${data.product}:${data.service}";
          value = data.app;
        })
        webProjectBuilds)
      # Type-check apps: type-check:product:service
      // (lib.mapAttrs' (name: data: {
          name = "type-check:${data.product}:${data.service}";
          value = data.app;
        })
        webProjectTypeChecks)
      # Lint apps: lint:product:service
      // (lib.mapAttrs' (name: data: {
          name = "lint:${data.product}:${data.service}";
          value = data.app;
        })
        webProjectLints)
      # Install apps: install:product:service
      // (lib.mapAttrs' (name: data: {
          name = "install:${data.product}:${data.service}";
          value = data.app;
        })
        webProjectInstalls)
      # Push-image apps: push:product:service (build and push image to GHCR only)
      // (lib.mapAttrs' (name: data: {
          name = "push:${data.product}:${data.service}";
          value = data.app;
        })
        webProjectPushImages);
  };
}
