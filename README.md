# <h1 align="center"> A Tangle Blueprint 🌐 </h1>

**A FROST Blueprint for Tangle Network.**

## 📚 Prerequisites

Before you can run this project, you will need to have the following software installed on your machine:

- [Rust](https://www.rust-lang.org/tools/install)
- [Forge](https://getfoundry.sh)
- [Tangle](https://github.com/tangle-network/tangle?tab=readme-ov-file#-getting-started-)

You will also need to install `cargo-tangle`, our CLI tool for creating and deploying Tangle Blueprints:

To install the Tangle CLI, run the following command:

> Supported on Linux, MacOS, and Windows (WSL2)

```bash
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/tangle-network/gadget/releases/download/cargo-tangle-v0.1.2/cargo-tangle-installer.sh | sh
```

Or, if you prefer to install the CLI from crates.io:

```bash
cargo install cargo-tangle --force # to get the latest version.
```

## 🚀 Getting Started

Once `cargo-tangle` is installed, you can create a new project with the following command:

```sh
cargo tangle blueprint create --name <project-name>
```

and follow the instructions to create a new project.

## 🛠️ Development

Once you have created a new project, you can run the following command to start the project:

```sh
cargo build
```
to build the project, and

```sh
cargo tangle blueprint deploy
```
to deploy the blueprint to the Tangle network.

## 📚 Overview

This project is about creating a simple Hello World Blueprint for Tangle and EigenLayer. Blueprints are specifications for Actively Validated Services (AVS) on the Tangle Network. An AVS is an off-chain service that runs arbitrary computations for a user-specified period of time.

Blueprints provide a useful abstraction, allowing developers to create reusable service infrastructures as if they were smart contracts. This enables developers to monetize their work and align long-term incentives with the success of their creations, benefiting proportionally to their Blueprint's usage.

For more details, please refer to the [project documentation](https://docs.tangle.tools/developers/blueprints).

## 📬 Feedback

If you have any feedback or issues, please feel free to open an issue on our [GitHub repository](https://github.com/tangle-network/blueprint-template/issues).

## 📜 License

This project is licensed under the unlicense License. See the [LICENSE](./LICENSE) file for more details.
