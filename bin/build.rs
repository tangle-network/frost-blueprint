use blueprint_sdk::build;
use blueprint_sdk::tangle::blueprint;
use frost_blueprint::{keygen, sign};
use std::path::Path;
use std::process;

fn main() {
    let contract_dirs: Vec<&str> = vec!["../contracts"];
    build::utils::soldeer_install();
    build::utils::soldeer_update();
    build::utils::build_contracts(contract_dirs);

    println!("cargo::rerun-if-changed=../bin");

    let blueprint = blueprint! {
        name: "frost-blueprint",
        master_manager_revision: "Latest",
        manager: { Evm = "FrostBlueprint" },
        jobs: [keygen, sign]
    };

    match blueprint {
        Ok(blueprint) => {
            // TODO: Should be a helper function probably
            let json = blueprint_sdk::tangle::metadata::macros::ext::serde_json::to_string_pretty(
                &blueprint,
            )
            .unwrap();
            std::fs::write(Path::new("../").join("blueprint.json"), json.as_bytes()).unwrap();
        }
        Err(e) => {
            println!("cargo::error={e:?}");
            process::exit(1);
        }
    }
}
