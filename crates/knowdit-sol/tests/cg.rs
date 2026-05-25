use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use knowdit_sol::cg::{
    SolidityCallableKind, SolidityContractKind, SolidityFunctionNodeKind, SoliditySourceInput,
    extract_contracts_functions, filter_analysis_source_files,
};

/// Read every test fixture file at `<repo>/<relative>` into a
/// `SoliditySourceInput` so we can call the now-content-based
/// `extract_contracts_functions` API.
async fn read_inputs(repo: &TempRepo, relatives: &[PathBuf]) -> Vec<SoliditySourceInput> {
    let mut out = Vec::with_capacity(relatives.len());
    for relative in relatives {
        let abs = repo.path.join(relative);
        let content = tokio::fs::read_to_string(&abs)
            .await
            .expect("test fixture must be readable");
        out.push(SoliditySourceInput {
            relative_path: relative.clone(),
            content,
        });
    }
    out
}

struct TempRepo {
    path: PathBuf,
}

impl TempRepo {
    fn new() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "knowdit-sol-cg-test-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("failed to create temp repo");
        Self { path }
    }

    fn write(&self, relative_path: &str, content: &str) {
        let path = self.path.join(relative_path);
        fs::create_dir_all(path.parent().expect("test path should have parent"))
            .expect("failed to create parent directory");
        fs::write(path, content).expect("failed to write test file");
    }
}

impl Drop for TempRepo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn callable_map(
    contract: &knowdit_sol::cg::ExtractedContract,
) -> BTreeMap<(&str, SolidityCallableKind), &knowdit_sol::cg::ExtractedCallable> {
    contract
        .functions
        .iter()
        .map(|function| ((function.name.as_str(), function.kind), function))
        .collect()
}

#[tokio::test]
async fn filters_analysis_scope_from_concrete_paths() {
    let source_files = vec![
        PathBuf::from("src/App.sol"),
        PathBuf::from("node_modules/Dep.sol"),
        PathBuf::from("target/Generated.sol"),
    ];

    let analysis_files =
        filter_analysis_source_files(source_files.clone(), vec![PathBuf::from("src/App.sol")])
            .expect("analysis scope filtering should succeed");

    assert_eq!(analysis_files, vec![PathBuf::from("src/App.sol")]);
    assert_eq!(
        filter_analysis_source_files(source_files.clone(), Vec::new())
            .expect("empty analysis set should default to all source files"),
        vec![
            PathBuf::from("node_modules/Dep.sol"),
            PathBuf::from("src/App.sol"),
            PathBuf::from("target/Generated.sol")
        ]
    );
}

#[tokio::test]
async fn extracts_raw_parameter_lists_and_modifier_callables() {
    let repo = TempRepo::new();
    repo.write(
        "contracts/Test.sol",
        r#"pragma solidity ^0.8.20;

contract Test {
    modifier onlyOwner(uint256 amount) {
        _;
    }

    constructor(address owner) {}

    receive() external payable {}

    fallback(bytes calldata data) external returns (bytes memory) {
        return data;
    }

    function transfer(address to, uint256 amount) public onlyOwner(amount) {
        helper(to);
    }

    function helper(address to) internal {}
}

library Lib {
    function ping(uint256 value) internal {}
}
"#,
    );

    let files = vec![PathBuf::from("contracts/Test.sol")];
    let inputs = read_inputs(&repo, &files).await;
    let contracts =
        extract_contracts_functions(&inputs).expect("tree-sitter extraction should succeed");

    let test_contract = contracts
        .iter()
        .find(|contract| contract.name == "Test")
        .expect("Test contract should be extracted");
    assert_eq!(test_contract.kind, SolidityContractKind::Contract);

    let functions = callable_map(test_contract);
    assert_eq!(
        functions
            .get(&("onlyOwner", SolidityCallableKind::Modifier))
            .expect("modifier should be extracted")
            .args,
        "uint256 amount"
    );
    assert_eq!(
        functions
            .get(&("constructor", SolidityCallableKind::Constructor))
            .expect("constructor should be extracted")
            .args,
        "address owner"
    );
    assert_eq!(
        functions
            .get(&("receive", SolidityCallableKind::Receive))
            .expect("receive should be extracted")
            .args,
        ""
    );
    assert_eq!(
        functions
            .get(&("fallback", SolidityCallableKind::Fallback))
            .expect("fallback should be extracted")
            .args,
        "bytes calldata data"
    );
    assert_eq!(
        functions
            .get(&("transfer", SolidityCallableKind::Function))
            .expect("transfer should be extracted")
            .args,
        "address to, uint256 amount"
    );

    let lib_contract = contracts
        .iter()
        .find(|contract| contract.name == "Lib")
        .expect("Lib library should be extracted");
    assert_eq!(lib_contract.kind, SolidityContractKind::Library);
    assert_eq!(lib_contract.functions[0].name, "ping");
    assert_eq!(lib_contract.functions[0].args, "uint256 value");
}

#[tokio::test]
async fn preserves_functions_with_if_bodies() {
    let repo = TempRepo::new();
    repo.write(
        "contracts/Branching.sol",
        r#"pragma solidity ^0.8.20;

contract Branching {
    function choose(uint256 amount, address recipient) public returns (uint256 result) {
        if (amount > 10) {
            return amount;
        }

        return 0;
    }
}
"#,
    );

    let files = vec![PathBuf::from("contracts/Branching.sol")];
    let inputs = read_inputs(&repo, &files).await;
    let contracts =
        extract_contracts_functions(&inputs).expect("tree-sitter extraction should succeed");
    let branching = contracts
        .iter()
        .find(|contract| contract.name == "Branching")
        .expect("Branching contract should be extracted");
    let choose = branching
        .functions
        .iter()
        .find(|function| function.name == "choose")
        .expect("choose function should be extracted");

    assert_eq!(choose.args, "uint256 amount, address recipient");
    assert!(choose.chunk.content.contains("if (amount > 10)"));
    assert!(choose.chunk.content.contains("returns (uint256 result)"));
}

#[tokio::test]
async fn extracts_multiple_contract_like_declarations_across_files() {
    let repo = TempRepo::new();
    repo.write(
        "src/Interfaces.sol",
        r#"pragma solidity ^0.8.20;

interface IRouter {
    function route(address token, uint256 amount) external returns (bool ok);
}
"#,
    );
    repo.write(
        "src/Implementations.sol",
        r#"pragma solidity ^0.8.20;

contract Router {
    function route(address token, uint256 amount) external returns (bool ok) {
        return amount > 0 && token != address(0);
    }
}

contract Vault {
    modifier onlyRouter(address router) {
        _;
    }

    function deposit(address token, uint256 amount, address router) public onlyRouter(router) {}
}
"#,
    );

    let files = vec![
        PathBuf::from("src/Interfaces.sol"),
        PathBuf::from("src/Implementations.sol"),
    ];
    let inputs = read_inputs(&repo, &files).await;
    let contracts =
        extract_contracts_functions(&inputs).expect("tree-sitter extraction should succeed");
    let by_name = contracts
        .iter()
        .map(|contract| (contract.name.as_str(), contract))
        .collect::<BTreeMap<_, _>>();

    assert_eq!(by_name["IRouter"].kind, SolidityContractKind::Interface);
    assert_eq!(by_name["Router"].kind, SolidityContractKind::Contract);
    assert_eq!(by_name["Vault"].kind, SolidityContractKind::Contract);

    let interface_functions = callable_map(by_name["IRouter"]);
    assert_eq!(
        interface_functions
            .get(&("route", SolidityCallableKind::Function))
            .expect("IRouter.route should be extracted")
            .node_kind,
        SolidityFunctionNodeKind::InterfaceFunctionDeclaration
    );

    let router_functions = callable_map(by_name["Router"]);
    let router_route = router_functions
        .get(&("route", SolidityCallableKind::Function))
        .expect("Router.route should be extracted");
    assert_eq!(router_route.args, "address token, uint256 amount");
    assert_eq!(
        router_route.node_kind,
        SolidityFunctionNodeKind::ContractFunctionDefinition
    );

    let vault_functions = callable_map(by_name["Vault"]);
    assert_eq!(
        vault_functions
            .get(&("onlyRouter", SolidityCallableKind::Modifier))
            .expect("Vault.onlyRouter modifier should be extracted")
            .args,
        "address router"
    );
    assert_eq!(
        vault_functions
            .get(&("deposit", SolidityCallableKind::Function))
            .expect("Vault.deposit should be extracted")
            .args,
        "address token, uint256 amount, address router"
    );
}

#[tokio::test]
async fn preserves_relative_paths_for_duplicate_contract_names() {
    let repo = TempRepo::new();
    repo.write(
        "src/one/Duplicate.sol",
        r#"pragma solidity ^0.8.20;

contract Duplicate {
    function first(uint256 amount) public {}
}
"#,
    );
    repo.write(
        "src/two/Duplicate.sol",
        r#"pragma solidity ^0.8.20;

contract Duplicate {
    function second(address recipient) public {}
}
"#,
    );

    let files = vec![
        PathBuf::from("src/one/Duplicate.sol"),
        PathBuf::from("src/two/Duplicate.sol"),
    ];
    let inputs = read_inputs(&repo, &files).await;
    let contracts =
        extract_contracts_functions(&inputs).expect("tree-sitter extraction should succeed");
    let duplicate_contracts = contracts
        .iter()
        .filter(|contract| contract.name == "Duplicate")
        .collect::<Vec<_>>();

    assert_eq!(duplicate_contracts.len(), 2);
    assert_eq!(
        duplicate_contracts
            .iter()
            .map(|contract| contract.relative_file_path.clone())
            .collect::<Vec<_>>(),
        vec![
            PathBuf::from("src/one/Duplicate.sol"),
            PathBuf::from("src/two/Duplicate.sol")
        ]
    );
}
