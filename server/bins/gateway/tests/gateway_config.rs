//! Configuration is tested at the loader's operator boundary against frozen Go.
use serde_json::Value;
use setjoin_gateway::configuration::Settings;

#[test]
fn recorded_configuration_layers_match_go() {
    let cases: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/gateway-config/layers.json"
    ))
    .unwrap();
    for case in cases.as_array().unwrap() {
        let env = case["env"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_owned()))
            .collect();
        let config = Settings::parse(case["yaml"].as_str().unwrap(), &env).unwrap();
        assert_eq!(config.projection(), case["expected"], "{}", case["name"]);
    }
}
