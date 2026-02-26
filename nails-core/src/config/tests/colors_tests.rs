//! Tests for color scheme configuration

use crate::config::{ColorProfile, ColorSchemeConfig, DecoyProfile};

#[test]
fn test_color_scheme_config_serde_round_trip() {
    // Test serialization and deserialization of ColorSchemeConfig
    let config = ColorSchemeConfig {
        enabled: true,
        hidden: ColorProfile {
            background: "#1a1a2e".to_string(),
            foreground: "#e0e0e0".to_string(),
        },
        decoy: DecoyProfile { reset: true },
    };

    // Serialize to JSON
    let json = serde_json::to_string(&config).expect("Should serialize");
    assert!(json.contains("\"enabled\""));
    assert!(json.contains("\"hidden\""));
    assert!(json.contains("\"background\""));
    assert!(json.contains("\"foreground\""));
    assert!(json.contains("\"decoy\""));
    assert!(json.contains("\"reset\""));

    // Deserialize back
    let deserialized: ColorSchemeConfig = serde_json::from_str(&json).expect("Should deserialize");
    assert_eq!(deserialized, config);
}

#[test]
fn test_color_scheme_config_disabled() {
    let config = ColorSchemeConfig {
        enabled: false,
        hidden: ColorProfile::default(),
        decoy: DecoyProfile { reset: false },
    };

    let json = serde_json::to_string(&config).expect("Should serialize");
    let deserialized: ColorSchemeConfig = serde_json::from_str(&json).expect("Should deserialize");

    assert!(!deserialized.enabled);
    assert!(!deserialized.decoy.reset);
}

#[test]
fn test_color_scheme_config_custom_colors() {
    let config = ColorSchemeConfig {
        enabled: true,
        hidden: ColorProfile {
            background: "#2e3440".to_string(),
            foreground: "#d8dee9".to_string(),
        },
        decoy: DecoyProfile { reset: true },
    };

    let json = serde_json::to_string(&config).expect("Should serialize");
    assert!(json.contains("#2e3440"));
    assert!(json.contains("#d8dee9"));

    let deserialized: ColorSchemeConfig = serde_json::from_str(&json).expect("Should deserialize");
    assert_eq!(deserialized.hidden.background, "#2e3440");
    assert_eq!(deserialized.hidden.foreground, "#d8dee9");
}
