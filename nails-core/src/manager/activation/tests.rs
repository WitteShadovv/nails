use super::test_gate::{
    activation_gate_test_lock, maybe_block_after_activating_state_transition_inner,
};
use serial_test::serial;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

struct ActivationGateEnvGuard {
    gate: Option<OsString>,
    entered: Option<OsString>,
}

impl ActivationGateEnvGuard {
    fn capture() -> Self {
        Self {
            gate: std::env::var_os("NAILS_TEST_ACTIVATING_GATE_PATH"),
            entered: std::env::var_os("NAILS_TEST_ACTIVATING_ENTERED_PATH"),
        }
    }

    fn clear() {
        unsafe {
            std::env::remove_var("NAILS_TEST_ACTIVATING_GATE_PATH");
            std::env::remove_var("NAILS_TEST_ACTIVATING_ENTERED_PATH");
        }
    }

    fn set(gate_path: &Path, entered_path: Option<&Path>) {
        unsafe {
            std::env::set_var("NAILS_TEST_ACTIVATING_GATE_PATH", gate_path);
        }

        match entered_path {
            Some(path) => unsafe {
                std::env::set_var("NAILS_TEST_ACTIVATING_ENTERED_PATH", path);
            },
            None => unsafe {
                std::env::remove_var("NAILS_TEST_ACTIVATING_ENTERED_PATH");
            },
        }
    }
}

impl Drop for ActivationGateEnvGuard {
    fn drop(&mut self) {
        match &self.gate {
            Some(value) => unsafe {
                std::env::set_var("NAILS_TEST_ACTIVATING_GATE_PATH", value);
            },
            None => unsafe {
                std::env::remove_var("NAILS_TEST_ACTIVATING_GATE_PATH");
            },
        }

        match &self.entered {
            Some(value) => unsafe {
                std::env::set_var("NAILS_TEST_ACTIVATING_ENTERED_PATH", value);
            },
            None => unsafe {
                std::env::remove_var("NAILS_TEST_ACTIVATING_ENTERED_PATH");
            },
        }
    }
}

fn spawn_gate_releaser(gate_path: PathBuf, entered_path: PathBuf) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        for _ in 0..100 {
            if entered_path.exists() {
                break;
            }

            std::thread::sleep(Duration::from_millis(10));
        }

        if gate_path.exists() {
            std::fs::remove_file(&gate_path).expect("gate file should be removable");
        }
    })
}

#[test]
#[serial]
fn test_activation_gate_returns_immediately_when_disabled() {
    let _gate_lock = activation_gate_test_lock().lock().unwrap();
    let _env_guard = ActivationGateEnvGuard::capture();
    ActivationGateEnvGuard::clear();

    assert!(maybe_block_after_activating_state_transition_inner().is_ok());
}

#[test]
#[serial]
fn test_activation_gate_writes_default_entered_marker() {
    let _gate_lock = activation_gate_test_lock().lock().unwrap();
    let _env_guard = ActivationGateEnvGuard::capture();
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let gate_path = temp_dir.path().join("activation.gate");
    let entered_path = PathBuf::from(format!("{}.entered", gate_path.display()));
    std::fs::write(&gate_path, []).expect("gate file");
    ActivationGateEnvGuard::set(&gate_path, None);

    let releaser = spawn_gate_releaser(gate_path.clone(), entered_path.clone());
    maybe_block_after_activating_state_transition_inner().expect("gate should be released");
    releaser.join().expect("releaser thread should finish");

    assert!(
        entered_path.exists(),
        "default entered marker should be created"
    );
    assert!(!gate_path.exists(), "gate should be removed by releaser");
}

#[test]
#[serial]
fn test_activation_gate_writes_custom_entered_marker_and_creates_parent_dirs() {
    let _gate_lock = activation_gate_test_lock().lock().unwrap();
    let _env_guard = ActivationGateEnvGuard::capture();
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let gate_path = temp_dir.path().join("activation.gate");
    let entered_path = temp_dir.path().join("nested/markers/entered.marker");
    std::fs::write(&gate_path, []).expect("gate file");
    ActivationGateEnvGuard::set(&gate_path, Some(&entered_path));

    let releaser = spawn_gate_releaser(gate_path.clone(), entered_path.clone());
    maybe_block_after_activating_state_transition_inner().expect("gate should be released");
    releaser.join().expect("releaser thread should finish");

    assert!(
        entered_path.exists(),
        "custom entered marker should be created"
    );
    assert!(
        entered_path.parent().expect("marker parent").exists(),
        "custom marker parent directory should be created"
    );
}

#[test]
#[serial]
fn test_activation_gate_reports_directory_creation_failures() {
    let _gate_lock = activation_gate_test_lock().lock().unwrap();
    let _env_guard = ActivationGateEnvGuard::capture();
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let blocker = temp_dir.path().join("not-a-directory");
    let gate_path = temp_dir.path().join("activation.gate");
    let entered_path = blocker.join("entered.marker");
    std::fs::write(&blocker, b"blocker").expect("blocker file");
    ActivationGateEnvGuard::set(&gate_path, Some(&entered_path));

    let err = maybe_block_after_activating_state_transition_inner().expect_err("should fail");
    let msg = err.to_string();

    assert!(msg.contains("Failed to prepare activation test marker directory"));
}

#[test]
#[serial]
fn test_activation_gate_reports_marker_write_failures() {
    let _gate_lock = activation_gate_test_lock().lock().unwrap();
    let _env_guard = ActivationGateEnvGuard::capture();
    let temp_dir = tempfile::tempdir().expect("tempdir");
    let gate_path = temp_dir.path().join("activation.gate");
    let entered_path = temp_dir.path().join("entered-directory");
    std::fs::create_dir_all(&entered_path).expect("entered dir");
    ActivationGateEnvGuard::set(&gate_path, Some(&entered_path));

    let err = maybe_block_after_activating_state_transition_inner().expect_err("should fail");
    let msg = err.to_string();

    assert!(msg.contains("Failed to write activation test marker"));
}
