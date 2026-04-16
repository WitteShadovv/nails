use super::super::tests_common::*;
use super::*;

#[test]
fn prompt_session_kill_confirmation_yes_flag_bypasses_validation() {
    let ctx = SessionContext {
        kind: SessionKind::Tty,
        session_id: None,
        display_manager: None,
        target_uid: None,
        target_user: None,
        logind_available: false,
    };

    assert!(prompt_session_kill_confirmation(&ctx, true).is_ok());
}

#[test]
fn prompt_session_kill_confirmation_requires_graphical_user_session() {
    let ctx = SessionContext {
        kind: SessionKind::Tty,
        session_id: None,
        display_manager: None,
        target_uid: None,
        target_user: None,
        logind_available: false,
    };

    let err = prompt_session_kill_confirmation(&ctx, false).unwrap_err();
    assert!(
        err.to_string()
            .contains("Cannot confirm session kill - not a graphical user session")
    );
}

#[test]
fn prompt_session_kill_confirmation_accepts_y_input() {
    let ctx = SessionContext {
        kind: SessionKind::GraphicalUser,
        session_id: Some("c1".to_string()),
        display_manager: Some("gdm".to_string()),
        target_uid: Some(1000),
        target_user: Some("alice".to_string()),
        logind_available: true,
    };

    let mut reader = std::io::Cursor::new("y\n");
    assert!(prompt_session_kill_confirmation_with_reader(&ctx, false, &mut reader).is_ok());
}

#[test]
fn prompt_session_kill_confirmation_accepts_yes_input() {
    let ctx = SessionContext {
        kind: SessionKind::GraphicalUser,
        session_id: Some("c1".to_string()),
        display_manager: Some("gdm".to_string()),
        target_uid: Some(1000),
        target_user: Some("alice".to_string()),
        logind_available: true,
    };

    let mut reader = std::io::Cursor::new("yes\n");
    assert!(prompt_session_kill_confirmation_with_reader(&ctx, false, &mut reader).is_ok());
}

#[test]
fn prompt_session_kill_confirmation_rejects_n_input() {
    let ctx = SessionContext {
        kind: SessionKind::GraphicalUser,
        session_id: Some("c1".to_string()),
        display_manager: Some("gdm".to_string()),
        target_uid: Some(1000),
        target_user: Some("alice".to_string()),
        logind_available: true,
    };

    let mut reader = std::io::Cursor::new("n\n");
    let err = prompt_session_kill_confirmation_with_reader(&ctx, false, &mut reader).unwrap_err();
    assert!(
        err.to_string()
            .contains("User declined session kill confirmation")
    );
}

#[test]
fn prompt_session_kill_confirmation_rejects_empty_input() {
    let ctx = SessionContext {
        kind: SessionKind::GraphicalUser,
        session_id: Some("c1".to_string()),
        display_manager: Some("gdm".to_string()),
        target_uid: Some(1000),
        target_user: Some("alice".to_string()),
        logind_available: true,
    };

    let mut reader = std::io::Cursor::new("\n");
    let err = prompt_session_kill_confirmation_with_reader(&ctx, false, &mut reader).unwrap_err();
    assert!(
        err.to_string()
            .contains("User declined session kill confirmation")
    );
}

#[test]
fn prompt_session_kill_confirmation_case_insensitive() {
    let ctx = SessionContext {
        kind: SessionKind::GraphicalUser,
        session_id: Some("c1".to_string()),
        display_manager: Some("gdm".to_string()),
        target_uid: Some(1000),
        target_user: Some("alice".to_string()),
        logind_available: true,
    };

    let mut reader = std::io::Cursor::new("Y\n");
    assert!(prompt_session_kill_confirmation_with_reader(&ctx, false, &mut reader).is_ok());

    let mut reader = std::io::Cursor::new("YES\n");
    assert!(prompt_session_kill_confirmation_with_reader(&ctx, false, &mut reader).is_ok());
}

#[test]
fn kill_graphical_session_rejects_non_graphical_session() {
    let ctx = SessionContext {
        kind: SessionKind::Tty,
        session_id: None,
        display_manager: None,
        target_uid: None,
        target_user: None,
        logind_available: false,
    };
    let exec = MockSessionCommandExecutor::new(true, true, true);

    let err = kill_graphical_session_with_executor(&ctx, &exec).unwrap_err();
    assert!(
        err.to_string()
            .contains("Not running in a graphical user session")
    );
}

#[test]
fn wait_for_user_manager_exit_returns_true_when_unit_is_inactive() {
    let exec = ScriptedSessionCommandExecutor::new(
        vec![Ok((false, "inactive".to_string(), String::new()))],
        vec![],
        true,
    );

    let exited = wait_for_user_manager_exit(&exec, 1000, Duration::from_millis(1)).unwrap();

    assert!(exited);
}

#[test]
fn wait_for_user_manager_exit_returns_false_after_timeout() {
    let exec = ScriptedSessionCommandExecutor::new(
        vec![
            Ok((true, "active".to_string(), String::new())),
            Ok((true, "active".to_string(), String::new())),
        ],
        vec![],
        true,
    );

    let exited = wait_for_user_manager_exit(&exec, 1000, Duration::from_millis(1)).unwrap();

    assert!(!exited);
}

#[test]
fn wait_for_user_manager_exit_propagates_systemctl_error() {
    let exec = ScriptedSessionCommandExecutor::new(
        vec![Err(NailsError::IoError(std::io::Error::other(
            "systemctl failed",
        )))],
        vec![],
        true,
    );

    assert!(wait_for_user_manager_exit(&exec, 1000, Duration::from_millis(1)).is_err());
}

#[test]
fn wait_for_user_manager_exit_retries_until_inactive() {
    let exec = RecordingScriptedSessionCommandExecutor::new(
        vec![
            Ok((true, "active".to_string(), String::new())),
            Ok((false, "inactive".to_string(), String::new())),
        ],
        vec![],
        true,
    );

    let exited = wait_for_user_manager_exit(&exec, 1000, Duration::from_millis(500)).unwrap();

    assert!(exited);
    assert_eq!(exec.systemctl_calls().len(), 2);
}

#[test]
fn wait_for_user_manager_exit_treats_non_active_success_output_as_exited() {
    let exec = ScriptedSessionCommandExecutor::new(
        vec![Ok((true, "failed".to_string(), String::new()))],
        vec![],
        true,
    );

    let exited = wait_for_user_manager_exit(&exec, 1000, Duration::from_millis(1)).unwrap();

    assert!(exited);
}

#[test]
fn restart_display_manager_returns_error_when_start_fails() {
    let exec = ScriptedSessionCommandExecutor::new(
        vec![Ok((false, String::new(), "boom".to_string()))],
        vec![],
        true,
    );

    let err = restart_display_manager_with_executor("display-manager", &exec).unwrap_err();
    assert!(
        err.to_string()
            .contains("Failed to start display manager display-manager: boom")
    );
}

#[test]
fn restart_display_manager_retries_until_service_becomes_active() {
    let exec = RecordingScriptedSessionCommandExecutor::new(
        vec![
            Ok((true, String::new(), String::new())),
            Ok((false, "inactive".to_string(), String::new())),
            Ok((true, "active".to_string(), String::new())),
        ],
        vec![],
        true,
    );

    assert!(restart_display_manager_with_executor("display-manager", &exec).is_ok());
    assert_eq!(
        exec.systemctl_calls(),
        vec![
            vec!["start".to_string(), "display-manager".to_string()],
            vec!["is-active".to_string(), "display-manager".to_string()],
            vec!["is-active".to_string(), "display-manager".to_string()],
        ]
    );
}

#[test]
fn restart_display_manager_propagates_is_active_error_after_start() {
    let exec = ScriptedSessionCommandExecutor::new(
        vec![
            Ok((true, String::new(), String::new())),
            Err(NailsError::IoError(std::io::Error::other(
                "systemctl failed",
            ))),
        ],
        vec![],
        true,
    );

    let err = restart_display_manager_with_executor("display-manager", &exec).unwrap_err();
    assert!(err.to_string().contains("systemctl failed"));
}

#[test]
fn restart_user_manager_returns_error_when_user_service_fails() {
    let exec = ScriptedSessionCommandExecutor::new(
        vec![
            Ok((true, String::new(), String::new())),
            Ok((false, String::new(), "boom".to_string())),
        ],
        vec![],
        true,
    );

    let err = restart_user_manager_with_executor(1000, &exec).unwrap_err();
    assert!(
        err.to_string()
            .contains("Failed to start user manager user@1000.service: boom")
    );
}

#[test]
fn restart_user_manager_succeeds_even_if_runtime_dir_start_fails() {
    let exec = ScriptedSessionCommandExecutor::new(
        vec![
            Err(NailsError::IoError(std::io::Error::other(
                "runtime-dir failed",
            ))),
            Ok((true, String::new(), String::new())),
        ],
        vec![],
        true,
    );

    assert!(restart_user_manager_with_executor(1000, &exec).is_ok());
}

#[test]
fn restart_user_manager_starts_runtime_service_before_user_service() {
    let exec = RecordingScriptedSessionCommandExecutor::new(
        vec![
            Ok((true, String::new(), String::new())),
            Ok((true, String::new(), String::new())),
        ],
        vec![],
        true,
    );

    assert!(restart_user_manager_with_executor(1000, &exec).is_ok());
    assert_eq!(
        exec.systemctl_calls(),
        vec![
            vec![
                "start".to_string(),
                "user-runtime-dir@1000.service".to_string()
            ],
            vec!["start".to_string(), "user@1000.service".to_string()],
        ]
    );
}

#[test]
fn restart_display_manager_uses_systemctl() {
    let exec = MockSessionCommandExecutor::new(true, true, true);
    let res = restart_display_manager_with_executor("display-manager", &exec);
    assert!(res.is_ok());
}
