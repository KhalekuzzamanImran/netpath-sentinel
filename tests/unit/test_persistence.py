from netpath_sentinel.domain.models import DiagnosticConfig
from netpath_sentinel.infrastructure.persistence import Repository


def test_repository_persists_diagnostic_session(tmp_path) -> None:
    repository = Repository(tmp_path / "sentinel.sqlite3")
    config = DiagnosticConfig(name="acceptance", destination_port=6000)
    repository.save_session("session-1", config)
    sessions = repository.list_sessions()
    assert len(sessions) == 1
    assert sessions[0].name == "acceptance"
    assert sessions[0].config["destination_port"] == 6000
