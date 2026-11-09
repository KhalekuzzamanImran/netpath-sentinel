import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from netpath_sentinel.presentation.desktop.app import MainWindow


def test_main_window_exposes_diagnostic_and_details_pages(qtbot, monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("NETPATH_SENTINEL_DATA_DIR", str(tmp_path))
    window = MainWindow()
    qtbot.addWidget(window)
    assert window.windowTitle() == "NetPath Sentinel"
    assert window.pages.count() == 8
    assert window.details.tabs.count() == 9
