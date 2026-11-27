import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
import lab_app
import dir_fuzzer as df

HERE = os.path.dirname(os.path.abspath(__file__))
WORDLIST = os.path.join(HERE, "..", "samples", "wordlist.txt")


@pytest.fixture()
def base():
    srv = lab_app.make_server(0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d" % srv.server_address[1]
    srv.shutdown()


def paths(rep):
    return {f["path"]: f for f in rep["findings"]}


def test_load_words_skips_comments():
    words = df.load_words(WORDLIST)
    assert "admin" in words
    assert not any(w.startswith("#") for w in words)


def test_load_words_dedupes_and_adds_extensions(tmp_path):
    p = tmp_path / "w.txt"
    p.write_text("config\nconfig\nrobots.txt\n")
    words = df.load_words(str(p), [".bak"])
    assert words == ["config", "config.bak", "robots.txt"]


def test_looks_like_404_soft_echoes_path():
    sigs = [{"status": 200, "length": 30, "junk": "zzzz",
             "shape": df.normalize(b"not found: zzzz", "zzzz")}]
    assert df.looks_like_404(200, b"not found: admin", sigs, "admin")
    assert not df.looks_like_404(200, b"DB_PASSWORD=labpass123", sigs, ".env")


def test_short_secret_file_is_not_hidden_by_soft_404(base):
    found = paths(df.run(base, [".env"]))
    assert ".env" not in found and "/.env" in found


def test_looks_like_404_real():
    sigs = [{"status": 404, "length": 10, "junk": "x", "shape": ""}]
    assert df.looks_like_404(404, b"", sigs)


def test_risk_levels():
    assert df.risk(".env", 200) == "high"
    assert df.risk("admin", 401) == "medium"
    assert df.risk("login", 200) == "low"
    assert df.risk("login", 404) == "none"


def test_finds_hidden_files(base):
    rep = df.run(base, df.load_words(WORDLIST))
    found = paths(rep)
    assert found["/.env"]["risk"] == "high"
    assert "/.git/HEAD" in found
    assert "/backup.zip" in found
    assert found["/admin"]["status"] == 401


def test_soft_404_is_filtered(base):
    rep = df.run(base, ["nothing-here", "dev", "old", "test"])
    assert rep["soft_404"] is True
    assert rep["findings"] == []


def test_redirect_is_not_followed(base):
    rep = df.run(base, ["assets"])
    f = paths(rep)["/assets"]
    assert f["status"] == 301
    assert f["redirect"] == "/assets/"


def test_extensions_find_backup(base):
    words = df.load_words(WORDLIST, [".bak"])
    found = paths(df.run(base, words))
    assert "/config.bak" in found
    assert found["/config.bak"]["risk"] == "high"


def test_high_findings_sorted_first(base):
    rep = df.run(base, df.load_words(WORDLIST))
    assert rep["findings"][0]["risk"] == "high"


def test_unreachable_target_raises():
    with pytest.raises(RuntimeError):
        df.run("http://127.0.0.1:1", ["admin"])


def test_refuses_remote_host():
    with pytest.raises(SystemExit):
        df.check_target("http://example.com", False)
    df.check_target("http://example.com", True)


def test_main_exit_code_and_json(base, capsys):
    code = df.main([base, "--wordlist", WORDLIST, "--json"])
    assert code == 1
    assert '"findings"' in capsys.readouterr().out
