import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import fim


def make(tmp_path):
    (tmp_path / "a.txt").write_text("one")
    (tmp_path / "b.txt").write_text("two")
    return str(tmp_path)


def test_no_change(tmp_path):
    d = make(tmp_path)
    base = fim.scan(d)
    assert fim.compare(base, fim.scan(d)) == []


def test_modified(tmp_path):
    d = make(tmp_path)
    base = fim.scan(d)
    (tmp_path / "a.txt").write_text("changed")
    assert fim.compare(base, fim.scan(d)) == [("MODIFIED", "a.txt")]


def test_new_and_deleted(tmp_path):
    d = make(tmp_path)
    base = fim.scan(d)
    (tmp_path / "c.txt").write_text("x")
    os.remove(tmp_path / "b.txt")
    assert fim.compare(base, fim.scan(d)) == [("DELETED", "b.txt"), ("NEW", "c.txt")]


def test_permission(tmp_path):
    d = make(tmp_path)
    base = fim.scan(d)
    os.chmod(tmp_path / "a.txt", 0o777)
    assert fim.compare(base, fim.scan(d)) == [("PERMISSION", "a.txt")]


def test_known_hash(tmp_path):
    (tmp_path / "e.txt").write_text("")
    assert fim.sha256(str(tmp_path / "e.txt")) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
