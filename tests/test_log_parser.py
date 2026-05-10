import io
from utils.log_parser import read_uploaded_file


def test_read_text_file():
    content = b"2024-01-15 ERROR something broke\n2024-01-15 WARN disk full"
    file = io.BytesIO(content)
    file.name = "test.log"
    result = read_uploaded_file(file)
    assert "something broke" in result
    assert "disk full" in result


def test_read_json_file():
    content = b'[{"level": "error", "msg": "OOM kill"}]'
    file = io.BytesIO(content)
    file.name = "test.json"
    result = read_uploaded_file(file)
    assert "OOM kill" in result


def test_read_csv_file():
    content = b"timestamp,level,message\n2024-01-15,ERROR,disk full"
    file = io.BytesIO(content)
    file.name = "test.csv"
    result = read_uploaded_file(file)
    assert "disk full" in result


def test_read_empty_file():
    file = io.BytesIO(b"")
    file.name = "empty.log"
    result = read_uploaded_file(file)
    assert result == ""
