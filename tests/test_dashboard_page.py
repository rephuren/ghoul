import re
from pathlib import Path

from ghoul import dashboard

PAGE = Path(dashboard.__file__).with_name("dashboard.html").read_text(encoding="utf-8")


def test_filter_controls_exist():
    for ident in ("f-ip", "f-attack", "p-prev", "p-next", "p-info"):
        assert f'id="{ident}"' in PAGE


def test_attack_options_match_api_labels():
    block = re.search(r'<select id="f-attack".*?</select>', PAGE, re.S)
    assert block
    options = re.findall(r"<option>([^<]+)</option>", block.group(0))
    assert options == dashboard.ATTACK_TYPES


def test_page_never_builds_markup_from_attacker_data():
    script = re.sub(r"//[^\n]*", "", PAGE[PAGE.index("<script>"):])  # комментарии не считаем
    assert "innerHTML" not in script and "insertAdjacentHTML" not in script and "document.write" not in script


def test_ip_filter_value_is_sent_as_query_parameter_not_concatenated():
    script = PAGE[PAGE.index("function sessionsUrl"):]
    assert "URLSearchParams" in script.split("}")[0] + "}" * 0 or "URLSearchParams" in script[:400]
    assert '"&ip="' not in script and "'&ip='" not in script


def test_state_survives_refresh():
    # страница и фильтры лежат в переменных, а refresh их только читает
    assert "const view = { page: 0" in PAGE
    body = re.search(r"async function refresh\(\) \{.*?\n  \}\n", PAGE, re.S)
    assert body and "view.page = 0" not in body.group(0)


def test_next_page_uses_extra_row_instead_of_a_count_query():
    assert "limit: PAGE + 1" in PAGE and "ses.slice(0, PAGE)" in PAGE
