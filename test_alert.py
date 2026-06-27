"""
Unit tests for alert_rules.py.

These use small, synthetic DataFrames instead of the real dataset, so
they verify rule LOGIC independent of any specific data file - the
kind of test that should keep passing even if the Mordor APT29 CSVs
ever change, and that would have caught the path-parsing bug (the
"program" mislabeling) immediately if it had existed sooner.

Run with: pytest tests/
"""

import pandas as pd
import pytest

from alert_rules import (
    detect_lateral_movement,
    detect_short_lived_tool,
    detect_suspicious_spawn,
    detect_anti_forensics,
    detect_obfuscated_command,
    run_all_rules,
)


# ---------------------------------------------------------------
# Alert 1: Lateral Movement
# ---------------------------------------------------------------

def make_logon(user, remote, elevated, ts="2020-05-02 03:00:00"):
    return {'TargetUserName': user, 'is_remote_logon': remote, 'was_elevated': elevated, '@timestamp': ts}


def test_lateral_movement_fires_on_remote_and_elevated():
    logons = pd.DataFrame([make_logon('pbeesly', True, True)])
    result = detect_lateral_movement(logons)
    assert len(result) == 1
    assert result.iloc[0]['severity'] == 'High'
    assert result.iloc[0]['alert_type'] == 'Lateral Movement'


@pytest.mark.parametrize("remote,elevated", [(True, False), (False, True), (False, False)])
def test_lateral_movement_silent_unless_both_conditions_met(remote, elevated):
    logons = pd.DataFrame([make_logon('pbeesly', remote, elevated)])
    assert len(detect_lateral_movement(logons)) == 0


def test_lateral_movement_excludes_machine_accounts():
    logons = pd.DataFrame([make_logon('SCRANTON$', True, True)])
    assert len(detect_lateral_movement(logons)) == 0


# ---------------------------------------------------------------
# Alert 2: Suspicious Short-Lived Tool
# ---------------------------------------------------------------

def make_proc(user, name, duration, ts="2020-05-02 03:00:00",
              office_spawn=False, svchost=False, command_line=""):
    return {
        'SubjectUserName': user, 'NewProcessName': name, 'duration_seconds': duration,
        '@timestamp': ts, 'suspicious_office_spawn': office_spawn, 'suspicious_svchost': svchost,
        'CommandLine': command_line,
    }


def test_short_lived_tool_fires_under_one_second():
    proc = pd.DataFrame([make_proc('pbeesly', 'rar.exe', 0.5)])
    result = detect_short_lived_tool(proc)
    assert len(result) == 1
    assert result.iloc[0]['severity'] == 'Medium'
    assert 'rar.exe' in result.iloc[0]['reason']


@pytest.mark.parametrize("duration", [1.0, 5.0, float('nan'), -1.0])
def test_short_lived_tool_silent_outside_under_one_second(duration):
    proc = pd.DataFrame([make_proc('pbeesly', 'rar.exe', duration)])
    assert len(detect_short_lived_tool(proc)) == 0


@pytest.mark.parametrize("user,name", [
    ('SCRANTON$', 'rar.exe'),
    ('LOCAL SERVICE', 'rar.exe'),
    ('pbeesly', 'conhost.exe'),
])
def test_short_lived_tool_excludes_known_noise(user, name):
    proc = pd.DataFrame([make_proc(user, name, 0.1)])
    assert len(detect_short_lived_tool(proc)) == 0


def test_short_lived_tool_excludes_anti_forensics_tools_to_avoid_double_counting():
    """sdelete64.exe should only ever appear in Alert 4, never Alert 2,
    even when it happens to run in under a second."""
    proc = pd.DataFrame([make_proc('pbeesly', 'sdelete64.exe', 0.05)])
    assert len(detect_short_lived_tool(proc)) == 0


# ---------------------------------------------------------------
# Alert 3: Suspicious Spawn
# ---------------------------------------------------------------

def test_suspicious_spawn_fires_on_office_spawn():
    proc = pd.DataFrame([make_proc('pbeesly', 'cmd.exe', 2.0, office_spawn=True)])
    result = detect_suspicious_spawn(proc)
    assert len(result) == 1
    assert 'Office' in result.iloc[0]['reason']


def test_suspicious_spawn_fires_on_svchost_pattern():
    proc = pd.DataFrame([make_proc('pbeesly', 'svchost.exe', 2.0, svchost=True)])
    result = detect_suspicious_spawn(proc)
    assert len(result) == 1
    assert 'svchost' in result.iloc[0]['reason']


def test_suspicious_spawn_silent_when_neither_pattern_present():
    proc = pd.DataFrame([make_proc('pbeesly', 'notepad.exe', 2.0)])
    assert len(detect_suspicious_spawn(proc)) == 0


# ---------------------------------------------------------------
# Alert 4: Anti-Forensics Tool
# ---------------------------------------------------------------

@pytest.mark.parametrize("duration", [0.05, 3.0, float('nan')])
def test_anti_forensics_fires_regardless_of_duration(duration):
    """The whole point of Alert 4: unlike Alert 2, duration must never
    gate this - a slow sdelete run on a large file is just as real."""
    proc = pd.DataFrame([make_proc('pbeesly', 'sdelete64.exe', duration)])
    result = detect_anti_forensics(proc)
    assert len(result) == 1
    assert result.iloc[0]['severity'] == 'High'


def test_anti_forensics_silent_on_unrelated_tool():
    proc = pd.DataFrame([make_proc('pbeesly', 'rar.exe', 0.5)])
    assert len(detect_anti_forensics(proc)) == 0


# ---------------------------------------------------------------
# Alert 5: Obfuscated Command Execution
# ---------------------------------------------------------------

def test_obfuscated_command_fires_on_precomputed_flag():
    proc = pd.DataFrame([{**make_proc('pbeesly', 'powershell.exe', float('nan')), 'obfuscated_command': True}])
    result = detect_obfuscated_command(proc)
    assert len(result) == 1
    assert result.iloc[0]['severity'] == 'High'


def test_obfuscated_command_fires_even_with_no_duration():
    """Regression test for the bug this rule was specifically added to
    fix: a process with NaN duration (no recorded exit event) must
    still be caught, since this rule is presence-based."""
    proc = pd.DataFrame([{**make_proc('pbeesly', 'powershell.exe', float('nan')), 'obfuscated_command': True}])
    assert proc['duration_seconds'].isna().all()
    assert len(detect_obfuscated_command(proc)) == 1


def test_obfuscated_command_computes_inline_when_column_missing():
    """If obfuscated_command hasn't been precomputed, fall back to
    checking CommandLine directly."""
    proc = pd.DataFrame([{
        **make_proc('pbeesly', 'powershell.exe', float('nan')),
        'CommandLine': 'powershell.exe -nop -w hidden -enc SGVsbG8=',
    }])
    result = detect_obfuscated_command(proc)
    assert len(result) == 1


def test_obfuscated_command_silent_on_plain_powershell():
    proc = pd.DataFrame([{
        **make_proc('pbeesly', 'powershell.exe', 5.0),
        'CommandLine': 'powershell.exe -File C:\\scripts\\backup.ps1',
    }])
    assert len(detect_obfuscated_command(proc)) == 0


# ---------------------------------------------------------------
# Integration: run_all_rules
# ---------------------------------------------------------------

def test_run_all_rules_combines_and_sorts_by_time():
    logons = pd.DataFrame([make_logon('pbeesly', True, True, ts="2020-05-02 03:10:00")])
    proc = pd.DataFrame([
        make_proc('pbeesly', 'rar.exe', 0.5, ts="2020-05-02 03:00:00"),
        make_proc('pbeesly', 'sdelete64.exe', 2.0, ts="2020-05-02 03:05:00"),
    ])
    result = run_all_rules(logons, proc)
    assert len(result) == 3
    # sorted ascending by timestamp
    assert list(result['timestamp']) == sorted(result['timestamp'])
    assert set(result['alert_type']) == {'Lateral Movement', 'Suspicious Short-Lived Tool', 'Anti-Forensics Tool'}


def test_run_all_rules_returns_empty_frame_with_no_matches():
    logons = pd.DataFrame([make_logon('pbeesly', False, False)])
    proc = pd.DataFrame([make_proc('pbeesly', 'notepad.exe', 5.0)])
    result = run_all_rules(logons, proc)
    assert len(result) == 0
