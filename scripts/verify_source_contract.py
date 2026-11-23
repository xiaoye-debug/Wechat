#!/usr/bin/env python3
"""Check DD method identities, enabled startup gates and exact bundle filters."""
import json
from pathlib import Path
import plistlib
import re

ROOT = Path(__file__).resolve().parent.parent


def bundle_filter(path):
    text = path.read_text(encoding="utf-8-sig")
    if text.lstrip().startswith("<?xml"):
        return plistlib.loads(text.encode())["Filter"]["Bundles"]
    body = re.search(r"Bundles\s*=\s*\((.*?)\);", text, re.S)
    if not body:
        raise AssertionError("Missing loader bundle filter")
    return re.findall(r'"([^"\n]+)"', body.group(1))


def verify():
    text = (ROOT / "Tweak.x").read_text(encoding="utf-8-sig")
    fixture = json.loads((ROOT / "tests/fixtures/dd-contract.json").read_text())
    registry_text = text.split("static const WCEBHookSpec kHookSpecs[] =", 1)[1].split("};", 1)[0]
    registry = [(cls, "+" if kind == "YES" else "-", selector) for cls, selector, kind in
                re.findall(r'\{\s*"([^"]+)",\s*"([^"]+)",\s*(YES|NO),', registry_text)]
    assert len(registry) == len(set(registry)) == 88, "Duplicate/missing registry identities"
    groups = re.findall(r"^%group\s+(WCEBHook\d+)$", text, re.M)
    assert len(groups) == len(set(groups)) == 88, "Duplicate/missing groups"
    defaults = {var: value == "YES" for var, value in
                re.findall(r"^static BOOL (g\w+) = (YES|NO);", text, re.M)}
    preferences = plistlib.loads((ROOT / "preferences.example.plist").read_bytes())
    config = re.findall(r'(g\w+) = WCEBBool\(@"([^"\n]+)", (YES|NO)\);', text)
    assert len(config) == 18
    for var, key, value in config:
        assert defaults[var] == (value == "YES") == preferences[key], f"Default mismatch: {key}"
    wiring = re.findall(
        r"if \(([^\n]+) && WCEBPrepare\(&kHookSpecs\[(\d+)\], &previous\)\) \{\s*%init\((WCEBHook\d+)\);", text)
    assert len(wiring) == 88
    status = {}
    for condition, index, group in wiring:
        index = int(index)
        assert group == groups[index] == f"WCEBHook{index + 1:03d}", "Initializer mismatch"
        assert registry[index] not in status, "Repeated initializer"
        status[registry[index]] = all(defaults[g] for g in re.findall(r"\bg[A-Z]\w*", condition))
    key = lambda row: (row["class"], row["kind"], row["selector"])
    dd = set(map(key, fixture["hooks"]))
    excluded = set(map(key, fixture["excluded_passthrough"]))
    transferred = dd - excluded
    assert len(dd) == 55 and len(transferred) == 54
    assert transferred <= status.keys(), "Missing migrated DD method"
    assert not (excluded & status.keys()), "Unexpected pure-passthrough hook"
    disabled_dd = sorted(k for k in transferred if not status[k])
    assert not disabled_dd, f"Migrated DD defaults still disabled: {disabled_dd}"
    loader_bundles = bundle_filter(ROOT / "WeChatEnvBypass.plist")
    policy = (ROOT / "WCEBHostPolicy.h").read_text()
    policy_bundles = re.findall(r'@"([^"\n]+)"', re.search(
        r"supportedBundles = @\[(.*?)\];", policy, re.S).group(1))
    assert loader_bundles == policy_bundles == fixture["bundle_ids"], "DD bundle allowlist mismatch"
    assert "WCEBSupportsHost(hostBundle.bundleIdentifier," in text
    assert 'infoDictionary[@"NSExtension"]' in text and 'isEqualToString:@"appex"' in text
    assert re.search(r"if \(isExtension\) return NO;", policy), "Extension exclusion missing"
    assert sum(status.values()) == 80
    assert not defaults["gIntegrity"] and not defaults["gPaymentEnvironment"]
    control = (ROOT / "control").read_text()
    version = re.search(r"^Version: (.+)$", control, re.M).group(1)
    assert f'#define WCEB_VERSION "{version}"' in text
    return {
        "status": "PASS", "version": version,
        "methods": len(registry), "duplicate_method_identities": 0,
        "dd_migrated_methods": len(transferred), "dd_default_enabled": len(transferred),
        "dd_excluded_passthrough": [list(k) for k in sorted(excluded)],
        "default_enabled_candidates": sum(status.values()),
        "default_disabled_candidates": len(status) - sum(status.values()),
        "bundle_ids": loader_bundles,
        "saved_preferences_override_defaults": True,
        "device_runtime_tested": False,
    }


if __name__ == "__main__":
    print(json.dumps(verify(), ensure_ascii=False, indent=2))
