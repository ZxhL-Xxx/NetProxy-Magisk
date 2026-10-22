"""离线合并 NetProxy 客户端配置，输出候选文件，不修改输入文件。"""

from __future__ import annotations

import argparse
import copy
import ipaddress
import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "examples" / "adguardhome" / "clients.json"


class UniqueLoader(yaml.SafeLoader):
    """UniqueLoader 拒绝 YAML 重复键，避免重写时静默丢失配置。"""


def unique_mapping(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ValueError(f"YAML 存在重复键：{key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping)


def merge_profile(config: dict, profiles: list[dict]) -> dict:
    if not isinstance(config, dict):
        raise ValueError("配置根节点必须是对象")
    result = copy.deepcopy(config)
    dns = result.get("dns", {})
    if dns.get("port") != 5591 or "127.0.0.1" not in dns.get("bind_hosts", []):
        raise ValueError("当前方案要求 AGH 监听 127.0.0.1:5591")
    if not dns.get("serve_plain_dns", True):
        raise ValueError("当前方案要求启用普通 DNS 服务")
    if not result.get("filtering", {}).get("protection_enabled", True):
        raise ValueError("AGH 保护当前关闭，请先确认过滤策略")
    if not result.get("filtering", {}).get("filtering_enabled", True):
        raise ValueError("AGH DNS 过滤当前关闭，请先确认过滤策略")
    clients = result.setdefault("clients", {})
    existing = clients.setdefault("persistent", [])
    if not isinstance(existing, list):
        raise ValueError("clients.persistent 必须是列表")
    names = {p["name"] for p in profiles}
    reserved = {ipaddress.ip_address(i) for p in profiles for i in p["ids"]}
    for client in existing:
        if not isinstance(client, dict):
            raise ValueError("客户端配置必须是对象")
        if client.get("name") in names:
            expected = next(p for p in profiles if p["name"] == client["name"])
            if client.get("ids") != expected["ids"]:
                raise ValueError("同名客户端使用了其他标识，拒绝覆盖")
            continue
        for identifier in client.get("ids", []):
            try:
                network = ipaddress.ip_network(identifier, strict=False)
            except ValueError:
                continue
            if any(address in network for address in reserved):
                raise ValueError("已有客户端覆盖保留的本地来源地址，拒绝生成")
    retained = [c for c in existing if c.get("name") not in names]
    clients["persistent"] = retained + copy.deepcopy(profiles)
    allowed = dns.get("allowed_clients", [])
    if allowed:
        networks = []
        for item in allowed:
            try:
                networks.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                continue
        if any(not any(address in n for n in networks) for address in reserved):
            raise ValueError("allowed_clients 未允许两个本地来源地址")
    for item in dns.get("disallowed_clients", []):
        try:
            network = ipaddress.ip_network(item, strict=False)
        except ValueError:
            continue
        if any(address in network for address in reserved):
            raise ValueError("disallowed_clients 阻止了本地来源地址")
    return result


def prepare(source: Path, target: Path) -> None:
    if source.resolve() == target.resolve():
        raise ValueError("输入与输出必须不同，原配置需要保留")
    config = yaml.load(source.read_text(encoding="utf-8-sig"), Loader=UniqueLoader)
    profiles = json.loads(PROFILE.read_text(encoding="utf-8"))
    candidate = merge_profile(config, profiles)
    text = yaml.safe_dump(candidate, allow_unicode=True, sort_keys=False)
    if yaml.safe_load(text) != candidate:
        raise ValueError("候选配置回读不一致")
    with target.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(text)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("target", type=Path)
    args = parser.parse_args()
    try:
        prepare(args.source, args.target)
    except (ValueError, OSError, yaml.YAMLError) as error:
        parser.exit(1, f"未生成配置：{error}\n")
    print("已生成候选配置；原文件未修改。请先用官方 AGH 核心检查候选文件。")


if __name__ == "__main__":
    main()
