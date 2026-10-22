"""在临时 loopback 端口验证 NetProxy 与 AGH 客户端分流，不接管系统网络。"""

import argparse
import copy
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import urllib.request

import yaml

from prepare_agh_config import ROOT, merge_profile


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Upstream(threading.Thread):
    def __init__(self, suffix):
        super().__init__(daemon=True)
        self.suffix, self.questions, self.stopped = suffix, [], threading.Event()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]

    def run(self):
        while not self.stopped.is_set():
            try:
                data, address = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            end, labels = 12, []
            while data[end]:
                count = data[end]
                labels.append(data[end + 1:end + 1 + count].decode())
                end += count + 1
            end += 5
            self.questions.append(".".join(labels))
            qtype = struct.unpack_from("!H", data, end - 4)[0]
            answer = socket.inet_pton(socket.AF_INET6, f"2001:db8::{self.suffix}") if qtype == 28 else socket.inet_aton(f"198.51.100.{self.suffix}")
            response = data[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + data[12:end]
            response += b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 60, len(answer)) + answer
            self.sock.sendto(response, address)

    def close(self):
        self.stopped.set()
        self.join(timeout=2)
        self.sock.close()


def query(port, host, source="127.0.0.1", qtype=1, tcp=False):
    question = b"".join(bytes([len(label)]) + label.encode() for label in host.split(".")) + b"\0" + struct.pack("!HH", qtype, 1)
    request = struct.pack("!HHHHHH", 1234, 0x0100, 1, 0, 0, 0) + question
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
        sock.bind((source, 0))
        sock.settimeout(5)
        if tcp:
            sock.connect(("127.0.0.1", port))
            sock.sendall(struct.pack("!H", len(request)) + request)
            length = int.from_bytes(sock.recv(2), "big")
            data = b""
            while len(data) < length:
                part = sock.recv(length - len(data))
                if not part:
                    raise RuntimeError("TCP DNS 响应提前结束")
                data += part
        else:
            sock.sendto(request, ("127.0.0.1", port))
            data, _ = sock.recvfrom(4096)
    rcode = data[3] & 15
    address = None
    if rcode == 0 and int.from_bytes(data[6:8], "big"):
        length = 16 if qtype == 28 else 4
        address = str(ipaddress.ip_address(data[-length:]))
    return rcode, address


def api(port, path):
    with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=2) as response:
        return json.load(response)


def start(executable, arguments, work, log_name):
    log = (work / log_name).open("wb")
    process = subprocess.Popen([str(executable), *arguments], cwd=work, stdout=log, stderr=subprocess.STDOUT,
                               creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    return process, log


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sing-box", type=Path, required=True)
    parser.add_argument("--agh", type=Path, required=True)
    parser.add_argument("--agh-source", type=Path, required=True)
    args = parser.parse_args()
    base = ROOT / ".agents/runs"
    base.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="agh-wire-", dir=base)).resolve()
    assert work.parent == base.resolve()
    upstreams = [Upstream(11), Upstream(22), Upstream(33)]
    processes, logs, results = [], [], []
    try:
        for upstream in upstreams:
            upstream.start()
        profiles = json.loads((ROOT / "examples/adguardhome/clients.json").read_text(encoding="utf-8"))
        config = yaml.safe_load((args.agh_source / "bin/AdGuardHome.yaml").read_text(encoding="utf-8"))
        config = merge_profile(config, profiles)
        agh_port, http_port, dns_port = free_port(), free_port(), free_port()
        config["http"]["address"] = f"127.0.0.1:{http_port}"
        config["users"] = []
        config["dns"].update(port=agh_port, upstream_dns=[f"127.0.0.1:{upstreams[2].port}"], bootstrap_dns=[],
                             fallback_dns=[], hostsfile_enabled=False, handle_ddr=False, upstream_timeout="300ms")
        config["clients"]["runtime_sources"] = {key: False for key in config["clients"]["runtime_sources"]}
        for client, upstream in zip(config["clients"]["persistent"], upstreams):
            client["upstreams"] = [f"127.0.0.1:{upstream.port}"]
        config["filtering"]["filters_update_interval"] = 0
        config["user_rules"].extend(["||fixture-block.example^$important", "@@||fixture-allow.example^$important"])
        sources = []
        for section in ("filters", "whitelist_filters"):
            for item in config[section]:
                source = args.agh_source / f'bin/data/filters/{item["id"]}.txt'
                cache = work / f'agh/data/filters/{item["id"]}.txt'
                cache.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, cache)
                target = work / f'agh/sources/{item["id"]}.txt'
                target.parent.mkdir(exist_ok=True)
                shutil.copyfile(source, target)
                item["url"] = target.as_posix()
                sources.append(target.as_posix())
        config["filtering"]["safe_fs_patterns"] = sources
        agh_work = work / "agh"
        agh_work.mkdir(exist_ok=True)
        agh_path = agh_work / "AdGuardHome.yaml"
        agh_path.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False), encoding="utf-8")
        process, log = start(args.agh.resolve(), ["--no-permcheck", "--no-check-update", "-w", str(agh_work), "-c", str(agh_path)], work, "agh.log")
        processes.append(process)
        logs.append(log)
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            try:
                state = api(http_port, "/control/filtering/status")
                if all(item.get("rules_count", 0) for key in ("filters", "whitelist_filters") for item in state[key]):
                    break
            except (OSError, KeyError):
                pass
            if process.poll() is not None:
                raise RuntimeError("AGH exited; see " + str(work / "agh.log"))
            time.sleep(0.2)
        else:
            raise RuntimeError("AGH readiness timeout")
        for source, suffix in (("127.0.0.2", 11), ("127.0.0.3", 22)):
            for host, expected in (("fixture-cache.example", f"198.51.100.{suffix}"),
                                   ("fixture-allow.example", f"198.51.100.{suffix}"),
                                   ("tracking.miui.com", f"198.51.100.{suffix}"),
                                   ("aiclk.com", "0.0.0.0"), ("fixture-block.example", "0.0.0.0")):
                actual = query(agh_port, host, source)
                assert actual == (0, expected), (source, host, actual, expected)
                results.append({"source": source, "host": host, "answer": actual})
            actual = query(agh_port, "fixture-tcp.example", source, tcp=True)
            assert actual == (0, f"198.51.100.{suffix}"), actual
            results.append({"source": source, "tcp": True, "answer": actual})
        sb = json.loads((ROOT / "src/module/config/singbox/config.json").read_text(encoding="utf-8"))
        sb["experimental"]["cache_file"]["path"] = (work / "cache.db").as_posix()
        sb["experimental"]["clash_api"]["external_controller"] = f"127.0.0.1:{free_port()}"
        sb["services"][0]["listen_port"] = free_port()
        sb["services"][0].pop("dashboard", None)
        for server in sb["dns"]["servers"]:
            if server["tag"] in ("dns-proxy", "dns-direct"):
                server["server_port"] = agh_port
        sb["inbounds"] = [{"type": "direct", "tag": "dns-test", "listen": "127.0.0.1", "listen_port": dns_port,
                           "override_address": "198.51.100.53", "override_port": 53}]
        for rule in sb["route"]["rule_set"]:
            for tag in rule["tag"]:
                source = ROOT / "src/module/config/singbox" / rule["path"].replace("{tag}", tag)
                target = work / "rules" / Path(rule["path"].replace("{tag}", tag)).relative_to("rules")
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, target)
            rule["path"] = (work / rule["path"]).as_posix()
            if rule["type"] == "remote":
                rule["url"] = "http://127.0.0.1:9/{tag}.srs"
        sb["providers"] = [{"type": "local", "tag": "fixture", "path": (work / "provider.json").as_posix()}]
        sb["outbounds"].extend([{"type": "direct", "tag": "direct"}, {"type": "direct", "tag": "Proxy"}])
        (work / "provider.json").write_text(json.dumps({"outbounds": [{"type": "socks", "tag": "fixture-node", "server": "127.0.0.1", "server_port": 9}]}), encoding="utf-8")
        path = work / "sing-box.json"
        path.write_text(json.dumps(sb), encoding="utf-8")
        process, log = start(args.sing_box.resolve(), ["run", "--disable-color", "-c", str(path)], work, "sing-box.log")
        processes.append(process)
        logs.append(log)
        time.sleep(1)
        if process.poll() is not None:
            raise RuntimeError("sing-box exited; see " + str(work / "sing-box.log"))
        for host, suffix in (("api.openai.com", 11), ("steamcommunity.com", 11), ("www.youtube.com", 11),
                             ("telegram.org", 11), ("github.com", 11), ("onedrive.live.com", 11), ("google.com", 11),
                             ("www.baidu.com", 22), ("steamchina.com", 22), ("download.microsoft.com", 22),
                             ("dl.google.com", 22), ("fixture-unknown.example", 11)):
            actual = query(dns_port, host)
            assert actual == (0, f"198.51.100.{suffix}"), (host, actual, suffix)
            results.append({"through": "sing-box", "host": host, "answer": actual})
        actual = query(dns_port, "fixture-tcp-chain.example", tcp=True)
        assert actual == (0, "198.51.100.11"), actual
        results.append({"through": "sing-box", "tcp": True, "answer": actual})
        for qtype, expected in ((1, "0.0.0.0"), (28, "::")):
            actual = query(dns_port, "fixture-block.example", qtype=qtype)
            assert actual == (0, expected), actual
            results.append({"through": "sing-box", "blocked_qtype": qtype, "answer": actual})
        upstreams[0].close()
        actual = query(dns_port, "failed-proxy-path.example")
        assert actual[0] != 0, actual
        assert "failed-proxy-path.example" not in upstreams[1].questions
        assert "failed-proxy-path.example" not in upstreams[2].questions
        results.append({"foreign_failure_no_direct_fallback": actual})
        process.terminate()
        process.wait(timeout=6)
        for host, expected in (("after-stop.example", "198.51.100.33"), ("fixture-block.example", "0.0.0.0")):
            actual = query(agh_port, host)
            assert actual == (0, expected), actual
            results.append({"after_sing_box_stop": host, "answer": actual})
        report = {"passed": len(results), "device_verified": False, "work": str(work), "checks": results}
        (work / "validation.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({key: value for key, value in report.items() if key != "checks"}, ensure_ascii=False))
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=6)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
        for log in logs:
            log.close()
        for upstream in upstreams:
            if not upstream.stopped.is_set():
                upstream.close()


if __name__ == "__main__":
    main()
