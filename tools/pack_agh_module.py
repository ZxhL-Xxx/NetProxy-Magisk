"""Build a LOCAL TEST module with a source-built Android ARM64 Native.

The signed APK, DEX, WebUI and core stay pinned to upstream v8.6.1.
Native is rebuilt from a clean source commit with the repository's PGO profile.
This is separate from the repository's CI source-build/release workflow.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
BASE_COMMIT = '3fd2a1cb9710b59f2723d3c0bb2a01c7090e0998'
BASE_SHA = 'a07bb10b587a74146d3771aeac6360fa9e7eb884993bc8280e12d46ad75d2c9d'
IMMUTABLE = ['NetProxy.apk', 'bin/android-platform.dex', 'bin/sing-box']


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run(args, **kwargs):
    if args[0] == 'git':
        args = ['git', '-c', f'safe.directory={ROOT.as_posix()}', *args[1:]]
    result = subprocess.run([str(a) for a in args], check=True, capture_output=True, **kwargs)
    return result.stdout


def build_native(go, output):
    env = dict(os.environ, CGO_ENABLED='0', GOOS='android', GOARCH='arm64', GOTOOLCHAIN='local')
    flags = ['-trimpath', '-buildvcs=false', '-pgo=auto', '-ldflags=-s -w -buildid=']
    run([go.resolve(), 'build', *flags, '-o', output, './cmd/netproxyctl'],
        cwd=ROOT / 'src/native/netproxy', env=env)
    info = run([go.resolve(), 'version', '-m', output]).decode()
    for required in ['-pgo=default.pgo', 'GOOS=android', 'GOARCH=arm64', 'CGO_ENABLED=0',
                     'github.com/reF1nd/sing-box']:
        if required not in info:
            raise ValueError(f'Native build metadata missing {required}')
    header = output.read_bytes()[:20]
    if header[:5] != b'\x7fELF\x02' or int.from_bytes(header[18:20], 'little') != 183:
        raise ValueError('Native must be an ELF64 AArch64 executable')
    return {'sha256': sha(output.read_bytes()), 'target': 'android/arm64',
            'go_version': run([go.resolve(), 'env', 'GOVERSION']).decode().strip(),
            'flags': flags, 'telemetry_credentials_injected': False,
            'pgo_sha256': sha((ROOT / 'src/native/netproxy/cmd/netproxyctl/default.pgo').read_bytes())}


def build(base, output, sevenzip, go):
    if output.exists():
        raise ValueError('Output already exists; choose a new output path')
    if sha(base.read_bytes()) != BASE_SHA:
        raise ValueError('Upstream release SHA-256 mismatch')
    run(['git', 'merge-base', '--is-ancestor', BASE_COMMIT, 'HEAD'], cwd=ROOT)
    if run(['git', 'status', '--porcelain'], cwd=ROOT).strip():
        raise ValueError('Commit and verify source changes before building the delivery')
    protected = ['src/android', 'src/webui']
    changed = run(['git', 'diff', '--name-only', BASE_COMMIT, '--', *protected], cwd=ROOT)
    untracked = run(['git', 'ls-files', '--others', '--exclude-standard', '--', *protected], cwd=ROOT)
    if changed.strip() or untracked.strip():
        raise ValueError('Android/WebUI source changed: use the full CI build instead')
    with zipfile.ZipFile(base) as archive:
        for info in archive.infolist():
            path = Path(info.filename.replace('\\', '/'))
            if path.is_absolute() or '..' in path.parts or ':' in info.filename:
                raise ValueError('Unsafe upstream archive path')
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='flash-stage-', dir=ROOT / '.agents/runs') as directory:
        stage = Path(directory)
        run([sevenzip, 'x', '-y', '-bd', f'-o{stage}', base.resolve()])
        hashes = {name: sha((stage / name).read_bytes()) for name in IMMUTABLE}
        native = build_native(go, stage / 'bin/netproxyctl')
        if hashes['bin/sing-box'] != sha((ROOT / 'src/module/bin/sing-box').read_bytes()):
            raise ValueError('Packaged core differs from source-pinned core')
        # Overlay text/configuration and rule resources. Built UI stays upstream.
        for source in sorted((ROOT / 'src/module').rglob('*')):
            if not source.is_file():
                continue
            name = source.relative_to(ROOT / 'src/module').as_posix()
            if name in IMMUTABLE or name == 'bin/netproxyctl' or name.startswith('webroot/netproxy/'):
                continue
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True)
            data = source.read_bytes()
            if source.suffix in {'.sh', '.json', '.prop', '.txt', '.md', '.yaml'} or name.startswith('META-INF/'):
                data = data.replace(b'\r\n', b'\n')
            target.write_bytes(data)
        inbound = json.loads((stage / 'config/inbound/inbound.json').read_text(encoding='utf-8'))
        if (inbound['backend'] != 'ebpf' or inbound['ebpf']['local']['data_plane'] != 'tc'
                or inbound['ebpf']['shared']['data_plane'] != 'socket_assign'):
            raise ValueError('RC1.6 requires the source TC/socket_assign profile')
        preset = stage / 'compat/agh'
        preset.mkdir(parents=True)
        shutil.copyfile(stage / 'config/singbox/config.json', preset / 'config.json')
        shutil.copyfile(stage / 'config/inbound/inbound.json', preset / 'inbound.json')
        shutil.copyfile(ROOT / 'examples/subscription/metadata-exclude.txt', preset / 'subscription-exclude.txt')
        prop = stage / 'module.prop'
        prop.write_text('id=netproxy\nname=NetProxy (AGH RC1)\n'
            'version=v8.6.1-agh-rc1.6\nversionCode=1095\nauthor=Fanju; compatibility by ZxhL-Xxx\n'
            'description=Local AGH RC1 paired test; automatic DNS handoff; ad filtering by AGH\n'
            'webuiIcon=webroot/netproxy/favicon.svg\n', encoding='utf-8', newline='\n')
        manifest = {'profile': '20261023-rc1-netproxy.6', 'kind': 'local-test-native-build',
            'native_build': native,
            'dns_handoff': 'tagged RETURN in AGH chains; lifecycle + Worker events',
            'global_selection': '总模式 -> Proxy (NetProxy node page)',
            'subscription_exclude_requires_user_setting': True,
            'ebpf_data_plane': inbound['ebpf']['local']['data_plane'],
            'ebpf_shared_data_plane': inbound['ebpf']['shared']['data_plane'],
            'ebpf_shared_enabled': inbound['ebpf']['shared']['enabled'],
            'ebpf_shared_interfaces': inbound['ebpf']['shared']['interface'],
            'source_head': run(['git', 'rev-parse', 'HEAD'], cwd=ROOT).decode().strip(),
            'resource_manifest_sha256': sha((ROOT / '.github/resources.json').read_bytes()),
            'base_commit': BASE_COMMIT, 'base_release': 'v8.6.1', 'base_archive_sha256': BASE_SHA,
            'base_url': 'https://github.com/Fanju6/NetProxy-Magisk/releases/tag/v8.6.1',
            'unchanged_binaries_sha256': hashes,
            'overlay_files_sha256': {p.relative_to(stage).as_posix(): sha(p.read_bytes())
                for p in sorted(stage.rglob('*')) if p.is_file() and
                (p.relative_to(stage).as_posix().startswith(('config/', 'compat/'))
                 or p.name in {'customize.sh', 'service.sh', 'module.prop'})}}
        (preset / 'build.json').write_text(json.dumps(manifest, indent=2)+'\n', encoding='utf-8')
        # Match upstream format: XZ9 in ZIP; index/APK/DEX stored without compression.
        run([sevenzip, 'a', '-bd', '-tzip', '-mm=XZ', '-mx=9', output.resolve(), '.',
             '-x!module.prop', '-x!NetProxy.apk', '-x!bin/android-platform.dex'], cwd=stage)
        run([sevenzip, 'a', '-bd', '-tzip', '-mx=0', output.resolve(), 'module.prop',
             'NetProxy.apk', 'bin/android-platform.dex'], cwd=stage)
        run([sevenzip, 't', '-bd', output.resolve()])
        # Verify through a separate extraction, including original signatures' bytes.
        verified = stage / '.verified'
        run([sevenzip, 'x', '-y', '-bd', f'-o{verified}', output.resolve()])
        for name, expected in hashes.items():
            if sha((verified / name).read_bytes()) != expected:
                raise ValueError(f'Binary changed: {name}')
        if sha((verified / 'bin/netproxyctl').read_bytes()) != native['sha256']:
            raise ValueError('Native build was replaced in package')
        for name, expected in manifest['overlay_files_sha256'].items():
            if sha((verified / name).read_bytes()) != expected:
                raise ValueError(f'Overlay mismatch: {name}')
        with zipfile.ZipFile(output) as archive:
            if archive.getinfo('module.prop').compress_type != zipfile.ZIP_STORED:
                raise ValueError('module.prop must be stored')
        output.with_suffix('.manifest.json').write_text(json.dumps(manifest, indent=2)+'\n', encoding='utf-8')
    digest = sha(output.read_bytes())
    output.with_suffix('.zip.sha256').write_text(f'{digest}  {output.name}\n', encoding='ascii')
    print(f'{output}\nSHA256: {digest}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('base', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--sevenzip', type=Path, required=True)
    parser.add_argument('--go', type=Path, required=True)
    args = parser.parse_args()
    build(args.base, args.output, args.sevenzip, args.go)
