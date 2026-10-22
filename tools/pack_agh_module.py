"""Build a LOCAL TEST module overlay from the verified upstream v8.6.1 release.

No APK signing or Native recompilation: these components must match the pinned
upstream source commit. The original signed APK/DEX/Native/core are retained.
This is separate from the repository's CI source-build/release workflow.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
BASE_COMMIT = '3fd2a1cb9710b59f2723d3c0bb2a01c7090e0998'
BASE_SHA = 'a07bb10b587a74146d3771aeac6360fa9e7eb884993bc8280e12d46ad75d2c9d'
IMMUTABLE = ['NetProxy.apk', 'bin/android-platform.dex', 'bin/netproxyctl', 'bin/sing-box']


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run(args, **kwargs):
    result = subprocess.run([str(a) for a in args], check=True, capture_output=True, **kwargs)
    return result.stdout


def build(base, output, sevenzip, tc_test=False):
    if output.exists():
        raise ValueError('Output already exists; choose a new output path')
    if sha(base.read_bytes()) != BASE_SHA:
        raise ValueError('Upstream release SHA-256 mismatch')
    run(['git', 'merge-base', '--is-ancestor', BASE_COMMIT, 'HEAD'], cwd=ROOT)
    protected = ['src/native', 'src/android', 'src/webui']
    changed = run(['git', 'diff', '--name-only', BASE_COMMIT, '--', *protected], cwd=ROOT)
    untracked = run(['git', 'ls-files', '--others', '--exclude-standard', '--', *protected], cwd=ROOT)
    if changed.strip() or untracked.strip():
        raise ValueError('Native/Android/WebUI source changed: use the full CI build instead')
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
        if hashes['bin/sing-box'] != sha((ROOT / 'src/module/bin/sing-box').read_bytes()):
            raise ValueError('Packaged core differs from source-pinned core')
        # Overlay text/configuration and rule resources. Built UI stays upstream.
        for source in sorted((ROOT / 'src/module').rglob('*')):
            if not source.is_file():
                continue
            name = source.relative_to(ROOT / 'src/module').as_posix()
            if name in IMMUTABLE or name.startswith('webroot/netproxy/'):
                continue
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True)
            data = source.read_bytes()
            if source.suffix in {'.sh', '.json', '.prop', '.txt', '.md', '.yaml'} or name.startswith('META-INF/'):
                data = data.replace(b'\r\n', b'\n')
            target.write_bytes(data)
        if tc_test:
            inbound_path = stage / 'config/inbound/inbound.json'
            inbound = json.loads(inbound_path.read_text(encoding='utf-8'))
            if inbound['backend'] != 'ebpf':
                raise ValueError('TC diagnostic requires the eBPF profile')
            inbound['ebpf']['local']['data_plane'] = 'tc'
            inbound_path.write_text(json.dumps(inbound, ensure_ascii=False, indent=2)+'\n', encoding='utf-8', newline='\n')
        preset = stage / 'compat/agh'
        preset.mkdir(parents=True)
        shutil.copyfile(stage / 'config/singbox/config.json', preset / 'config.json')
        shutil.copyfile(stage / 'config/inbound/inbound.json', preset / 'inbound.json')
        prop = stage / 'module.prop'
        suffix = '-tc-test' if tc_test else ''
        code = 1092 if tc_test else 1091
        prop.write_text('id=netproxy\nname=NetProxy (AGH RC1)\n'
            f'version=v8.6.1-agh-rc1.3{suffix}\nversionCode={code}\nauthor=Fanju; compatibility by ZxhL-Xxx\n'
            'description=Local AGH RC1 paired test; eBPF; ad filtering by AGH\n'
            'webuiIcon=webroot/netproxy/favicon.svg\n', encoding='utf-8', newline='\n')
        manifest = {'profile': '20261022-rc1-netproxy.3' + suffix, 'kind': 'local-test-overlay',
            'diagnostic_tc': tc_test,
            'ebpf_data_plane': json.loads((stage / 'config/inbound/inbound.json').read_text(encoding='utf-8'))['ebpf']['local']['data_plane'],
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
    parser.add_argument('--test-tc', action='store_true', help='Build eBPF TC diagnostic variant; keep the same DNS and routing')
    args = parser.parse_args()
    build(args.base, args.output, args.sevenzip, args.test_tc)
