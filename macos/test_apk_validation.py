"""Run the sideload entry point without starting a privileged proxy session."""

from pathlib import Path
import io
import os
import shutil
import struct
import subprocess
import tempfile
from zipfile import ZIP_DEFLATED, ZipFile


root = Path(__file__).resolve().parent.parent

with tempfile.TemporaryDirectory(prefix="zeeload-apk-") as temporary:
    directory = Path(temporary)
    scripts = directory / "scripts"
    scripts.mkdir()
    entry = scripts / "zeekr-sideload.sh"
    shutil.copyfile(root / "scripts/zeekr-sideload.sh", entry)
    (scripts / "transparent-test.sh").write_text('printf "TEST_PROXY_ENTRY\\n"\n')

    tools = directory / "bin"
    tools.mkdir()
    # macOS file(1) can describe an APK without the words used by the old check.
    file_command = tools / "file"
    file_command.write_text('#!/bin/bash\nprintf "data\\n"\n')
    file_command.chmod(0o755)
    environment = dict(os.environ, PATH=f"{tools}:{os.environ.get('PATH', '')}")

    content = io.BytesIO()
    with ZipFile(content, "w", ZIP_DEFLATED) as archive:
        archive.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00test manifest")
        archive.writestr("classes.dex", b"dex\n035\x00")
        archive.writestr("META-INF/CERT.SF", "Signature-Version: 1.0\n")
    apk = content.getvalue()

    # Preserve the ZIP layout used by APK v2/v3 signatures before the directory.
    eocd = apk.rfind(b"PK\x05\x06")
    central_offset = struct.unpack_from("<I", apk, eocd + 16)[0]
    signature_pair = struct.pack("<QI", 8, 0x7109871A) + b"test"
    block_size = len(signature_pair) + 24
    block = struct.pack("<Q", block_size) + signature_pair
    block += struct.pack("<Q", block_size) + b"APK Sig Block 42"
    signed_layout = bytearray(apk[:central_offset] + block + apk[central_offset:])
    struct.pack_into("<I", signed_layout, eocd + len(block) + 16, central_offset + len(block))

    damaged_manifest = bytearray(apk)
    name_length, extra_length = struct.unpack_from("<HH", apk, 26)
    damaged_manifest[30 + name_length + extra_length] ^= 0xFF

    cases = [
        ("应用 安装 '测试' (1).apk", apk, True),
        ("UPPERCASE.APK", apk, True),
        ("signing-block.apk", signed_layout, True),
        ("renamed-text.apk", b"this is not an APK", False),
        ("incomplete.apk", apk[:-24], False),
        ("missing-manifest.apk", apk.replace(b"AndroidManifest.xml", b"AndroidManifest.bad"), False),
        ("damaged-manifest.apk", damaged_manifest, False),
    ]
    wrapper = io.BytesIO()
    with ZipFile(wrapper, "w") as archive:
        archive.writestr("downloaded-app.apk", apk)
    cases.append(("download.zip", wrapper.getvalue(), False))

    for name, data, valid in cases:
        path = directory / name
        path.write_bytes(data)
        result = subprocess.run(
            ["/bin/bash", str(entry), "--apk", str(path)],
            env=environment,
            capture_output=True,
            text=True,
            timeout=20,
        )
        reached_proxy = "TEST_PROXY_ENTRY" in result.stdout
        if valid:
            assert result.returncode == 0 and reached_proxy and not result.stderr, (name, result.stdout, result.stderr)
        else:
            assert result.returncode == 2 and not reached_proxy, (name, result.stdout, result.stderr)
            assert "AndroidManifest.xml" in result.stderr, (name, result.stderr)
        print(f"PASS {name}")
