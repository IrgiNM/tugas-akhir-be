import io
import posixpath
import shlex

import paramiko
from django.conf import settings


def load_private_key():
    private_key_text = settings.VPS_PRIVATE_KEY

    if not private_key_text:
        raise RuntimeError("VPS_PRIVATE_KEY belum diatur di Railway Variables")

    private_key_text = private_key_text.replace("\\n", "\n")

    key_classes = [
        paramiko.Ed25519Key,
        paramiko.RSAKey,
        paramiko.ECDSAKey,
    ]

    for key_class in key_classes:
        try:
            return key_class.from_private_key(io.StringIO(private_key_text))
        except Exception:
            continue

    raise RuntimeError("Private key VPS tidak valid atau formatnya tidak didukung")


def upload_file_to_vps(local_file_path, file_name):
    if not settings.VPS_HOST:
        raise RuntimeError("VPS_HOST belum diatur")

    if not settings.VPS_USER:
        raise RuntimeError("VPS_USER belum diatur")

    if not settings.VPS_BASE_URL:
        raise RuntimeError("VPS_BASE_URL belum diatur")

    private_key = load_private_key()

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        ssh.connect(
            hostname=settings.VPS_HOST,
            port=settings.VPS_PORT,
            username=settings.VPS_USER,
            pkey=private_key,
            timeout=8,
            banner_timeout=8,
            auth_timeout=8,
            look_for_keys=False,
            allow_agent=False,
        )

        remote_dir = settings.VPS_REMOTE_DIR.rstrip("/")

        mkdir_command = f"mkdir -p {shlex.quote(remote_dir)}"
        stdin, stdout, stderr = ssh.exec_command(mkdir_command)
        exit_code = stdout.channel.recv_exit_status()

        if exit_code != 0:
            error_message = stderr.read().decode()
            raise RuntimeError(f"Gagal membuat folder VPS: {error_message}")

        remote_file_path = posixpath.join(remote_dir, file_name)

        with ssh.open_sftp() as sftp:
            sftp.put(local_file_path, remote_file_path)

        file_url = f"{settings.VPS_BASE_URL.rstrip('/')}/{file_name}"
        return file_url

    finally:
        ssh.close()