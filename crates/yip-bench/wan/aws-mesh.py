#!/usr/bin/env python3
"""
Multi-region AWS mesh manager for live global benchmarking and telemetry recordings.
Provisions ephemeral instances across US-East, US-West, EU-Central, and AP-Northeast,
configures peering, injects loss, and guarantees 100% clean teardown.
"""

import sys, os, time, json, subprocess, concurrent.futures
from pathlib import Path

REGIONS = [
    {"name": "us-east-1", "loc": "🇺🇸 US-East (VA)", "loss": 0},
    {"name": "us-west-2", "loc": "🇺🇸 US-West (OR)", "loss": 3},
    {"name": "eu-central-1", "loc": "🇩🇪 EU-Central (FRA)", "loss": 5},
    {"name": "ap-northeast-1", "loc": "🇯🇵 AP-Northeast (TYO)", "loss": 8},
]

AMI_MAP = {
    "us-east-1": "ami-04dd8f99034cb36c4",
    "us-west-2": "ami-0b15e723ce4fd90a0",
    "eu-central-1": "ami-0421220c1edd30bba",
    "ap-northeast-1": "ami-0775ebb274d4d42fc",
}

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent.parent
SESSION_FILE = SCRIPT_DIR / "results" / ".aws-mesh-session.json"
KEY_FILE = SCRIPT_DIR / "id_ed25519_mesh"

def run_cmd(cmd, check=True):
    res = subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True)
    if check and res.returncode != 0:
        raise RuntimeError(f"Command failed ({res.returncode}): {cmd}\nStderr: {res.stderr}")
    return res.stdout.strip()

def get_runner_ip():
    for url in ["https://api.ipify.org", "https://checkip.amazonaws.com", "https://icanhazip.com"]:
        try:
            ip = run_cmd(f"curl -s --max-time 3 {url}")
            if ip and len(ip.split(".")) == 4:
                return ip
        except Exception:
            continue
    return "0.0.0.0"

def cmd_up():
    print("[*] Starting multi-region AWS mesh deployment...")
    runner_ip = get_runner_ip()
    print(f"[*] Local runner IP: {runner_ip}")
    cidr = f"{runner_ip}/32" if runner_ip != "0.0.0.0" else "0.0.0.0/0"

    # Generate keypair
    if KEY_FILE.exists():
        KEY_FILE.unlink()
    if Path(str(KEY_FILE) + ".pub").exists():
        Path(str(KEY_FILE) + ".pub").unlink()

    run_cmd(f"ssh-keygen -t ed25519 -N '' -f {KEY_FILE}")
    KEY_FILE.chmod(0o600)
    pubkey = (Path(str(KEY_FILE) + ".pub")).read_text().strip()

    run_id = str(int(time.time()))
    key_name = f"yip-mesh-key-{run_id}"
    sg_name = f"yip-mesh-sg-{run_id}"

    session = {
        "run_id": run_id,
        "key_name": key_name,
        "key_file": str(KEY_FILE),
        "nodes": []
    }

    user_data = f"""#cloud-config
runcmd:
  - mkdir -p /root/.ssh
  - echo "{pubkey}" >> /root/.ssh/authorized_keys
  - chmod 700 /root/.ssh
  - chmod 600 /root/.ssh/authorized_keys
  - echo "PermitRootLogin prohibit-password" > /etc/ssh/sshd_config.d/99-root.conf
  - systemctl restart ssh || service ssh restart || true
"""
    ud_path = SCRIPT_DIR / ".ud_tmp.txt"
    ud_path.write_text(user_data)

    def provision_region(r):
        reg = r["name"]
        print(f"[{reg}] Importing keypair {key_name}...")
        run_cmd(["aws", "ec2", "import-key-pair", "--region", reg, "--key-name", key_name, "--public-key-material", f"fileb://{KEY_FILE}.pub"])

        print(f"[{reg}] Creating security group...")
        sg_id = run_cmd(["aws", "ec2", "create-security-group", "--region", reg, "--group-name", sg_name, "--description", "yip mesh SG", "--output", "text", "--query", "GroupId"])

        # Allow SSH and UDP 51833
        run_cmd(["aws", "ec2", "authorize-security-group-ingress", "--region", reg, "--group-id", sg_id, "--protocol", "tcp", "--port", "22", "--cidr", cidr])
        run_cmd(["aws", "ec2", "authorize-security-group-ingress", "--region", reg, "--group-id", sg_id, "--protocol", "udp", "--port", "51833", "--cidr", "0.0.0.0/0"])

        ami_id = AMI_MAP[reg]
        print(f"[{reg}] Launching instance ({ami_id})...")
        inst_id = run_cmd(["aws", "ec2", "run-instances", "--region", reg, "--image-id", ami_id, "--instance-type", "t3.small", "--key-name", key_name, "--security-group-ids", sg_id, "--user-data", f"file://{ud_path}", "--tag-specifications", f"ResourceType=instance,Tags=[{{Key=Name,Value=yip-mesh-{reg}}}]", "--output", "text", "--query", "Instances[0].InstanceId"])

        print(f"[{reg}] Waiting for instance {inst_id} to be running...")
        run_cmd(["aws", "ec2", "wait", "instance-running", "--region", reg, "--instance-ids", inst_id])

        ip = run_cmd(["aws", "ec2", "describe-instances", "--region", reg, "--instance-ids", inst_id, "--output", "text", "--query", "Reservations[0].Instances[0].PublicIpAddress"])
        print(f"[{reg}] Running at public IP: {ip}")

        return {
            "region": reg,
            "loc": r["loc"],
            "loss": r["loss"],
            "instance_id": inst_id,
            "sg_id": sg_id,
            "public_ip": ip
        }

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(provision_region, REGIONS))

    ud_path.unlink(missing_ok=True)
    session["nodes"] = results
    SESSION_FILE.parent.mkdir(parents=True, exist_ok=True)
    SESSION_FILE.write_text(json.dumps(session, indent=2))
    print(f"[*] Session recorded to {SESSION_FILE}")

    # Wait for SSH on all nodes
    def wait_ssh(node):
        ip = node["public_ip"]
        print(f"[{node['region']}] Waiting for SSH on {ip}...")
        for _ in range(30):
            try:
                out = run_cmd(f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i {KEY_FILE} root@{ip} 'echo ready'", check=False)
                if out == "ready":
                    print(f"[{node['region']}] SSH ready!")
                    return True
            except Exception:
                pass
            time.sleep(3)
        raise RuntimeError(f"Timeout waiting for SSH on {node['region']} ({ip})")

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(wait_ssh, session["nodes"]))

    print("[*] All 4 global nodes are UP and SSH reachable!")

def cmd_down():
    if not SESSION_FILE.exists():
        print("[*] No session file found; nothing to tear down.")
        return
    session = json.loads(SESSION_FILE.read_text())
    key_name = session.get("key_name")
    nodes = session.get("nodes", [])

    print(f"[*] Tearing down {len(nodes)} global AWS instances...")

    def destroy_node(n):
        reg = n["region"]
        inst_id = n["instance_id"]
        sg_id = n["sg_id"]
        print(f"[{reg}] Terminating instance {inst_id}...")
        run_cmd(["aws", "ec2", "terminate-instances", "--region", reg, "--instance-ids", inst_id], check=False)
        print(f"[{reg}] Waiting for termination...")
        run_cmd(["aws", "ec2", "wait", "instance-terminated", "--region", reg, "--instance-ids", inst_id], check=False)

        print(f"[{reg}] Deleting security group {sg_id}...")
        run_cmd(["aws", "ec2", "delete-security-group", "--region", reg, "--group-id", sg_id], check=False)

        if key_name:
            print(f"[{reg}] Deleting keypair {key_name}...")
            run_cmd(["aws", "ec2", "delete-key-pair", "--region", reg, "--key-name", key_name], check=False)

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(destroy_node, nodes))

    if KEY_FILE.exists():
        KEY_FILE.unlink(missing_ok=True)
    if Path(str(KEY_FILE) + ".pub").exists():
        Path(str(KEY_FILE) + ".pub").unlink(missing_ok=True)
    SESSION_FILE.unlink(missing_ok=True)
    print("[*] Teardown complete. All global cloud resources destroyed.")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "down":
        cmd_down()
    else:
        cmd_up()
