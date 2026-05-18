import subprocess
import sys
import time
import os


def run_agent(script_name):
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), script_name)

    if not os.path.exists(script_path):
        print(f"[-] Agent '{script_name}' not found in TOOLS directory.")
        return

    print(f"[*] Dispatching: {script_name}...")
    start_time = time.time()

    try:
        result = subprocess.run(
            [sys.executable, script_path],
            capture_output=True,
            text=True,
            timeout=600
        )
        elapsed = time.time() - start_time
        print(f"\n[+] '{script_name}' completed in {elapsed:.2f}s")
        print("=== OUTPUT ===")
        print(result.stdout)

        if result.stderr:
            print("=== ERRORS ===")
            print(result.stderr)

    except subprocess.TimeoutExpired:
        print(f"[-] '{script_name}' timed out after 10 minutes.")
    except OSError as e:
        print(f"[-] Failed to execute agent: {e}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python run_lmx.py <agent_script.py>")
        sys.exit(1)

    run_agent(sys.argv[1])
