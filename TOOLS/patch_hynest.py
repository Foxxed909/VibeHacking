import os
import glob
import argparse

def patch_hynest_cloud(base_dir):

    protected_files = [
        "dashboard.html", "billing.html", "settings.html", "index.html", 
        "plans.html", "upgrade.html", "updates.html", "payment.html", 
        "live.html"
    ]
    
    # Core Guard Script Content
    # (Self-contained to avoid dependencies loading issues)
    guard_script = """
    <script id="hynest-security-guard">
      (function() {
        const token = localStorage.getItem('hynest_token') || sessionStorage.getItem('hynest_session_token');
        if (!token) {
          const next = encodeURIComponent(window.location.pathname + window.location.search);
          window.location.href = 'login.html?next=' + next;
        }
      })();
    </script>
"""
    
    print(f"[*] Applying Hynest Cloud Security Patch to {len(protected_files)} pages...")
    
    for filename in protected_files:
        path = os.path.join(base_dir, filename)
        if not os.path.exists(path):
            print(f"[-] Skipping {filename} (Not found in project)")
            continue
            
        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check if we already patched this file
            if 'hynest-security-guard' in content:
                print(f"[*] {filename} is already secure. Skipping.")
                continue
                
            # Injecting right at the top of the <head>
            # (Ensures it blocks the rest of the page from even loading)
            if '<head>' in content:
                new_content = content.replace('<head>', '<head>' + guard_script)
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                print(f"[🟢 FIXED] {filename} is now protected.")
            else:
                print(f"[🟡 WARN] {filename} lacks a <head> tag. Appending to top...")
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(guard_script + content)
                    
        except Exception as e:
            print(f"[-] Failed to patch {filename}: {e}")

    print("\n[+] Security Patch Deployment Complete. Hynest Cloud is now fortified.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Patch Hynest - Auth Guard Injector")
    parser.add_argument("target", help="Path to the Hynest Cloud web directory (e.g. C:\\Projects\\Hynest\\Cloud\\web)")
    args = parser.parse_args()
    patch_hynest_cloud(args.target)
