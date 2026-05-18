import os
import glob
import re

tools_dir = os.path.dirname(os.path.abspath(__file__))
files = glob.glob(os.path.join(tools_dir, "*.py"))

for file in files:
    with open(file, 'r', encoding='utf-8') as f:
        content = f.read()

    # If --version is not in the script, inject it
    if 'argparse.ArgumentParser' in content and '--version' not in content:
        # Extract the tool name
        tool_match = re.search(r'description="([^"]+)"', content)
        tool_name = "Tool"
        if tool_match:
            desc = tool_match.group(1)
            # e.g. "Axios - ID Scanner" -> "Axios"
            tool_name = desc.split("-")[0].strip()
        
        # We will replace the ArgumentParser instantiation with the instantiation + the version flag
        replacement = r"\g<0>\n    parser.add_argument('-v', '--version', action='version', version='{} 1.0.0')".format(tool_name)
        new_content = re.sub(r'parser = argparse\.ArgumentParser\([^)]*\)', replacement, content)
        
        with open(file, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"Patched {os.path.basename(file)} to include --version")
    else:
        print(f"Skipped {os.path.basename(file)}")

