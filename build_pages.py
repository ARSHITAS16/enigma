"""
Builder script to generate index.html for GitHub Pages deployment using Stlite (WebAssembly Streamlit).
Embeds all Python application files and datasets into a single standalone client-side file.
"""

import os
import json

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

FILES_TO_EMBED = [
    'app.py',
    'analyzer/__init__.py',
    'analyzer/engine.py',
    'analyzer/patterns.py',
    'analyzer/recommendations.py',
    'analyzer/generator.py',
    'analyzer/timing.py',
    'analyzer/common_passwords.py',
    'data/common_passwords.txt'
]

files_data = {}
for rel_path in FILES_TO_EMBED:
    full_path = os.path.join(BASE_DIR, rel_path.replace('/', os.sep))
    with open(full_path, 'r', encoding='utf-8') as f:
        files_data[rel_path] = f.read()

json_files = json.dumps(files_data, ensure_ascii=False)

HTML_TEMPLATE = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="X-UA-Compatible" content="IE=edge" />
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
  <title>ENIGMA | Password Security Workbench</title>
  <meta name="description" content="ENIGMA — Explainable Password Risk Analysis Workbench. Decode the pattern. Reveal the risk. Protect the secret." />
  <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🛡️</text></svg>">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@stlite/browser@0.85.1/build/stlite.css" />
  <style>
    * {{
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }}
    html, body {{
      width: 100%;
      height: 100%;
      background-color: #101210;
      color: #F4F6F2;
      font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
      overflow: hidden;
    }}
    #root {{
      width: 100%;
      height: 100%;
    }}
    #loader-overlay {{
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: radial-gradient(circle at 50% 30%, #1c221c 0%, #101210 100%);
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      z-index: 999999;
      transition: opacity 0.6s ease, visibility 0.6s ease;
    }}
    .shield-icon {{
      font-size: 3.5rem;
      margin-bottom: 1rem;
      animation: pulse-shield 2s infinite ease-in-out;
    }}
    .loader-title {{
      font-size: 1.5rem;
      font-weight: 700;
      letter-spacing: 0.05em;
      color: #F4F6F2;
      margin-bottom: 0.35rem;
    }}
    .loader-subtitle {{
      font-size: 0.88rem;
      color: #80CC14;
      font-weight: 500;
      margin-bottom: 1.5rem;
      letter-spacing: 0.03em;
    }}
    .progress-bar-container {{
      width: 240px;
      height: 4px;
      background: #202420;
      border-radius: 999px;
      overflow: hidden;
      margin-bottom: 1rem;
    }}
    .progress-bar-fill {{
      width: 40%;
      height: 100%;
      background: linear-gradient(90deg, #80CC14, #9BE622);
      border-radius: 999px;
      animation: progress-slide 1.5s infinite ease-in-out;
    }}
    .loader-note {{
      font-size: 0.78rem;
      color: #6E766D;
      text-align: center;
      max-width: 320px;
      line-height: 1.4;
    }}
    @keyframes pulse-shield {{
      0%, 100% {{ transform: scale(1); filter: drop-shadow(0 0 10px rgba(128, 204, 20, 0.3)); }}
      50% {{ transform: scale(1.08); filter: drop-shadow(0 0 20px rgba(128, 204, 20, 0.6)); }}
    }}
    @keyframes progress-slide {{
      0% {{ transform: translateX(-100%); }}
      100% {{ transform: translateX(250%); }}
    }}
  </style>
</head>
<body>
  <!-- Loading Splash Screen -->
  <div id="loader-overlay">
    <div class="shield-icon">🛡️</div>
    <h1 class="loader-title">ENIGMA</h1>
    <p class="loader-subtitle">Password Security Workbench</p>
    <div class="progress-bar-container">
      <div class="progress-bar-fill"></div>
    </div>
    <p class="loader-note">Compiling Python WebAssembly runtime in your browser... First launch takes a few seconds.</p>
  </div>

  <!-- Stlite Application Root Mount Container -->
  <div id="root"></div>

  <script type="module">
    import {{ mount }} from "https://cdn.jsdelivr.net/npm/@stlite/browser@0.85.1/build/stlite.js";

    const embeddedFiles = {json_files};

    try {{
      mount(
        {{
          entrypoint: "app.py",
          files: embeddedFiles,
          streamlitConfig: {{
            "theme.base": "dark",
            "theme.primaryColor": "#80CC14",
            "theme.backgroundColor": "#101210",
            "theme.secondaryBackgroundColor": "#191C19",
            "theme.textColor": "#F4F6F2"
          }}
        }},
        document.getElementById("root")
      );

      // Dismiss loader overlay once mounted
      const observer = new MutationObserver(() => {{
        const iframe = document.querySelector('#root iframe');
        if (iframe) {{
          setTimeout(() => {{
            const loader = document.getElementById('loader-overlay');
            if (loader) {{
              loader.style.opacity = '0';
              setTimeout(() => loader.remove(), 600);
            }}
          }}, 1200);
          observer.disconnect();
        }}
      }});
      observer.observe(document.getElementById('root'), {{ childList: true, subtree: true }});

      // Safety fallback to dismiss loader after 12 seconds if observer didn't trigger
      setTimeout(() => {{
        const loader = document.getElementById('loader-overlay');
        if (loader) {{
          loader.style.opacity = '0';
          setTimeout(() => loader.remove(), 600);
        }}
      }}, 12000);

    }} catch (err) {{
      console.error("Stlite mount error:", err);
      const note = document.querySelector('.loader-note');
      if (note) {{
        note.innerHTML = '<span style="color:#EF4444;">Error launching WebAssembly runtime: ' + err.message + '</span>';
      }}
    }}
  </script>
</body>
</html>
"""

output_path = os.path.join(BASE_DIR, 'index.html')
with open(output_path, 'w', encoding='utf-8') as f:
    f.write(HTML_TEMPLATE)

print(f"Generated {output_path} successfully ({os.path.getsize(output_path)} bytes)")

# Also create .nojekyll
nojekyll_path = os.path.join(BASE_DIR, '.nojekyll')
with open(nojekyll_path, 'w', encoding='utf-8') as f:
    f.write('')
print(f"Created {nojekyll_path}")
