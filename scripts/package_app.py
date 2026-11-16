#!/usr/bin/env python3
"""Prepare the existing Cowork work directory; never copies credential caches."""
from pathlib import Path
import shutil
ROOT=Path(__file__).resolve().parent.parent
DEST=ROOT/'dist'
(DEST/'web').mkdir(parents=True,exist_ok=True)
(DEST/'web'/'index.html').write_text((ROOT/'index.html').read_text().replace('./assets/','/assets/'))
shutil.copytree(ROOT/'assets',DEST/'web'/'assets',dirs_exist_ok=True)
p=DEST/'web'/'assets'/'app.js';p.write_text(p.read_text().replace('./assets/','/assets/'))
for name in ['app.py','case_store.py','trace_agent.py','requirements.txt','install.sh','start.sh','health.sh']:shutil.copy2(ROOT/name,DEST/name)
(DEST/'scripts').mkdir(exist_ok=True)
for name in ['collect_evidence.py','vesta_evidence.py','xray_profile.py','case_review.py']:shutil.copy2(ROOT/'scripts'/name,DEST/'scripts'/name)
shutil.copytree(ROOT/'runtime',DEST/'runtime',dirs_exist_ok=True)
for p in DEST.rglob('*'):
 if p.is_file() and p.name in ['auth.json','config.json','.redInfo','local-credential.json']:
  raise RuntimeError('Credential-like file found in output; refusing to package.')
print('Existing work prepared. Keep runtime/ when packing.')
