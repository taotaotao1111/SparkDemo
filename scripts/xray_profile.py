#!/usr/bin/env python3
"""Run the official XRAY CLI with isolated per-user credential files.

The CLI currently uses a fixed auth.json path. Rename its files under a process
lock; never parse, print or copy credentials. A crash marker permits recovery.
"""
import fcntl
import os
from pathlib import Path
import re
import subprocess
import sys


def main():
    profile=os.environ.get('TRACE_XRAY_PROFILE','')
    legacy=os.environ.get('TRACE_XRAY_LEGACY_PROFILE','')
    if not re.fullmatch(r'[a-f0-9]{64}',profile) or not re.fullmatch(r'[a-f0-9]{64}',legacy):
        print('缺少经过核对的查询身份。',file=sys.stderr);return 2
    directory=Path.home()/'.config'/'xray'
    directory.mkdir(parents=True,exist_ok=True,mode=0o700)
    profiles=directory/'trace-profiles';profiles.mkdir(exist_ok=True,mode=0o700)
    active=directory/'trace-active-profile'
    auth=directory/'auth.json'
    with open(directory/'trace-profiles.lock','a') as lock:
        os.chmod(lock.name,0o600)
        fcntl.flock(lock,fcntl.LOCK_EX)
        previous=active.read_text().strip() if active.is_file() else legacy
        if not re.fullmatch(r'[a-f0-9]{64}',previous):
            print('授权上下文需要恢复，请联系应用维护者。',file=sys.stderr);return 2
        if auth.exists():
            prior=profiles/previous;prior.mkdir(exist_ok=True,mode=0o700)
            os.replace(auth,prior/'auth.json')
        target=profiles/profile;target.mkdir(exist_ok=True,mode=0o700)
        stored=target/'auth.json'
        if stored.exists():os.replace(stored,auth)
        active.write_text(profile);active.chmod(0o600)
        try:
            binary=Path(__file__).resolve().parent.parent/'runtime'/'bin'/'xray-cli'
            return subprocess.run([str(binary)]+sys.argv[1:],env=os.environ.copy()).returncode
        finally:
            if auth.exists():os.replace(auth,stored)
            active.unlink(missing_ok=True)


if __name__=='__main__':raise SystemExit(main())
