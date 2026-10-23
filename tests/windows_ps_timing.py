import os, subprocess, sys, time, winreg
root = os.environ.get("SystemRoot", r"C:\Windows")
ps = os.path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
base = {"SystemRoot": root, "PATH": os.path.join(root, "System32")}
extra = {k: os.environ[k] for k in ("LOCALAPPDATA", "USERPROFILE", "APPDATA", "TEMP", "TMP", "HOMEDRIVE", "HOMEPATH", "USERNAME", "COMPUTERNAME", "windir") if k in os.environ}
with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment") as key:
    machine = os.path.expandvars(winreg.QueryValueEx(key, "PSModulePath")[0])
cache = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Windows", "PowerShell")
print("cache dir exists:", os.path.isdir(cache), os.listdir(cache) if os.path.isdir(cache) else None)


def timed(label, env, cmd="Write-Output ok"):
    t = time.time()
    r = subprocess.run([ps, "-NoProfile", "-NonInteractive", "-Command", cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       universal_newlines=True, env=env, timeout=300)
    print("%6.1fs %s -> %s" % (time.time() - t, label, r.stdout.strip()[:30]))
    sys.stdout.flush()


for i in (1, 2, 3):
    timed("G1 minimal+profile vars, no PSModulePath #%d" % i, dict(base, **extra))
for i in (1, 2, 3):
    timed("G2 minimal+profile vars+machine PSModulePath #%d" % i, dict(base, PSModulePath=machine, **extra))
print("cache dir after:", os.listdir(cache) if os.path.isdir(cache) else None)
for i in (1, 2):
    timed("G3 with -NoProfile, inherited env #%d" % i, None)
timed("G4 minimal+profile vars, Get-Process", dict(base, **extra), "Get-Process -Id $PID | Select -Expand Id")
