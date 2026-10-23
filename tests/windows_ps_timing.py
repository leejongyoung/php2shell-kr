import concurrent.futures, os, subprocess, sys, time, winreg
root = os.environ.get("SystemRoot", r"C:\Windows")
ps = os.path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
base = {"SystemRoot": root, "PATH": os.path.join(root, "System32")}
inherited = os.environ.get("PSModulePath", "")
with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment") as key:
    machine = winreg.QueryValueEx(key, "PSModulePath")[0]
print("inherited PSModulePath:", inherited)
print("machine PSModulePath (registry):", machine)
machine_expanded = os.path.expandvars(machine)
print("machine expanded:", machine_expanded)
extra = {k: os.environ[k] for k in ("LOCALAPPDATA", "USERPROFILE", "APPDATA", "TEMP") if k in os.environ}


def timed(label, env):
    t = time.time()
    r = subprocess.run([ps, "-NoProfile", "-NonInteractive", "-Command", "Write-Output ok"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       universal_newlines=True, env=env, timeout=180)
    return label, time.time() - t, r.stdout.strip()


jobs = [("minimal + inherited PSModulePath", dict(base, PSModulePath=inherited)),
        ("minimal + machine PSModulePath", dict(base, PSModulePath=machine_expanded)),
        ("minimal + LOCALAPPDATA + machine PSModulePath", dict(base, PSModulePath=machine_expanded, LOCALAPPDATA=extra.get("LOCALAPPDATA", ""))),
        ("minimal + USERPROFILE/LOCALAPPDATA/APPDATA/TEMP + machine", dict(base, PSModulePath=machine_expanded, **extra)),
        ("minimal + empty PSModulePath", dict(base, PSModulePath=""))]
for i, part in enumerate([p for p in inherited.split(";") if p]):
    jobs.append(("minimal + only inherited entry #%d %s" % (i, part), dict(base, PSModulePath=part)))
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
    for label, elapsed, out in pool.map(lambda j: timed(*j), jobs):
        print("%6.1fs %s %s" % (elapsed, label, out))
        sys.stdout.flush()
