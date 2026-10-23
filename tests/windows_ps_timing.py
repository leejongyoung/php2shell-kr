import concurrent.futures, os, subprocess, sys, time
root = os.environ.get("SystemRoot", r"C:\Windows")
ps = os.path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
base = {"SystemRoot": root, "PATH": os.path.join(root, "System32")}
names = ["SystemDrive", "ComSpec", "PATHEXT", "OS", "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS", "COMPUTERNAME", "USERNAME", "USERDOMAIN",
         "USERDOMAIN_ROAMINGPROFILE", "ALLUSERSPROFILE", "ProgramFiles", "ProgramFiles(x86)", "CommonProgramFiles", "ProgramW6432", "PROCESSOR_IDENTIFIER",
         "PROCESSOR_LEVEL", "PROCESSOR_REVISION", "HOMEDRIVE", "HOMEPATH", "windir", "TEMP", "TMP", "USERPROFILE", "LOCALAPPDATA", "APPDATA", "ProgramData",
         "PUBLIC", "LOGONSERVER", "SESSIONNAME", "DriverData", "CommonProgramW6432", "CommonProgramFiles(x86)", "PSModulePath"]
have = {n: os.environ[n] for n in names if n in os.environ}
print("candidate vars present:", sorted(have))


def timed(label, env):
    t = time.time()
    r = subprocess.run([ps, "-NoProfile", "-NonInteractive", "-Command", "Write-Output ok"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       universal_newlines=True, env=env, timeout=180)
    return label, time.time() - t, r.stdout.strip()


full = dict(base); full.update(have)
jobs = [("ALL candidates", full)]
for n in have:
    e = dict(full); del e[n]
    jobs.append(("all minus %s" % n, e))
    e2 = dict(base); e2[n] = have[n]
    jobs.append(("minimal plus %s" % n, e2))
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
    for label, elapsed, out in pool.map(lambda j: timed(*j), jobs):
        print("%6.1fs %-40s %s" % (elapsed, label, out))
        sys.stdout.flush()
