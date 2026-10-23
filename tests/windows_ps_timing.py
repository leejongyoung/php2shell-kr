import os, subprocess, sys, time
root = os.environ.get("SystemRoot", r"C:\Windows")
ps = os.path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
base = {"SystemRoot": root, "PATH": os.path.join(root, "System32")}
envs = {
    "A minimal(tool)": dict(base),
    "B +windir,TEMP,TMP": dict(base, windir=root, TEMP=r"C:\Windows\Temp", TMP=r"C:\Windows\Temp"),
    "C +USERPROFILE,LOCALAPPDATA,APPDATA,ProgramData": dict(base, windir=root, TEMP=r"C:\Windows\Temp", TMP=r"C:\Windows\Temp",
        USERPROFILE=os.environ.get("USERPROFILE", ""), LOCALAPPDATA=os.environ.get("LOCALAPPDATA", ""), APPDATA=os.environ.get("APPDATA", ""),
        ProgramData=os.environ.get("ProgramData", ""), ProgramFiles=os.environ.get("ProgramFiles", "")),
    "D +PSModulePath": dict(base, PSModulePath=os.path.join(root, "System32", "WindowsPowerShell", "v1.0", "Modules")),
    "E inherited": None,
}
cmds = {"noop": "Write-Output ok",
        "getaccesscontrol": "(Get-Item -LiteralPath 'C:\\Windows\\System32\\cmd.exe').GetAccessControl().Owner"}
for name, env in envs.items():
    for label, cmd in cmds.items():
        for attempt in (1, 2):
            t = time.time()
            r = subprocess.run([ps, "-NoProfile", "-NonInteractive", "-Command", cmd], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               universal_newlines=True, env=env, timeout=180)
            print("%-48s %-17s #%d %6.1fs rc=%d out=%r err=%r" % (name, label, attempt, time.time() - t, r.returncode, r.stdout.strip()[:40], r.stderr.strip()[:80]))
            sys.stdout.flush()
