# Process Inject Kit

Cobalt Strike 4.5 now supports two new Aggressor Script hooks
`PROCESS_INJECT_SPAWN` and `PROCESS_INJECT_EXPLICIT`.  These hooks allow
a user to define how the fork&run and explicit injection techniques are
implemented when executing post-exploitation commands instead of using
the built-in techniques.


#### PROCESS_INJECT_SPAWN

Hook to allow users to define how the fork and run process injection technique
is implemented when executing post exploitation commands using a Beacon Object
File (BOF).


#### PROCESS_INJECT_EXPLICIT

Hook to allow users to define how the explicit process injection technique is
implemented when executing post exploitation commands using a Beacon Object
File (BOF).


# Load into Cobalt Strike

Open the Scripts manager, Cobalt Strike -> Scripts

Load `<output directory>/process_inject/processinject.cna`


### TODO
- Fully implement our own process spawn with syscalls