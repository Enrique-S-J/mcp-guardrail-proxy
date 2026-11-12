"""The real proxy, with one fault injected: a disk that has filled up.

    python faulty_disk_proxy.py <proxy arguments...>

Once the file named by $FAULTY_DISK_FLAG exists, every write to a regular
file fails with ENOSPC. Opening files keeps working, as it does on a full
disk, and pipes are untouched, so the MCP wire and the upstream carry on.
That is the case a writability check that only opens the log cannot see.
"""

import errno
import os
import stat
import sys

from mcp_guardrail_proxy.__main__ import main

FLAG = os.environ["FAULTY_DISK_FLAG"]
_real_write = os.write


def _write(fd, data):
    if stat.S_ISREG(os.fstat(fd).st_mode) and os.path.exists(FLAG):
        raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))
    return _real_write(fd, data)


os.write = _write

if __name__ == "__main__":
    main(sys.argv[1:])
