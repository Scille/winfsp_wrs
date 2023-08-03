from enum import Enum
import json

ENTRY_INFO_EXTENSION = ".__parsec_entry_info__"

class SyncState(Enum):
    NotSet = 0
    Synced = 1
    Refresh = 2

def get_file_state(path: str) -> SyncState:
    entry_info = path + ENTRY_INFO_EXTENSION

    print("try open", entry_info)

    try:
        fd = open(entry_info, "r", encoding="utf8")
    except Exception:
        return SyncState.NotSet

    print(fd)

    buffer = fd.read()

    print("opened", buffer)

    if json.loads(buffer)["need_sync"]:
        return SyncState.Refresh
    else:
        return SyncState.Synced

print(get_file_state("Z:/foo.txt"))
print(get_file_state("Z:/bar.txt"))
print(get_file_state("Z:/none.txt"))
