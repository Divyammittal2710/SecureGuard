from database import get_scan_history

history = get_scan_history()

for row in history:
    print(row)