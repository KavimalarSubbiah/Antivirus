# main file for checking a file for probable Malware

import sys
from file_checker import checkFile


def main():
    if len(sys.argv) != 2:
        print("""
Invalid arguments given!
This program is to check if a given file is probable malware or not.

Usage: python3 main.py [file]
Try: python3 main.py malwares/Ransomware/Locky.exe
""")
        exit(1)
    filename = sys.argv[1]
    legitimate = checkFile(filename)
    print("\nStatus of Phase 2: Heurisitic Analysis\n")
    if legitimate:
        print(f"File {sys.argv[1]} has passed. It is probably LEGITIMATE.\n")
    else:
        print(f"File {sys.argv[1]} has failed. It is probably MALICIOUS and you are advised to DELETE THE FILE.")


if __name__ == "__main__":
    main()
