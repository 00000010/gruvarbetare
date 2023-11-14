import os
import sys
import gruvarbetare
import subprocess

def read(folder):
    
    #resolve the path
    
    if os.path.exists(folder):
        print("opening folder...\n ")
        files =os.listdir(folder)
        
        for filename in files:
            filepath=os.path.join(folder,filename)
           # if os.access(filepath,os.X_OK):
            print(" Testing ", filename)
            filepath=os.path.join(folder,filename)
            command = ["python3", "gruvarbetare.py", "-f", filepath]
            subprocess.call(command)
        return
def main():
    if len(sys.argv) !=2:
            print("Usage: malwarefolder feeder.py ")
            sys.exit(1)

    read(sys.argv[1])

if __name__ == '__main__':
    main()
