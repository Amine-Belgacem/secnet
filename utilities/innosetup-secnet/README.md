# inno-cmd-template
InnoSetup command-line utility installer template script. The script will create an installer for a 32bit program and append it to the **%PATH%** environment variable to be able to execute it from the command-line.

## How ?
Download and install innosetup from [official website](https://jrsoftware.org/) or use the version in `./inno-release-6.2`

Clone repository.

    git clone https://github.com/Amine-Belkacem/inno-cmd-template.git

Replace `myprog.exe` with your utility. 

Replace the content of `readme.txt` and `license.txt` with your content.

Adapt `script.iss` to your needs and build.
