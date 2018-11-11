
README
------

Setting up the environments

1. Download
   - https://github.com/rapid7/metasploit-framework/wiki/Nightly-Installers

2. Install metasploitframework-latest.msi

3. Run
   - C:\metasploit-framework\bin\msfpescan.bat

	Usage: C:/metasploit-framework/bin/../embedded/bin/msfpescan [mode] <options> [t
	argets]

	Modes:
	    -j, --jump [regA,regB,regC]      Search for jump equivalent instructions
	    -p, --poppopret                  Search for pop+pop+ret combinations
	    -r, --regex [regex]              Search for regex match
	    -a, --analyze-address [address]  Display the code at the specified address
	    -b, --analyze-offset [offset]    Display the code at the specified offset
	    -f, --fingerprint                Attempt to identify the packer/compiler
	    -i, --info                       Display detailed information about the image
	    -R, --ripper [directory]         Rip all module resources to disk
	        --context-map [directory]    Generate context-map files

	Options:
	    -M, --memdump                    The targets are memdump.exe directories
	    -A, --after [bytes]              Number of bytes to show after match (-a/-b)
	    -B, --before [bytes]             Number of bytes to show before match (-a/-b)
	    -D, --disasm                     Disassemble the bytes at this address
	    -I, --image-base [address]       Specify an alternate ImageBase
	    -F, --filter-addresses [regex]   Filter addresses based on a regular expression
	    -h, --help                       Show this message

	C:\Users\IEUser>
