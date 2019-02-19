pp --gui -M Win32::OLE q2mi2txt.pl -o Q2MI2TXT-v2.exe

perl -e "use Win32::Exe; $exe = Win32::Exe->new('Q2MI2TXT-v2.exe'); $exe->set_single_group_icon('q2mi2txt_HM1_icon.ico'); $exe->write;"

pause