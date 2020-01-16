ls c:\windows -include *.dll -recurse -erroraction silentlycontinue |
foreach { $_.fullname } |
out-file -encoding ascii -filepath $env:TEMP\dll_fullpath_list.txt
