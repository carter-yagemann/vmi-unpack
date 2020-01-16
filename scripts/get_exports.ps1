param(
    [string]$out_base=$false,
    [string[]]$glob=@()
)
# $out_base = 'e:\gtri\malware_unpacking'
$default_glob = "dll_fullpath_list.splits.*"

if ($out_base -eq $false) {
    throw "first argument must be a valid directory"
}
elseif (-not (test-path $out_base -pathtype 'Container')) {
    throw "$($out_base) is not a valid directory"
}
$old_dir = pwd
cd $out_base

if ($glob.length -eq 1 -and
    ($glob[0].contains('*') -or $glob[0].contains('?'))
    ) {
    $glob = ls $glob[0] | foreach { $_.fullname }
}
elseif ($glob.length -eq 0) {
    $glob = ls $default_glob | foreach { $_.fullname }
}

if (-not ($glob -is [String[]]) -or ($glob.length -eq 0)) {
    throw "the list of input files is empty. maybe bad glob?"
}

$glob |
foreach {
    $out_name = join-path $out_base ((split-path -leaf $_)+'.dll_log')
    "processing $out_name"
    $args = "/undecorate 0 /from_textfile $_ /stab $out_name"
    start-process -wait -filepath "dllexp" -argument $args
}
cd $old_dir
