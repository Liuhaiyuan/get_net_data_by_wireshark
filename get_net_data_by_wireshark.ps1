#######################    Run on PowerShell 3.0 +
#######################    Author:              liuhaiyuan
#######################    Create Date:         2018-05-20          V0.1

<#
.Synopsis
   Get installed software list by retrieving registry.
.DESCRIPTION
   The function return a installed software list by retrieving registry from below path;
   1.'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
   2.'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
   3.'HKLM:SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
   Author: Mosser Lee (http://www.pstips.net/author/mosser/)

.EXAMPLE
   Get-InstalledSoftwares
.EXAMPLE
   Get-InstalledSoftwares  | Group-Object Publisher
#>
function Get-InstalledSoftwares
{
    #
    # Read registry key as product entity.
    #
    function ConvertTo-ProductEntity
    {
        param([Microsoft.Win32.RegistryKey]$RegKey)
        $product = '' | select Name,Publisher,Version
        $product.Name =  $_.GetValue("DisplayName")
        $product.Publisher = $_.GetValue("Publisher")
        $product.Version =  $_.GetValue("DisplayVersion")

        if( -not [string]::IsNullOrEmpty($product.Name)){
            $product
        }
    }

    $UninstallPaths = @(,
    # For local machine.
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    # For current user.
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall')

    # For 32bit softwares that were installed on 64bit operating system.
    if([Environment]::Is64BitOperatingSystem) {
        $UninstallPaths += 'HKLM:SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    }
    $UninstallPaths | foreach {
        Get-ChildItem $_ | foreach {
            ConvertTo-ProductEntity -RegKey $_
        }
    }
}

# 获取wireshark信息
$wireshark_info = $(Get-InstalledSoftwares  | Where-Object {$_.Name -like "*Wireshark*"})

if ($wireshark_info.Name -like "*wireshark*"){
    Write-Output "检测到您的电脑上已有wireshark，自动运行120秒收集数据信息，请稍后。"
	
	# get soft name ，start process， 根据启动进程所在的目录位置，启动tshark程序进行对应抓包
    $soft_name = $wireshark_info.Name -split " "
    $process_name = $soft_name[0]
    Start-Process $process_name
    $shark_process = Get-Process -Name $process_name
    $file = Dir $($shark_process.Path)
    
    $tshark_path = $file.DirectoryName + "\tshark.exe"
	$editcap_path = $file.DirectoryName + "\editcap.exe"
    $location = Get-Location
    $pcapng_dir = $location.Path + "\pcapng"
    $zip_dir = $location.Path + "\" + (Get-Date).ToString('yyyy-MM-dd-hh-mm-ss') + ".zip"
    
    if(Test-Path $pcapng_dir){
        $pcapng_dir
    }else{
       New-Item $pcapng_dir -Type Directory
    }

    if(Test-Path $tshark_path){
        & "$tshark_path" -a duration:120 -w pcapng\automatic_capture.pcapng
        Stop-Process -Name $process_name
        $pcapng_dir
        $zip_dir
        Add-Type -A 'System.IO.Compression.FileSystem'; 
        [IO.Compression.ZipFile]::CreateFromDirectory($pcapng_dir, $zip_dir); 
    }else {
        Write-Error "$file.DirectoryName  目录下tshark.exe 文件不存在。"
    }
     

    # 抓包完成，根据数据包文件大小进行文件切割，以邮件附件大小20M（20 000 000）为分界线。
    #$pcapng_file = Get-ChildItem pcapng\automatic_capture.pcapng
    #$pcapng_size = '{0:n2}' -f $($pcapng_file.Length / 1024 / 1024)
    

    # 切割数据报文文件，防止抓取数据包太大，导致wireshark无法打开，本脚本暂无该需求，注释屏蔽。
    #if(Test-Path $editcap_path){
    #    & "$editcap_path" -c 100 pcapng\automatic_capture.pcapng pcapng\editcap_capture.pcapng
    #}else {
    #    Write-Error "$file.DirectoryName  目录下editcap.exe 文件不存在。"
    #}
    
    
}else {
    Write-Error "未在您的电脑上检测到wireshark软件，请安装wireshark软件。"
}