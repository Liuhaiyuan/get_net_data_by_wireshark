# Obtain a suitable buffer length by partial file length
function Get-BufferLength ([int]$partialFileLength)
{
    [int]$MinBufferLength = 1MB
    # No need to consume great amount memory，initialize as 50M, you can adjust it from here.
    [int]$MaxBufferLength = 50MB
 
    if($partialFileLength -ge 1GB) { return $MaxBufferLength}
    elseif( $partialFileLength -le 50MB) { return $MinBufferLength }
    else{ return [int]( $MaxBufferLength/1GB * $partialFileLength )}
}
 
# Write partial stream to file from current position
function Write-PartialStreamToFile
{
    param(
    [IO.FileStream]$stream,
    [long]$length,
    [string]$outputFile
    )
 
    #copy stream to file
    function Copy-Stream( [int]$bufferLength )
    {
        [byte[]]$buffer = New-Object byte[]( $bufferLength )
 
        # Read partial file data to memory buffer
        $stream.Read($buffer,0,$buffer.Length) | Out-Null
 
        # Flush buffer to file
        $outStream = New-Object IO.FileStream($outputFile,'Append','Write','Read')
        $outStream.Write($buffer,0,$buffer.Length)
        $outStream.Flush()
        $outStream.Close()
    }
 
    $maxBuffer = Get-BufferLength $length
    $remBuffer = 0
    $loop = [Math]::DivRem($length,$maxBuffer,[ref]$remBuffer)
 
    if($loop -eq 0)
    {
        Copy-Stream $remBuffer
        return
    }
 
    1..$loop | foreach {
        $bufferLength = $maxBuffer
 
        # let last loop contains remanent length
        if( ($_ -eq $loop) -and ($remBuffer -gt 0) ) 
        {
            $bufferLength = $maxBuffer + $remBuffer
         }
         Copy-Stream  $bufferLength
 
         # show outer progress
         $progress = [int]($_*100/$loop)
         write-progress -activity 'Writting file' -status 'Progress' -id 2 -percentcomplete $progress -currentOperation "$progress %"
    }
}
 
# split a large file into mutiple parts by part count or part length
function Split-File
{
    param(
    [Parameter(Mandatory=$True)]
    [IO.FileInfo]$File,
    [Switch]$ByPartCount,
    [Switch]$ByPartLength,
    [int]$PartCount,
    [int]$PartLength,
    [IO.DirectoryInfo]$OutputDir = '.'
    )
 
    # Argument validation
    if(-not $File.Exists) { throw "Source file [$File] not exists" }
    if(-not  $OutputDir.Exists) { mkdir $OutputDir.FullName | Out-Null}
    if( (-not $ByPartCount) -and (-not $ByPartLength) )
    {
        throw 'Must specify one of parameter, [ByPartCount] or [ByPartLength]'
    }
    elseif( $ByPartCount )
    {
        if($PartCount -le 1) {throw '[PartCount] must larger than 1'}
        $PartLength = $File.Length / $PartCount
    }
    elseif( $ByPartLength )
    {
        if($PartLength -lt 1) { throw '[PartLength] must larger than 0' }
        if($PartLength -ge $File.Length) { throw '[PartLength] must less than source file' }
        $temp = $File.Length /$PartLength
        $PartCount = [int]$temp
        if( ($File.Length % $PartLength) -gt 0 -and ( $PartCount -lt $temp ) )
        {
          $PartCount++
        }
    }
 
    $stream = New-Object IO.FileStream($File.FullName,
    [IO.FileMode]::Open ,[IO.FileAccess]::Read ,[IO.FileShare]::Read )
 
    # Make sure each part file name ended like '001' so that it's convenient to merge
    [string]$numberMaskStr = [string]::Empty.PadLeft( [int]([Math]::Log10($PartCount) + 1), "0" )
 
    1 .. $PartCount | foreach {
         $outputFile = Join-Path $OutputDir ( "{0}.part_{1} " -f $File.Name , $_.ToString( $numberMaskStr ) )
         # show outer progress
         $progress = [int]($_*100/$PartCount)
         write-progress -activity "Splitting file" -status "Progress $progress %" -Id 1 -percentcomplete $progress -currentOperation "Handle file $outputFile"
         if($_ -eq $PartCount)
         {
            Write-PartialStreamToFile $stream ($stream.Length - $stream.Position) $outputFile
         }
         else
         {
         Write-PartialStreamToFile $stream $PartLength  $outputFile
         }
    }
    $stream.Close()
}
 
function Merge-File
{
    param(
    [Parameter(Mandatory=$True)]
    [IO.DirectoryInfo]$SourceDir,
    [string]$Filter,
    [IO.FileInfo]$OutputFile
    )
 
    # arguments validation
    if ( -not $SourceDir.Exists ) { throw "Directory $SourceDir not exists." }
    $files = dir $SourceDir -File -Filter $Filter
    if($files -eq $null){ throw "No matched file in directory $SourceDir"}
 
    # output stream
    $outputStream = New-Object IO.FileStream($OutputFile.FullName,
        [IO.FileMode]::Append ,[IO.FileAccess]::Write ,[IO.FileShare]::Read )
 
    # merge file
    $files | foreach{
        #input stream
        $inputStream = New-Object IO.FileStream($_.FullName,
        [IO.FileMode]::Open ,[IO.FileAccess]::Read ,[IO.FileShare]::Read )
 
        $bufferLength = Get-BufferLength -partialFileLength $_.Length
        while($inputStream.Position -lt $inputStream.Length)
        {
            if( ($inputStream.Position + $bufferLength) -gt $inputStream.Length)
            {
                $bufferLength = $inputStream.Length - $inputStream.Position
            }
 
            # show outer progress
            $progress = [int]($inputStream.Position *100/ $inputStream.Length)
            write-progress -activity 'Merging file' -status "Progress $progress %"  -percentcomplete $progress
 
            # read file to memory buffer
            $buffer= New-Object byte[]( $bufferLength )
            $inputStream.Read( $buffer,0,$buffer.Length) | Out-Null
 
            #flush buffer to file
            $outputStream.Write( $buffer,0,$buffer.Length) | Out-Null
            $outputStream.Flush()
        }
        $inputStream.Close()
    }
    $outputStream.Close()
}