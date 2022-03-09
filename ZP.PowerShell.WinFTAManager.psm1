Function ZP-GetFTA
{
    [CmdletBinding(PositionalBinding = $False)]
    Param
    (
        [Parameter(Position = 0, Mandatory = $False)]
        [String]
        $Extension
    )
    If ($Extension)
    {
        Write-Verbose "Get File Type Association for `".$($Extension)`""
        $AssocFile = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.$($Extension)\UserChoice" -ErrorAction SilentlyContinue).ProgId
        Write-Output $AssocFile
    }
    Else
    {
        Write-Verbose "Get File Type Association List"
        $AssocList = Get-ChildItem "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\*" |
        Where-Object -FilterScript {$_.PSChildName.StartsWith(".")} |
        ForEach-Object {
            $ProgId = (Get-ItemProperty "$($_.PSParentPath)\$($_.PSChildName)\UserChoice" -ErrorAction SilentlyContinue).ProgId
            "$($_.PSChildName) => $ProgId"
        }
        Write-Output $AssocList
    }
}
Function ZP-GetPTA
{
    [CmdletBinding(PositionalBinding = $False)]
    Param
    (
        [Parameter(Position = 0, Mandatory = $False)]
        [String]
        $Protocol
    )
    If ($Protocol)
    {
        Write-Verbose "Get Protocol Type Association for $Protocol"
        $AssocFile = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Protocol\UserChoice" -ErrorAction SilentlyContinue).ProgId
        Write-Output $AssocFile
    }
    Else
    {
        Write-Verbose "Get Protocol Type Association List"
        $AssocList = Get-ChildItem "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\*" |
        ForEach-Object {
            $ProgId = (Get-ItemProperty "$($_.PSParentPath)\$($_.PSChildName)\UserChoice" -ErrorAction SilentlyContinue).ProgId
            "$($_.PSChildName) => $ProgId"
        }
        Write-Output $AssocList
    }
}