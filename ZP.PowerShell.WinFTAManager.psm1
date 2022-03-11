Function ZP-GetWinTypeAssoc
{
    [CmdletBinding(PositionalBinding = $False)]
    Param
    (
        [Parameter(ParameterSetName = "Extension")]
        [Switch]
        $Extension,
        [Parameter(ParameterSetName = "Protocol")]
        [Switch]
        $Protocol,
        [Parameter(Position = 0, Mandatory)]
        [Parameter(ParameterSetName = "Extension")]
        [Parameter(ParameterSetName = "Protocol")]
        [AllowEmptyString()]
        [String]
        $Type
    )
    If ((-Not $Extension) -And (-Not $Protocol))
    {
        Write-Error "?????"
    }
    $GetAllMsg = "Get $($Extension ? "File" : "Protocol") Type Association List"
    $GetTypeMsg = "Get $($Extension ? "File" : "Protocol") Type Association for `"$($Extension ? "." : [String]::Empty)$($Type)`""
    $AssocListPath = "HKCU:\Software\Microsoft\Windows\$($Extension ? "CurrentVersion\Explorer\FileExts" : "Shell\Associations\UrlAssociations")\*"
    $AssocTypePath = "HKCU:\Software\Microsoft\Windows\$($Extension ? "CurrentVersion\Explorer\FileExts\.$($Type)" : "Shell\Associations\UrlAssociations\$($Type)")\UserChoice"
    Write-Verbose ($Type ? $GetTypeMsg : $GetAllMsg)
    Write-Verbose "Getting from $($Type ? $AssocTypePath : $AssocListPath)"
    If ($Type)
    {
        Write-Output @{$Type = (Get-ItemProperty $AssocTypePath -ErrorAction SilentlyContinue).ProgId}
    }
    Else
    {
        If ($Extension)
        {
            Write-Output (Get-ChildItem $AssocListPath | Where-Object -FilterScript {$_.PSChildName.StartsWith(".")} | ForEach-Object {
                @{$_.PSChildName.Substring(1) = (Get-ItemProperty "$($_.PSParentPath)\$($_.PSChildName)\UserChoice" -ErrorAction SilentlyContinue).ProgId}
            })
        }
        Else
        {
            Write-Output (Get-ChildItem $AssocListPath | ForEach-Object {
                @{$_.PSChildName = (Get-ItemProperty "$($_.PSParentPath)\$($_.PSChildName)\UserChoice" -ErrorAction SilentlyContinue).ProgId}
            })
        }
    }
}
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
        Write-Output ".$($Extension) => $((ZP-GetWinTypeAssoc -Type $Extension -Extension).Values[0])"
    }
    Else
    {
        Write-Output (ZP-GetWinTypeAssoc -Type "" -Extension | ForEach-Object {
            ".$($_.Keys[0]) => $($_.Values[0])"
        })
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
        Write-Output "$($Protocol) => $((ZP-GetWinTypeAssoc -Type $Protocol -Protocol).Values[0])"
    }
    Else
    {
        Write-Output (ZP-GetWinTypeAssoc -Type "" -Protocol | ForEach-Object {
            "$($_.Keys[0]) => $($_.Values[0])"
        })
    }
}