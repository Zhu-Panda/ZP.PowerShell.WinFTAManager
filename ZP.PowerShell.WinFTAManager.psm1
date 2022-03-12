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
        If ($Extension)
        {
            Write-Output ([PSCustomObject] @{
                Extension = $Type
                ProgId = (Get-ItemProperty $AssocTypePath -ErrorAction SilentlyContinue).ProgId
            })
        }
        Else
        {
            Write-Output ([PSCustomObject] @{
                Protocol = $Type
                ProgId = (Get-ItemProperty $AssocTypePath -ErrorAction SilentlyContinue).ProgId
            })
        }
    }
    Else
    {
        If ($Extension)
        {
            Write-Output (Get-ChildItem $AssocListPath | Where-Object -FilterScript {$_.PSChildName.StartsWith(".")} | ForEach-Object {
                [PSCustomObject] @{
                    Extension = $_.PSChildName.Substring(1)
                    ProgId = (Get-ItemProperty "$($_.PSParentPath)\$($_.PSChildName)\UserChoice" -ErrorAction SilentlyContinue).ProgId
                }
            })
        }
        Else
        {
            Write-Output (Get-ChildItem $AssocListPath | ForEach-Object {
                [PSCustomObject] @{
                    Protocol = $_.PSChildName
                    ProgId = (Get-ItemProperty "$($_.PSParentPath)\$($_.PSChildName)\UserChoice" -ErrorAction SilentlyContinue).ProgId
                }
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
        Write-Output (ZP-GetWinTypeAssoc -Type $Extension -Extension)
    Else
    {
        Write-Output (ZP-GetWinTypeAssoc -Type "" -Extension)
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
        Write-Output (ZP-GetWinTypeAssoc -Type $Protocol -Protocol)
    }
    Else
    {
        Write-Output (ZP-GetWinTypeAssoc -Type "" -Protocol)
    }
}
Function ZP-SetWinTypeAssoc
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
        [String]
        $Type,
        [Parameter(Position = 1, Mandatory)]
        [Parameter(ParameterSetName = "Extension")]
        [Parameter(ParameterSetName = "Protocol")]
        [String]
        $ProgId,
        [Parameter(Position = 2)]
        [Parameter(ParameterSetName = "Extension")]
        [Parameter(ParameterSetName = "Protocol")]
        [String]
        $Icon
    )
}