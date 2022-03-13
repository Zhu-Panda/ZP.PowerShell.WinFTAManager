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
    }
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
    Function Local:Refresh-Registry
    {
        Try
        {
            Add-Type -Path $PSScriptRoot/RegInterop.cs
        }
        Catch
        {}
        Try
        {
            [ZP.PowerShell.WinFTAManager.RegInterop]::Refresh()
        }
        Catch
        {} 
    }
      
    
    Function Local:Set-Icon 
    {
        Param
        (
            [Parameter(Position = 0, Mandatory)]
            [String]
            $ProgId,
            [Parameter(Position = 1, Mandatory)]
            [String]
            $Icon
        )
        Try
        {
            $IconKey = "HKEY_CURRENT_USER\SOFTWARE\Classes\$($ProgId)\DefaultIcon"
            [Microsoft.Win32.Registry]::SetValue($IconKey, "", $Icon) 
            Write-Verbose "Write Reg Icon OK"
            Write-Verbose "Reg Icon Path: $IconKey"
        }
        Catch
        {
            Write-Verbose "Write Reg Icon Fail"
        }
    }
    
    
    Function Local:Write-ExtensionKeys
    {
        Param
        (
            [Parameter(Position = 0, Mandatory)]
            [String]
            $ProgId,
            [Parameter(Position = 1, Mandatory)]
            [String]
            $Extension,
            [Parameter(Position = 2, Mandatory)]
            [String]
            $ProgHash
        )
        Function Local:Remove-UserChoiceKey
        {
            Param
            (
                [Parameter(Position = 0, Mandatory)]
                [String]
                $Key
            )
            Try
            {
                Add-Type -Path $PSScriptRoot/RegInterop.cs
            }
            Catch {}
            Try
            {
                [ZP.PowerShell.WinFTAManager.RegInterop]::DeleteKey($Key)
            }
            Catch {} 
        } 
    
        Try
        {
            $UserChoicePath = "Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$($Extension)\UserChoice"
            Write-Verbose "Remove Extension UserChoice Key If Exist: $($UserChoicePath)"
            Remove-UserChoiceKey $UserChoicePath
        }
        Catch
        {
            Write-Verbose "Extension UserChoice Key No Exist: $($UserChoicePath)"
        }
    
        Try
        {
            $UserChoicePath = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$($Extension)\UserChoice"
            [Microsoft.Win32.Registry]::SetValue($UserChoicePath, "Hash", $ProgHash)
            [Microsoft.Win32.Registry]::SetValue($UserChoicePath, "ProgId", $ProgId)
            Write-Verbose "Write Reg Extension UserChoice OK"
        }
        Catch
        {
            Throw "Write Reg Extension UserChoice FAIL"
        }
    }
    Function Local:Write-ProtocolKeys
    {
        Param
        (
            [Parameter(Position = 0, Mandatory)]
            [String]
            $ProgId,
            [Parameter(Position = 1, Mandatory)]
            [String]
            $Protocol,
            [Parameter(Position = 2, Mandatory)]
            [String]
            $ProgHash
        )
        Try
        {
            $UserChoicePath = "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$($Protocol)\UserChoice"
            Write-Verbose "Remove Protocol UserChoice Key If Exist: $($UserChoicePath)"
            Remove-Item -Path $UserChoicePath -Recurse -ErrorAction Stop | Out-Null
        }
        Catch
        {
            Write-Verbose "Protocol UserChoice Key No Exist: $($UserChoicePath)"
        }
        Try
        {
            $UserChoicePath = "HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$($Protocol)\UserChoice"
            [Microsoft.Win32.Registry]::SetValue($UserChoicePath, "Hash", $ProgHash)
            [Microsoft.Win32.Registry]::SetValue($UserChoicePath, "ProgId", $ProgId)
            Write-Verbose "Write Reg Protocol UserChoice OK"
        }
        Catch
        {
            Throw "Write Reg Protocol UserChoice FAIL"
        }
        
    }
      
    Function Local:Get-UserExperience
    {
        [OutputType([String])]
        $UserExperienceSearch = "User Choice set via Windows User Experience"
        $User32Path = "$([Environment]::GetFolderPath([Environment+SpecialFolder]::SystemX86))\shell32.dll"
        $FileStream = [System.IO.File]::Open($User32Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $BinaryReader = New-Object System.IO.BinaryReader($FileStream)
        [Byte[]] $BytesData = $BinaryReader.ReadBytes(5mb)
        $FileStream.Close()
        $DataString = [Text.Encoding]::Unicode.GetString($BytesData)
        $Position1 = $DataString.IndexOf($UserExperienceSearch)
        $Position2 = $DataString.IndexOf("}", $Position1)
        Write-Output $DataString.Substring($Position1, $Position2 - $Position1 + 1)
    }
    Function Local:Get-UserSid
    {
        [OutputType([String])]
        $UserSid = ([System.DirectoryServices.AccountManagement.UserPrincipal]::Current).Sid.Value.ToLower()
        Write-Output $UserSid
    }
    Function Local:Get-HexDateTime
    {
        [OutputType([String])]
        $Now = [DateTime]::Now
        $DateTime = [DateTime]::New($Now.Year, $Now.Month, $Now.Day, $Now.Hour, $Now.Minute, 0)
        $FileTime = $DateTime.ToFileTime()
        $Hi = ($FileTime -shr 32)
        $Low = ($FileTime -band 0xFFFFFFFFL)
        $DateTimeHex = ($Hi.ToString("X8") + $Low.ToString("X8")).ToLower()
        Write-Output $DateTimeHex
    } 
    Function Get-Hash
    {
        [CmdletBinding()]
        Param
        (
        [Parameter(Position = 0, Mandatory)]
        [String]
        $BaseInfo
        )
        Function Local:Get-ShiftRight
        {
            [CmdletBinding()]
            Param 
            (
                [Parameter(Position = 0, Mandatory)]
                [Long]
                $iValue, 
                [Parameter(Position = 1, Mandatory)]
                [Int]
                $iCount 
            )
            If ($iValue -band 0x80000000)
            {
                Write-Output (( $iValue -shr $iCount) -bxor 0xFFFF0000)
            }
            Else
            {
                Write-Output ($iValue -shr $iCount)
            }
        }
        Function Local:Get-Long
        {
            [CmdletBinding()]
            Param
            (
                [Parameter(Position = 0, Mandatory)]
                [Byte[]]
                $Bytes,
                [Parameter(Position = 1)]
                [Int]
                $Index = 0
            )
            Write-Output ([BitConverter]::ToInt32($Bytes, $Index))
        }
        Function Local:Convert-Int32
        {
            Param
            (
                [Parameter(Position = 0, Mandatory)]
                $Value
            )
            [Byte[]] $Bytes = [BitConverter]::GetBytes($Value)
            Return [BitConverter]::ToInt32($Bytes, 0) 
        }
        [Byte[]] $BytesBaseInfo = [System.Text.Encoding]::Unicode.GetBytes($BaseInfo) 
        $BytesBaseInfo += 0x00, 0x00  
        
        $MD5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
        [Byte[]] $BytesMD5 = $MD5.ComputeHash($BytesBaseInfo)
        
        $LengthBase = ($BaseInfo.Length * 2) + 2 
        $Length = (($LengthBase -band 4) -le 1) + (Get-ShiftRight $LengthBase  2) - 1
        $Base64Hash = ""
    
        If ($Length -gt 1)
        {
            $Map = @{
                PDATA = 0;
                CACHE = 0;
                COUNTER = 0;
                INDEX = 0; 
                MD51 = 0; 
                MD52 = 0;
                OUTHASH1 = 0;
                OUTHASH2 = 0;
                R0 = 0;
                R1 = @(0, 0); 
                R2 = @(0, 0);
                R3 = 0;
                R4 = @(0, 0);
                R5 = @(0, 0);
                R6 = @(0, 0);
                R7 = @(0, 0)
            }
        
            $Map.CACHE = 0
            $Map.OUTHASH1 = 0
            $Map.PDATA = 0
            $Map.MD51 = (((Get-Long $BytesMD5) -bor 1) + 0x69FB0000L)
            $Map.MD52 = ((Get-Long $BytesMD5 4) -bor 1) + 0x13DB0000L
            $Map.INDEX = Get-ShiftRight ($Length - 2) 1
            $Map.COUNTER = $Map.INDEX + 1
            While ($Map.COUNTER)
            {
                $Map.R0 = Convert-Int32 ((Get-Long $BytesBaseInfo $Map.PDATA) + [Long]$map.OUTHASH1)
                $Map.R1[0] = Convert-Int32 (Get-Long $BytesBaseInfo ($Map.PDATA + 4))
                $Map.PDATA = $Map.PDATA + 8
                $Map.R2[0] = Convert-Int32 (($Map.R0 * ([Long]$Map.MD51)) - (0x10FA9605L * ((Get-ShiftRight $Map.R0 16))))
                $Map.R2[1] = Convert-Int32 ((0x79F8A395L * ([Long]$Map.R2[0])) + (0x689B6B9FL * (Get-ShiftRight $Map.R2[0] 16)))
                $Map.R3 = Convert-Int32 ((0xEA970001L * $Map.R2[1]) - (0x3C101569L * (Get-ShiftRight $Map.R2[1] 16) ))
                $Map.R4[0] = Convert-Int32 ($Map.R3 + $Map.R1[0])
                $Map.R5[0] = Convert-Int32 ($Map.CACHE + $Map.R3)
                $Map.R6[0] = Convert-Int32 (($Map.R4[0] * [Long]$Map.MD52) - (0x3CE8EC25L * (Get-ShiftRight $Map.R4[0] 16)))
                $Map.R6[1] = Convert-Int32 ((0x59C3AF2DL * $Map.R6[0]) - (0x2232E0F1L * (Get-ShiftRight $Map.R6[0] 16)))
                $Map.OUTHASH1 = Convert-Int32 ((0x1EC90001L * $Map.R6[1]) + (0x35BD1EC9L * (Get-ShiftRight $Map.R6[1] 16)))
                $Map.OUTHASH2 = Convert-Int32 ([Long]$Map.R5[0] + [Long]$Map.OUTHASH1)
                $Map.CACHE = ([Long]$Map.OUTHASH2)
                $Map.COUNTER = $Map.COUNTER - 1
            }
          
            [Byte[]] $OutHash = @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
            [Byte[]] $Buffer = [BitConverter]::GetBytes($Map.OUTHASH1)
            $Buffer.CopyTo($OutHash, 0)
            $Buffer = [BitConverter]::GetBytes($Map.OUTHASH2)
            $Buffer.CopyTo($OutHash, 4)
        
            $Map = @{
                PDATA = 0;
                CACHE = 0;
                COUNTER = 0;
                INDEX = 0;
                MD51 = 0;
                MD52 = 0;
                OUTHASH1 = 0;
                OUTHASH2 = 0;
                R0 = 0;
                R1 = @(0, 0);
                R2 = @(0, 0);
                R3 = 0;
                R4 = @(0, 0);
                R5 = @(0, 0);
                R6 = @(0, 0);
                R7 = @(0, 0)
            }
        
            $Map.CACHE = 0
            $Map.OUTHASH1 = 0
            $Map.PDATA = 0
            $Map.MD51 = ((Get-Long $BytesMD5) -bor 1)
            $Map.MD52 = ((Get-Long $BytesMD5 4) -bor 1)
            $Map.INDEX = Get-ShiftRight ($Length - 2) 1
            $Map.COUNTER = $Map.INDEX + 1
    
            While ($Map.COUNTER)
            {
                $Map.R0 = Convert-Int32 ((Get-Long $BytesBaseInfo $Map.PDATA) + ([Long]$Map.OUTHASH1))
                $Map.PDATA = $Map.PDATA + 8
                $Map.R1[0] = Convert-Int32 ($Map.R0 * [Long]$Map.MD51)
                $Map.R1[1] = Convert-Int32 ((0xB1110000L * $Map.R1[0]) - (0x30674EEFL * (Get-ShiftRight $Map.R1[0] 16)))
                $Map.R2[0] = Convert-Int32 ((0x5B9F0000L * $Map.R1[1]) - (0x78F7A461L * (Get-ShiftRight $Map.R1[1] 16)))
                $Map.R2[1] = Convert-Int32 ((0x12CEB96DL * (Get-ShiftRight $Map.R2[0] 16)) - (0x46930000L * $Map.R2[0]))
                $Map.R3 = Convert-Int32 ((0x1D830000L * $Map.R2[1]) + (0x257E1D83L * (Get-ShiftRight $Map.R2[1] 16)))
                $Map.R4[0] = Convert-Int32 ([Long]$Map.MD52 * ([Long]$Map.R3 + (Get-Long $BytesBaseInfo ($Map.PDATA - 4))))
                $Map.R4[1] = Convert-Int32 ((0x16F50000L * $Map.R4[0]) - (0x5D8BE90BL * (Get-ShiftRight $Map.R4[0] 16)))
                $Map.R5[0] = Convert-Int32 ((0x96FF0000L * $Map.R4[1]) - (0x2C7C6901L * (Get-ShiftRight $Map.R4[1] 16)))
                $Map.R5[1] = Convert-Int32 ((0x2B890000L * $Map.R5[0]) + (0x7C932B89L * (Get-ShiftRight $Map.R5[0] 16)))
                $Map.OUTHASH1 = Convert-Int32 ((0x9F690000L * $Map.R5[1]) - (0x405B6097L * (Get-ShiftRight ($Map.R5[1]) 16)))
                $Map.OUTHASH2 = Convert-Int32 ([Long]$Map.OUTHASH1 + $Map.CACHE + $Map.R3) 
                $Map.CACHE = ([Long]$Map.OUTHASH2)
                $Map.COUNTER = $Map.COUNTER - 1
            }
        
            $Buffer = [BitConverter]::GetBytes($Map.OUTHASH1)
            $Buffer.CopyTo($OutHash, 8)
            $Buffer = [BitConverter]::GetBytes($Map.OUTHASH2)
            $Buffer.CopyTo($OutHash, 12)
        
            [Byte[]] $OutHashBase = @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
            $HashValue1 = ((Get-Long $OutHash 8) -bxor (Get-Long $OutHash))
            $HashValue2 = ((Get-Long $OutHash 12) -bxor (Get-Long $OutHash 4))
        
            $Buffer = [BitConverter]::GetBytes($HashValue1)
            $Buffer.CopyTo($OutHashBase, 0)
            $Buffer = [BitConverter]::GetBytes($HashValue2)
            $Buffer.CopyTo($OutHashBase, 4)
            $Base64Hash = [Convert]::ToBase64String($OutHashBase) 
        }
    
        Write-Output $Base64Hash
    }
    If ((-Not $Extension) -And (-Not $Protocol))
    {
        Write-Error "?????"
        Return
    }
    $BasicInfoMsg = "ProgId: $($ProgId), $($Extension ? "Extension" : "Protocol"): $($Type)"
    Write-Verbose $BasicInfoMsg
    Write-Verbose "Getting Hash For $($BasicInfoMsg)"
    $UserSid = Get-UserSid
    $UserExperience = Get-UserExperience
    $UserDateTime = Get-HexDateTime
    Write-Verbose "DateTime: $($UserDateTime)"
    Write-Verbose "Sid: $($UserSid)"
    Write-Verbose "User Experience: $($UserExperience)"
    $BaseInfo = "$($Extension ? "." : [String]::Empty)$($Type)$($UserSid)$($ProgId)$($UserDateTime)$($UserExperience)".ToLower()
    Write-Verbose "BaseInfo: $BaseInfo"
    $ProgHash = Get-Hash $BaseInfo
    Write-Verbose "Hash: $ProgHash"
    $WriteRegMsg = "Write Registry $($Extension ? "Extension" : "Protocol"): $($Type)"
    If ($Extension)
    {
        Write-Verbose $WriteRegMsg
        Write-ExtensionKeys $ProgId ".$($Type)" $ProgHash
    }
    Else
    {
        Write-Verbose $WriteRegMsg
        Write-ProtocolKeys $ProgId $Type $ProgHash
    }
    If ($Icon)
    {
        Write-Verbose  "Set Icon: $Icon"
        Set-Icon $ProgId $Icon
    }
    Refresh-Registry
}