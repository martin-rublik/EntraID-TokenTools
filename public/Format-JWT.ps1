<#
.SYNOPSIS
    The command parses JWT token from input or pipeline.

.DESCRIPTION
	The command parses JWT token from input or pipeline; 
	Once parsed, it can either output a psobject or JSON.
	Do not use for validation as the signature is removed.

.PARAMETER Text
    Input text necessary for parsing

    Default value: None
    Mandatory: Yes (accepts also pipeline passing)

.PARAMETER AsJson
	If this switch is present it will output the parsed JWT token as JSON.

	Default value: None
	Mandatory: No

.NOTES
    Author     : Martin Rublik (martin.rublik@bspc.sk)
    Created    : 2023-10-04
    Version    : 1.0


    Changelog:
    V 1.0 (2023-10-24) - intial version

    License:
    The MIT License (MIT)

    Copyright (c) 2016 Martin Rublik

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.


.EXAMPLE
	$token.access_token | Format-JWT -AsJson

	Parse access_token and output it as formated JSON.

#>

function Format-JWT
{
    param(
    ## Text of an XML document.
    [Parameter(ValueFromPipeline = $true,Mandatory=$true)]
	[string[]]$Text,
	[Parameter(ValueFromPipeline = $false,Mandatory=$false)]
    [switch]$AsJson
    )
    $parts=$Text.Split(".")
    if ($parts.Count -ne 3)
    {
        throw "Inccorect JWT, expacting three b64 strings seperated by '.'"
    }

    # pad parts
    for($i=0;$i -lt 2;$i++)
    {
        $len=$parts[$i].Length
        if ($len % 4 -eq 2) {$parts[$i]=$parts[$i]+"=="}
        if ($len % 4 -eq 3) {$parts[$i]=$parts[$i]+"="}
    }

    $result= New-Object psobject
    try
    {
        $toDecode=$parts[0]
        $header=$toDecode | Base64-To-String | ConvertFrom-Json 
        $result | Add-Member -MemberType NoteProperty Header -Value $header -Force
    }catch
    {
        throw "Error decoding JWT header: $($_.exception.message)"
    }
    try
    {
        $toDecode=$parts[1]
        $toDecodeLenMod=$toDecode.Length % 4
        $payload=$toDecode | Base64-To-String | ConvertFrom-Json 
        $result | Add-Member -MemberType NoteProperty Payload -Value $payload -Force
    }catch
    {
        throw "Error decoding JWT payload: $($_.exception.message)"
    }

    if ($AsJson.IsPresent)
    {
        return $result | ConvertTo-Json
    }
    $result
}