<#
.SYNOPSIS
    The command implements auth code token request/grant.

.DESCRIPTION
	The command implements auth code token request/grant. More information:
	https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow

.PARAMETER TenantID
    Entra ID Tenant ID, where authentication should take place.

    Default value: None
    Mandatory: Yes 

.PARAMETER ClientID
	Entra ID registered application ID (client ID). 

	Default value: None
	Mandatory: Yes

.PARAMETER ReplyUrl
	ReplyUrl defined in registered application. 

	Default value: None
	Mandatory: Yes

.PARAMETER ClientSecret
	Respective client_secret necessary for authentication. For public clients
	this value should not be specified.

	Default value: None
	Mandatory: No

.PARAMETER Scopes
	Requested OAuth scopes. 

	Default value: .default
	Mandatory: No

.NOTES
    Author     : Martin Rublik (martin.rublik@bspc.sk)
    Created    : 2023-10-04
    Version    : 1.0

	Most of the content inspired by https://blog.darrenjrobinson.com/connecting-to-microsoft-graph-using-the-authorization-code-with-pkce-flow-and-powershell/
	
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
	$token = Get-TokenViaCode -TenantId '198a560e-d60c-450e-b801-f11cf700c193' -ClientID 'dadc1055-f974-4d40-a57f-7550adc07d39' -ReplyUrl 'https://some-app-url.com'

	Requests a token via auth code flow (mostly used for human based interactive access).
	Default scope (.default) is used.

.EXAMPLE
	$token = Get-TokenViaCode -TenantId '198a560e-d60c-450e-b801-f11cf700c193' -ClientID 'dadc1055-f974-4d40-a57f-7550adc07d39' -ClientSecret $secret -ReplyUrl 'https://some-app-url.com' -Scope 'api://198a560e-d60c-450e-b801-f11cf700c193/.default'

	Requests a token via auth code flow (mostly used for human based interactive access).
	Default scope enterprise application scope (198a560e-d60c-450e-b801-f11cf700c193/.default) is used. This will include all application roles assigned to respecitve service principal
#>

function Get-TokenViaCode
{
	[cmdletbinding(ConfirmImpact = 'Low')]
	param(
				[Parameter(ValueFromPipeline = $false,Mandatory=$true)]
				[string] $TenantID,
				[Parameter(ValueFromPipeline = $false,Mandatory=$true)]
                [string] $ClientID,
				[Parameter(ValueFromPipeline = $false,Mandatory=$false)]
                [string] $ClientSecret,
				[Parameter(ValueFromPipeline = $false,Mandatory=$true)]
                [string] $ReplyUrl,
				[Parameter(ValueFromPipeline = $false,Mandatory=$false)]
                [string[]] $Scopes=".default"
	)


	try
	{
        # build URL for code request
        if (-not ($ReplyUrl -match "(?i)^https:"))
        {
            throw "Only https URL are supported. Unsupported reply url: $ReplyUrl"
        }
        $url = "https://login.microsoftonline.com/$($TenantID)/oauth2/v2.0/authorize?response_type=code&redirect_uri=$($ReplyUrl)&client_id=$($ClientID)&response_mode=query&scope=$($Scopes -join "%20")"

        # import web browser ...
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Web

        $primaryScreen=[System.Windows.Forms.Screen]::AllScreens | ?{$_.Primary}
        $width=$primaryScreen.WorkingArea.Width / 4
        $height=$primaryScreen.WorkingArea.Height / 2

        $form = New-Object -TypeName System.Windows.Forms.Form -Property @{Width = $width; Height = $height}
        $web = New-Object -TypeName System.Windows.Forms.WebBrowser -Property @{Width = $width-20; Height = $height; Url = $url }

        $DocComp = {
            $uri = $web.Url.AbsoluteUri        
            if ($uri -match "error=[^&]*|code=[^&]*") { $form.Close() }
        }

        $web.ScriptErrorsSuppressed = $false
        $web.Add_DocumentCompleted($DocComp)
        $form.Controls.Add($web)
        $form.Add_Shown( { $form.Activate() })
        $form.ShowDialog() | Out-Null
        $queryOutput = [System.Web.HttpUtility]::ParseQueryString($web.Url.Query)
    
        $codeResult = @{}
        foreach ($key in $queryOutput.Keys) {
            $codeResult["$key"] = $queryOutput[$key]
        }

        if ($codeResult.code) 
        {
            Write-Verbose "Received an authorization code."
            $tokenParams = @{
                grant_type    = "authorization_code";
                client_id     = $ClientID;
                code          = $codeResult.code;
                tenant_id     = $TenantID;
                redirect_uri  = $ReplyURL;
            }

            if ($ClientSecret)
            {
                $tokenParams.Add('client_secret',$ClientSecret)
            }

        
            # with auth code get a token
            $tokenResponse = Invoke-RestMethod -Method Post `
                -Uri "https://login.microsoftonline.com/$($TenantID)/oauth2/v2.0/token" `
                -Body $tokenParams -ContentType 'application/x-www-form-urlencoded' 

            return $tokenResponse
    }
    else {
        Write-Error $_
    }


    }catch
    {
        throw $_
    }
}