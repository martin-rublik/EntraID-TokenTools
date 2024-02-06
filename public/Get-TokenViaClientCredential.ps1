<#
.SYNOPSIS
    The command implements client_credentials token request.

.DESCRIPTION
	The command implements client_credentials token request. More information:
	https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow

.PARAMETER TenantID
    Entra ID Tenant ID, where authentication should take place.

    Default value: None
    Mandatory: Yes 

.PARAMETER ClientID
	Entra ID registered application ID (client ID). 

	Default value: None
	Mandatory: Yes

.PARAMETER ClientSecret
	Respective client_secret necessary for authentication.

	Default value: None
	Mandatory: Yes

.PARAMETER Scopes
	Requested OAuth scopes. 

	Default value: .default
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
	$token = Get-TokenViaClientCredential -TenantId '198a560e-d60c-450e-b801-f11cf700c193' -ClientID 'dadc1055-f974-4d40-a57f-7550adc07d39' -ClientSecret $secret 

	Requests a token via client_credential flow (mostly used for system-2-system access).
	Default scope (.default) is used.

.EXAMPLE
	$token = Get-TokenViaClientCredential -TenantId '198a560e-d60c-450e-b801-f11cf700c193' -ClientID 'dadc1055-f974-4d40-a57f-7550adc07d39' -ClientSecret $secret -Scope 'api://198a560e-d60c-450e-b801-f11cf700c193/.default'

	Requests a token via client_credential flow (mostly used for system-2-system access).
	Default scope enterprise application scope (198a560e-d60c-450e-b801-f11cf700c193/.default) is used. This will include all application roles assigned to respecitve service principal
#>

function Get-TokenViaClientCredential
{
	[cmdletbinding(ConfirmImpact = 'Low')]
	param(
				[Parameter(Mandatory=$true,ValueFromPipeline = $false)]
				[string] $TenantID,
				[Parameter(Mandatory=$true,ValueFromPipeline = $false)]
                [string] $ClientID,
				[Parameter(Mandatory=$true,ValueFromPipeline = $false)]
                [string] $ClientSecret,
				[Parameter(Mandatory=$false,ValueFromPipeline = $false)]
                [string[]] $Scopes=".default"
	)


	try
	{
        # build URL for code request
		
		$body=@{
			client_secret=$ClientSecret
			client_id=$ClientID
			scope=$($Scopes -join " ")
			grant_type='client_credentials'
		}

		$url="https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
		$tokenResponse=Invoke-RestMethod -Method Post -Uri $url -Body $body
		$tokenResponse
    }catch
    {
        throw $_
    }
}