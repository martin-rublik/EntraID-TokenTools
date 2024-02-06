<#
.SYNOPSIS
    The command implements client_credentials token request via client certificate.

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

.PARAMETER Certificate
	X509Certificate2 object stored in windows store. Make sure the underlying CSP supports SHA2 (such as Microsoft Enhanced RSA and AES Cryptographic Provider)

	Default value: None
	Mandatory: Yes

.PARAMETER PfxCertificate
	Path to certificate and private key stored in PKCS#12 envelope.

	Default value: None
	Mandatory: Yes

.PARAMETER Password
	Path to password to PKCS#12 file.

	Default value: None
	Mandatory: Yes

.PARAMETER Scopes
	Requested OAuth scopes. 

	Default value: .default
	Mandatory: No

.NOTES
    Author     : Martin Rublik (martin.rublik@bspc.sk)
    Created    : 2024-02-05
    Version    : 1.0


    Changelog:
    V 1.0 (2023-10-24) - intial version
    V 1.1 (2024-02-05) - added support for client certificate calls

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
	
	Inspired by:
	
	PKCS#12 correct CSP selection, cumbersome but works
		https://stackoverflow.com/questions/45084515/update-x509certificate2-with-correct-cryptographic-service-provider-in-bouncy-ca
	JWT creation:
		https://stackoverflow.com/questions/73673368/powershell-code-to-implement-client-credential-authentication-using-self-signed

.EXAMPLE
	$token = Get-TokenViaClientCertificate -TenantID '198a560e-d60c-450e-b801-f11cf700c193' -ClientID 'b7260572-0f8b-43cb-b45d-a86e3dcb645b' -Certificate (ls Cert:\CurrentUser\my\25b100eb723374e0c28255cccda93e06221eed9f) 

	Requests a token via client_credential flow (mostly used for system-2-system access).
	Default scope (.default) is used.

.EXAMPLE
	$token = Get-TokenViaClientCertificate -TenantID "4e549187-9eea-4eb9-80a3-58a43b8f0ed7" -ClientID 'b7260572-0f8b-43cb-b45d-a86e3dcb645b' -PfxCertificate 'C:\data\onedrive\OneDrive - BSP Consulting\Desktop\ED-selfSigned-Cert2.pfx' -Password '1234'

	Requests a token via client_credential flow (mostly used for system-2-system access).
	Default scope (.default) is used.
#>

function Get-TokenViaClientCertificate
{
	[cmdletbinding(ConfirmImpact = 'Low')]
	param(
				[Parameter(Mandatory=$true,ValueFromPipeline = $false)]
                [string] $TenantID,
                [Parameter(Mandatory=$true,ValueFromPipeline = $false)]
                [string] $ClientID,
                [Parameter(Mandatory=$true,ValueFromPipeline = $false,ParameterSetName="CertFromStore")]
                [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
                [Parameter(Mandatory=$true,ValueFromPipeline = $false,ParameterSetName="CertFromFile")]
                [string] $PfxCertificate,
                [Parameter(Mandatory=$true,ValueFromPipeline = $false,ParameterSetName="CertFromFile")]
                [string] $Password,
                [Parameter(Mandatory=$false,ValueFromPipeline = $false)]
                [string[]] $Scopes=".default"
	)


	try
	{
        # build URL for code request
		
        if ($Certificate)
        {
            $ClientCertificate=$Certificate
            $PrivateKey = [System.Security.Cryptography.RSACryptoServiceProvider]$ClientCertificate.PrivateKey
        }

        if ($PfxCertificate)
        {
            $ClientCertificate=new-object System.Security.Cryptography.X509Certificates.X509Certificate2($PfxCertificate, $Password, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
            $serialzed=$ClientCertificate.PrivateKey.ToXmlString($true)
            $cspParams = new-object System.Security.Cryptography.CspParameters
            $cspParams.ProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider"
            $cspParams.ProviderType = 24

            $PrivateKey = New-Object System.Security.Cryptography.RSACryptoServiceProvider($cspParams);
            $PrivateKey.FromXmlString($serialzed)
        }

        #Create base64 hash of certificate
        ##################################
        $CertificateBase64Hash = [System.Convert]::ToBase64String($ClientCertificate.GetCertHash())
 
        #Create JWT timestamp for expiration
        ####################################
        $StartDate = (Get-Date "1970-01-01T00:00:00Z" ).ToUniversalTime()
        $JWTExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End (Get-Date).ToUniversalTime().AddMinutes(5)).TotalSeconds
        $JWTExpiration = [math]::Round($JWTExpirationTimeSpan,0)
 
        #Create JWT validity start timestamp
        ####################################
        $NotBeforeExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End ((Get-Date).ToUniversalTime())).TotalSeconds
        $NotBefore = [math]::Round($NotBeforeExpirationTimeSpan,0)
     
        #Create JWT header
        #################
        $JWTHeader = @{
            alg = "RS256"
            typ = "JWT"
            x5t = $CertificateBase64Hash -replace '\+','-' -replace '/','_' -replace '='
        }
 
        #Create JWT payload
        #################
        $JWTPayLoad = @{
           aud = "https://login.microsoftonline.com/$tenantId/oauth2/token"
           exp = $JWTExpiration
           iss = $ClientID
           jti = [guid]::NewGuid()
           nbf = $NotBefore
           sub = $ClientID
        }
 
        # Convert header and payload to base64
        #################################
        $JWTHeaderToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTHeader | ConvertTo-Json))
        $EncodedHeader = [System.Convert]::ToBase64String($JWTHeaderToByte)
        $JWTPayLoadToByte =  [System.Text.Encoding]::UTF8.GetBytes(($JWTPayload | ConvertTo-Json))
        $EncodedPayload = [System.Convert]::ToBase64String($JWTPayLoadToByte)
 
        # Join header and Payload with "." to create a valid (unsigned) JWT
        ######################################################
        $JWT = $EncodedHeader + "." + $EncodedPayload
 
        # Define RSA signature and hashing algorithm
        #####################################
        $RSAPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1
        $HashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256
 
        # Create a signature of the JWT
        #########################
        $Signature = [Convert]::ToBase64String(
            $PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($JWT),$HashAlgorithm,$RSAPadding)
        ) -replace '\+','-' -replace '/','_' -replace '='
 
        # Join the signature to the JWT with "."
        ###############################
        $JWT = $JWT + "." + $Signature
 
        # Use the self-generated JWT as Authorization to get the Access Token
        ##########################################################
        $Header = @{
            Authorization = "Bearer $JWT"
        }
 
        $Body = @{
            client_id = $ClientID
            client_assertion = $JWT
            client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            scope = $($Scopes -join " ")
            grant_type = "client_credentials"
        }
 
        #$authUri = "https://login.microsoftonline.com/common/oauth2/token"
        $authUri = "https://login.microsoftonline.com/$TenantID/oauth2/v2.0/token"
 
        $TokenResponse = Invoke-RestMethod -Header $Header -Uri $authUri -Method POST -Body $Body
        $TokenResponse    
    }catch
    {
        throw $_
    }
}