Function sendEmail{
    Param (
        # email recipient
        [Parameter(Mandatory=$false)]
        [string]$emailTo,

        # email subject
        [Parameter(Mandatory=$false)]
        [string]$emailSubject,

        # email body
        [Parameter(Mandatory=$false)]
        [string]$emailBody,

        # email attachment
        [Parameter(Mandatory=$false)]
        $emailAttachments
    )

    $pcUser = $env:UserName
    $secureEmailFlag = (Get-ItemPropertyValue -Path $ppmsRegPath -name secureEmailFlag) 
    $emailUser = (Get-ItemPropertyValue -Path $ppmsRegPath -name emailUser) 
    $emailPass = (Get-ItemPropertyValue -Path $ppmsRegPath -name emailPass) 
    $PCname = (Get-ItemPropertyValue -Path $ppmsRegPath -name PCname) #Equipment name
    $emailFrom = [string](Get-ItemPropertyValue -Path $ppmsRegPath -name emailFrom) #Define email account in From address
    $smtpClient = [string](Get-ItemPropertyValue -Path $ppmsRegPath -name smtpClient) #Define smtp email client
    $secpasswd = ConvertTo-SecureString $emailPass -AsPlainText -Force
    $credentials = New-Object System.Management.Automation.PSCredential ("$emailUser", $secpasswd)
    
    If(($emailTo -eq "") -or ($emailTo -eq $null)){
        . "$PSScriptRoot\getUserInfo.ps1"
        $emailTo = (getUserInfo $pcUser).userEmail
        If ($emailTo -eq "") {
            "No valid user email listed, send to admin email"
            $emailTo = $emailFrom
        }
    }

    $emailParams = @{
        From = $emailFrom
        To = $emailTo
        Subject = $emailSubject
        Body = $emailBody
        SmtpServer = $smtpClient
        port = "587"
    }
    
    If($secureEmailFlag -eq 1) {
        $emailParams.UseSsl = $true
        $emailParams.Credential = $credentials    
    }
    If(($attachments -ne $null) -and ($attachments -ne "")) {
        $emailParams.Attachments = $emailAttachments
    }

    Try {
        Send-MailMessage @emailParams
        logdata "email sent"
    } Catch {
        logdata "couldnt send email"
        Write-Error $_
    }
}

