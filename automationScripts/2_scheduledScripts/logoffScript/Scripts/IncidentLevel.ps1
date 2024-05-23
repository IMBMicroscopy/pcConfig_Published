#Custom Button Popup Window code
. "$PSScriptRoot\CustomForm.ps1" 

#Incident Creation Code
#######################################################
Add-Type -AssemblyName PresentationFramework
 
$incidentDescription = ""
$Severity = $null
$popUpTimer = 30

# Define the location list
$Array = @(
    "1 = Low Level - System useable, But Minor Issue"
    "2 = Medium Level - System Partially Down"
    "3 = High Level - System Down"
)
 
# Create a stackpanel container
$StackPanel = New-Object System.Windows.Controls.StackPanel

# Create a combobox
$ComboBox = New-Object System.Windows.Controls.ComboBox
$ComboBox.ItemsSource = $Array
$ComboBox.Margin = "10,10,10,0"
$ComboBox.Background = "White"
$ComboBox.FontSize = 16
 
# Create a textblock
$TextBlock = New-Object System.Windows.Controls.TextBlock
$TextBlock.Text = "Select the Incident Severity"
$TextBlock.Margin = 10
$TextBlock.FontSize = 16

# Create a 2nd textblock
$TextBlock2 = New-Object System.Windows.Controls.TextBlock
$TextBlock2.Text = "
Incident Notes"
$TextBlock2.Margin = 10
$TextBlock2.FontSize = 16
 
#Create a text input field
$textInput = New-Object System.Windows.Controls.TextBox
#$textInput.DesiredSize.Height = 40
$textInput.Margin = 10
$textInput.FontSize = 16
$TextInput.HorizontalScrollBarVisibility = "Auto"
$TextInput.VerticalScrollBarVisibility = "Auto"
$TextInput.TextWrapping = "Wrap"
$textInput.AcceptsReturn = "True"
$textInput.Height = 80 



 #Assemble the stackpanel
$TextBlock, $ComboBox, $TextBlock2, $textInput | foreach {
    $StackPanel.AddChild($PSItem)
}

$Params = @{
    TitleFontSize = 20
    TitleBackground = 'Red'
    TitleTextForeground = 'White'
    Sound = 'Windows Exclamation'
    Timeout = $popUpTimer
    ButtonType = 'Ok'
}
$Severity = $null
$SeverityNumber = $null
New-WPFMessageBox @Params -Content $StackPanel -Title "Report Incident"
$Severity = $ComboBox.SelectedValue
If($Severity -ne $null){$severityNumber = [string]($severity.Chars(0))}
$incidentDescription = $textInput.Text
"Severity = $Severity"
"SeverityNumber = $SeverityNumber"
"description = $incidentDescription"