$PCname = (Get-ItemPropertyValue -Path $ppmsRegPath -name PCname) #Equipment name

#Get list of questions
$Text = ""
$noQuestions = 0

If([System.IO.File]::Exists("$QuestionDrive$QuestionPath$PCname.txt")) {
    $Text = Get-Content -Path $QuestionDrive$QuestionPath$PCname.txt
    $QType = Get-Random -Maximum $Text.Count

    $Text = ($Text[$QType]) -split ":"
    $Text = ($Text -split (",")).Trim()

    $array = @()
    $list = 1..$Text.Count
    $list = $list | Sort-Object {Get-Random}
    $shuffled = $list | Sort-Object {Get-Random}

    For($i=0;$i -lt $Text.Count;$i++) {
    
        $array += $Text[$list[$i]]
    }

    #Custom Button Popup Window code
    . "$PSScriptRoot\CustomForm.ps1" 

    #Incident Creation Code
    #######################################################
    Add-Type -AssemblyName PresentationFramework
 
    $answer = $null
    $popUpTimer = 30
 
    # Create a stackpanel container
    $StackPanel = New-Object System.Windows.Controls.StackPanel

    # Create a combobox
    $ComboBox = New-Object System.Windows.Controls.ListBox
    $ComboBox.ItemsSource = $Array
    $ComboBox.Margin = "10,10,10,0"
    $ComboBox.Background = "White"
    $ComboBox.FontSize = 16
 
    # Create a textblock
    $TextBlock = New-Object System.Windows.Controls.TextBlock
    $TextBlock.Text = "What $($Text[0]) Are You Working With Today?"
    $TextBlock.Margin = 10
    $TextBlock.FontSize = 16

     #Assemble the stackpanel
    $TextBlock, $ComboBox | foreach {
        $StackPanel.AddChild($PSItem)
    }

    $Question = @{
        TitleFontSize = 20
        TitleBackground = 'Red'
        TitleTextForeground = 'White'
        Sound = 'Windows Exclamation'
        Timeout = $popUpTimer
        ButtonType = 'Ok'
    }

    New-WPFMessageBox @Question -Content $StackPanel -Title "Question?"
    $answerNumber = "$($Text[0])($($ComboBox.SelectedIndex)/$($Array.Count-1)) : "
    $Answer = $ComboBox.SelectedValue
    "Answer = $answerNumber$Answer"
}
Else{
    $noQuestions = 1
    logdata "Questionaire file not found"}




